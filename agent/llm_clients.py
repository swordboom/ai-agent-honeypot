import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

OPENROUTER_BASE = "https://openrouter.ai/api/v1"

# Free chat-capable models from openrouter_free_models.txt, ordered by usefulness for
# short multilingual roleplay + JSON extraction. Embedding / rerank / content-safety
# entries from that list are intentionally excluded: they cannot do chat completion.
DEFAULT_FREE_MODELS: Tuple[str, ...] = (
    "z-ai/glm-5.2:free",
    "nvidia/nemotron-3-super:free",
    "google/gemma-4-31b:free",
    "nvidia/nemotron-3-nano-30b-a3b:free",
    "google/gemma-4-26b-a4b:free",
    "poolside/laguna-xs-2.1:free",
    "nvidia/nemotron-nano-9b-v2:free",
    "cohere/north-mini-code:free",
    "openai/gpt-oss-20b:free",
)


class _ModelHealth:
    """
    Remembers which model slugs actually work.

    OpenRouter rotates its free tier constantly: slugs get renamed, retired, or
    rate-limited. Rather than hard-failing, a model that returns 404/400 (bad slug)
    is dropped permanently and one that returns 429/5xx is benched for a cooldown.
    """

    def __init__(self, cooldown_seconds: int = 120):
        self._cooldown = cooldown_seconds
        self._benched: Dict[str, float] = {}
        self._dead: set = set()
        self._last_ok: Optional[str] = None
        self._lock = threading.Lock()

    def usable(self, models: List[str]) -> List[str]:
        now = time.time()
        with self._lock:
            live = [m for m in models if m not in self._dead and self._benched.get(m, 0.0) < now]
            # Stick to the last model that worked: fewer cold-start failures per request.
            if self._last_ok in live:
                live.remove(self._last_ok)
                live.insert(0, self._last_ok)
            return live

    def mark_ok(self, model: str) -> None:
        with self._lock:
            self._last_ok = model
            self._benched.pop(model, None)

    def mark_failed(self, model: str, status: Optional[int]) -> None:
        with self._lock:
            if status in (400, 401, 403, 404):
                self._dead.add(model)
            else:
                self._benched[model] = time.time() + self._cooldown

    def snapshot(self) -> Dict[str, object]:
        now = time.time()
        with self._lock:
            return {
                "lastWorkingModel": self._last_ok,
                "retiredModels": sorted(self._dead),
                "cooldownModels": sorted(m for m, until in self._benched.items() if until > now),
            }


_health = _ModelHealth()


def model_health_snapshot() -> Dict[str, object]:
    return _health.snapshot()


def sanitize_reply(text: Optional[str], max_chars: int = 240) -> str:
    if not text:
        return ""
    cleaned = " ".join(text.replace("\n", " ").strip().split())
    lower = cleaned.lower()
    blocked_markers = ["as an ai", "language model", "honeypot", "bot"]
    if any(marker in lower for marker in blocked_markers):
        return ""
    return cleaned[:max_chars]


def extract_json_object(text: str) -> Optional[Dict]:
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    snippet = text[start : end + 1]
    try:
        return json.loads(snippet)
    except Exception:
        return None


@dataclass(frozen=True)
class OpenRouterClient:
    """
    Single LLM entry point. Tries each free model in order until one answers.

    OpenRouter speaks the OpenAI chat-completions wire format, so `messages` and
    `response_format` are passed straight through.
    """

    api_key: str
    models: Tuple[str, ...] = DEFAULT_FREE_MODELS
    timeout_seconds: int = 12
    referer: str = "https://github.com/agentic-honey-pot"
    title: str = "Agentic Honey-Pot"

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
        response_format: Optional[Dict] = None,
    ) -> Optional[str]:
        if not self.api_key:
            return None

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            # OpenRouter uses these for free-tier attribution; harmless if ignored.
            "HTTP-Referer": self.referer,
            "X-Title": self.title,
        }

        for model in _health.usable(list(self.models)):
            payload: Dict[str, object] = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if response_format:
                payload["response_format"] = response_format

            try:
                resp = requests.post(
                    f"{OPENROUTER_BASE}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=self.timeout_seconds,
                )
            except Exception as exc:
                logger.warning("OpenRouter request failed model=%s: %s", model, exc)
                _health.mark_failed(model, None)
                continue

            if resp.status_code >= 400:
                logger.warning("OpenRouter model=%s status=%s body=%s", model, resp.status_code, resp.text[:200])
                _health.mark_failed(model, resp.status_code)
                continue

            try:
                content = resp.json()["choices"][0]["message"]["content"]
            except Exception as exc:
                logger.warning("OpenRouter bad payload model=%s: %s", model, exc)
                _health.mark_failed(model, None)
                continue

            if content:
                _health.mark_ok(model)
                return content

            _health.mark_failed(model, None)

        return None


def list_free_models(timeout_seconds: int = 8) -> List[str]:
    """Live free-model slugs from OpenRouter. Used by the dashboard to show drift."""
    try:
        resp = requests.get(f"{OPENROUTER_BASE}/models", timeout=timeout_seconds)
        if resp.status_code >= 400:
            return []
        data = resp.json().get("data") or []
    except Exception as exc:
        logger.warning("OpenRouter model listing failed: %s", exc)
        return []

    free = []
    for entry in data:
        slug = entry.get("id") or ""
        pricing = entry.get("pricing") or {}
        prompt_price = str(pricing.get("prompt", "0"))
        if slug.endswith(":free") or prompt_price in {"0", "0.0", "-1"}:
            free.append(slug)
    return sorted(set(free))
