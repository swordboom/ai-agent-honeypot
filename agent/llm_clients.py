import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

OPENROUTER_BASE = "https://openrouter.ai/api/v1"
# Groq speaks the same OpenAI chat-completions wire format, so it is the same client
# with a different base URL and key.
GROQ_BASE = "https://api.groq.com/openai/v1"

# ponytail: one model. Groq's free tier gives gpt-oss-120b a real daily budget and it
# answers in character, so a fallback chain buys nothing until this one starts failing.
DEFAULT_GROQ_MODELS: Tuple[str, ...] = ("openai/gpt-oss-120b",)

# Free chat-capable models from openrouter_free_models.txt, ordered by usefulness for
# short multilingual roleplay + JSON extraction. Embedding / rerank / content-safety
# entries from that list are intentionally excluded: they cannot do chat completion.
DEFAULT_FREE_MODELS: Tuple[str, ...] = (
    # Ordered by measured behaviour on real scam prompts, not by listing order: the
    # instruct-tuned models answer in character, the reasoning models below them lose
    # the whole budget to chain-of-thought and get rejected by sanitize_reply, so they
    # sit at the tail as availability backstops only.
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "google/gemma-4-31b-it:free",
    "google/gemma-4-26b-a4b-it:free",
    "openai/gpt-oss-20b:free",
    "z-ai/glm-5.2:free",
    "nvidia/nemotron-3.5-lightning:free",
    "nvidia/nemotron-nano-9b-v2:free",
    "nvidia/nemotron-3-nano-30b-a3b:free",
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
        # Keyed by provider base URL: one provider's daily cap must not mute the other.
        self._chain_blocked_until: Dict[str, float] = {}

    def usable(self, models: List[str], scope: str = "") -> List[str]:
        now = time.time()
        with self._lock:
            # The free tier caps requests per DAY per account, not per model. Once
            # that trips, every slug returns 429 and walking the chain costs nine
            # round-trips per reply for nothing.
            if now < self._chain_blocked_until.get(scope, 0.0):
                return []
            live = [m for m in models if m not in self._dead and self._benched.get(m, 0.0) < now]
            # Stick to the last model that worked: fewer cold-start failures per request.
            if self._last_ok in live:
                live.remove(self._last_ok)
                live.insert(0, self._last_ok)
            return live

    def block_chain(self, seconds: float, scope: str = "") -> None:
        """Account-level quota exhausted: stop trying every model until it resets."""
        with self._lock:
            self._chain_blocked_until[scope] = max(
                self._chain_blocked_until.get(scope, 0.0), time.time() + max(60.0, seconds)
            )

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
                "chainBlockedSeconds": max(
                    [0] + [int(until - now) for until in self._chain_blocked_until.values() if until > now]
                ),
            }


_health = _ModelHealth()


def model_health_snapshot() -> Dict[str, object]:
    return _health.snapshot()


# Reasoning models spend the whole reply budget on chain-of-thought and never reach
# the answer, so the "reply" arrives as third-person commentary about writing a reply.
# Sending that to a scammer blows the persona harder than "as an AI" would. None of
# these phrases occur in a real victim's message, so rejecting them is safe: the
# caller falls back to the deterministic per-language reply.
_META_NARRATION = (
    "the user wants",
    "the user says",
    "the user is",
    "respond as",
    "reply as",
    "stay in role",
    "in character",
    "scam victim",
    "the assistant",
    "system prompt",
)

# Word-boundary, not substring: a fluent reply saying "both accounts" or "bottom of
# the page" is not a persona break.
_BLOCKED_RE = re.compile(r"\bas an ai\b|\blanguage model\b|\bhoney ?pot\b|\bbots?\b", re.IGNORECASE)

_THINK_RE = re.compile(r"(?is)<think>.*?</think>")


def sanitize_reply(text: Optional[str], max_chars: int = 240) -> str:
    if not text:
        return ""
    cleaned = " ".join(_THINK_RE.sub(" ", text).replace("\n", " ").strip().split())
    lower = cleaned.lower()
    if _BLOCKED_RE.search(cleaned):
        return ""
    if any(marker in lower for marker in _META_NARRATION):
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


# OpenRouter says "free-models-per-day"; Groq says "requests per day (RPD)" / "TPD".
_DAILY_CAP_RE = re.compile(r"per[-_ ]day|\b[RT]PD\b", re.IGNORECASE)


def _reset_seconds(resp, default: float = 900.0) -> float:
    """Seconds until the account quota resets, from the provider's header if present."""
    headers = getattr(resp, "headers", {}) or {}
    try:
        # OpenRouter: epoch milliseconds.
        return max(60.0, (float(headers.get("X-RateLimit-Reset")) / 1000.0) - time.time())
    except (TypeError, ValueError):
        pass
    try:
        # Groq: plain seconds.
        return max(60.0, float(headers.get("Retry-After")))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class OpenRouterClient:
    """
    Single LLM entry point. Tries each model in order until one answers.

    Both OpenRouter and Groq speak the OpenAI chat-completions wire format, so
    `messages` and `response_format` are passed straight through and the only
    difference between providers is `base_url`, the key, and the model list.
    """

    api_key: str
    models: Tuple[str, ...] = DEFAULT_FREE_MODELS
    timeout_seconds: int = 12
    referer: str = "https://github.com/agentic-honey-pot"
    title: str = "Agentic Honey-Pot"
    base_url: str = OPENROUTER_BASE
    # gpt-oss only. "low" keeps the reasoning budget from eating the reply.
    reasoning_effort: str = ""

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

        for model in _health.usable(list(self.models), scope=self.base_url):
            payload: Dict[str, object] = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                # Groq rejects the legacy `max_tokens` on reasoning models.
                ("max_completion_tokens" if self.base_url == GROQ_BASE else "max_tokens"): max_tokens,
            }
            if response_format:
                payload["response_format"] = response_format
            if self.reasoning_effort:
                payload["reasoning_effort"] = self.reasoning_effort

            try:
                resp = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=self.timeout_seconds,
                )
            except Exception as exc:
                logger.warning("LLM request failed model=%s: %s", model, exc)
                _health.mark_failed(model, None)
                continue

            if resp.status_code >= 400:
                logger.warning("LLM model=%s status=%s body=%s", model, resp.status_code, resp.text[:200])
                if resp.status_code == 429 and _DAILY_CAP_RE.search(resp.text):
                    _health.block_chain(_reset_seconds(resp), scope=self.base_url)
                    _health.mark_failed(model, resp.status_code)
                    return None
                _health.mark_failed(model, resp.status_code)
                continue

            try:
                content = resp.json()["choices"][0]["message"]["content"]
            except Exception as exc:
                logger.warning("LLM bad payload model=%s: %s", model, exc)
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
