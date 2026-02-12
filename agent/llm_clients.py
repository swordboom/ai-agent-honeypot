import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


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
class OpenAIClient:
    api_key: str
    model: str
    timeout_seconds: int

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
        response_format: Optional[Dict] = None,
    ) -> Optional[str]:
        if not self.api_key:
            return None

        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format:
            payload["response_format"] = response_format

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout_seconds)
            if resp.status_code >= 400:
                logger.warning("OpenAI status=%s body=%s", resp.status_code, resp.text[:200])
                return None
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.warning("OpenAI request failed: %s", exc)
            return None


@dataclass(frozen=True)
class GeminiClient:
    api_key: str
    model: str
    timeout_seconds: int

    def chat(self, messages: List[Dict[str, str]], temperature: float, max_tokens: int) -> Optional[str]:
        if not self.api_key:
            return None

        system_parts = [m["content"] for m in messages if m.get("role") == "system"]
        dialog = [m for m in messages if m.get("role") != "system"]

        contents = []
        for msg in dialog:
            role = "user" if msg.get("role") == "user" else "model"
            contents.append({"role": role, "parts": [{"text": msg.get("content", "")}]})
        if not contents:
            contents.append({"role": "user", "parts": [{"text": "Hello"}]})

        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        payload = {
            "system_instruction": {"parts": [{"text": "\n".join(system_parts)}]},
            "contents": contents,
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }

        try:
            resp = requests.post(url, json=payload, timeout=self.timeout_seconds)
            if resp.status_code >= 400:
                logger.warning("Gemini status=%s body=%s", resp.status_code, resp.text[:200])
                return None
            data = resp.json()
            candidates = data.get("candidates") or []
            if not candidates:
                return None
            parts = candidates[0].get("content", {}).get("parts", [])
            if not parts:
                return None
            return parts[0].get("text", "")
        except Exception as exc:
            logger.warning("Gemini request failed: %s", exc)
            return None

