import time
from typing import Dict, List, Optional, Tuple

from agent.llm_clients import GeminiClient, OpenAIClient, extract_json_object


def _empty_payload() -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    return (
        {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": [],
        },
        {
            "referenceIds": [],
            "amounts": [],
            "emails": [],
            "cryptoWallets": [],
            "domains": [],
            "ifscCodes": [],
        },
    )


def _coerce_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value).strip()] if str(value).strip() else []


def extract_structured_intelligence(
    text: str,
    openai: Optional[OpenAIClient],
    gemini: Optional[GeminiClient],
    timeout_hint_seconds: int = 10,
) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    if not text or (not (openai and openai.api_key) and not (gemini and gemini.api_key)):
        return _empty_payload()

    system = (
        "Extract scam intelligence entities from the message. "
        "Return ONLY valid JSON with these keys:\n"
        "- bankAccounts: string[]\n"
        "- upiIds: string[]\n"
        "- phishingLinks: string[]\n"
        "- phoneNumbers: string[]\n"
        "- suspiciousKeywords: string[]\n"
        "- referenceIds: string[]\n"
        "- amounts: string[]\n"
        "- emails: string[]\n"
        "- cryptoWallets: string[]\n"
        "- domains: string[]\n"
        "- ifscCodes: string[]\n"
        "If none, use empty arrays. No commentary."
    )

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": text},
    ]

    raw = None
    if openai and openai.api_key:
        raw = openai.chat(
            messages,
            temperature=0.0,
            max_tokens=260,
            response_format={"type": "json_object"},
        )

    if not raw and gemini and gemini.api_key:
        raw = gemini.chat(messages, temperature=0.0, max_tokens=260)

    if not raw:
        return _empty_payload()

    obj = extract_json_object(raw)
    if not isinstance(obj, dict):
        return _empty_payload()

    callback = {
        "bankAccounts": _coerce_list(obj.get("bankAccounts")),
        "upiIds": _coerce_list(obj.get("upiIds")),
        "phishingLinks": _coerce_list(obj.get("phishingLinks")),
        "phoneNumbers": _coerce_list(obj.get("phoneNumbers")),
        "suspiciousKeywords": _coerce_list(obj.get("suspiciousKeywords")),
    }
    extended = {
        "referenceIds": _coerce_list(obj.get("referenceIds")),
        "amounts": _coerce_list(obj.get("amounts")),
        "emails": _coerce_list(obj.get("emails")),
        "cryptoWallets": _coerce_list(obj.get("cryptoWallets")),
        "domains": _coerce_list(obj.get("domains")),
        "ifscCodes": _coerce_list(obj.get("ifscCodes")),
    }

    # Normalize a few common fields cheaply.
    callback["upiIds"] = [v.lower() for v in callback["upiIds"]]
    callback["phishingLinks"] = [v.rstrip("),.;") for v in callback["phishingLinks"]]
    extended["emails"] = [v.lower() for v in extended["emails"]]

    return callback, extended


def should_run_llm_extraction(last_run_at: Optional[float], min_interval_seconds: int) -> bool:
    now = time.time()
    if last_run_at is None:
        return True
    return (now - last_run_at) >= max(0, min_interval_seconds)

