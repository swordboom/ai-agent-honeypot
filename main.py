import hashlib
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Tuple, Union

import requests
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

APP_NAME = "Agentic Honey-Pot"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(APP_DIR, "static")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


API_KEY = os.getenv("HONEY_POT_API_KEY") or os.getenv("API_KEY") or "dev-key"
DASHBOARD_KEY = os.getenv("HONEY_POT_DASHBOARD_KEY") or ""
EXTENDED_RESPONSE = _env_bool("HONEY_POT_EXTENDED_RESPONSE", False)
CALLBACK_ENDPOINT = os.getenv(
    "HONEY_POT_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or ""
OPENAI_MODEL = os.getenv("OPENAI_MODEL") or "gpt-4o-mini"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or ""
GEMINI_MODEL = os.getenv("GEMINI_MODEL") or "gemini-1.5-flash"
AGENT_MAX_HISTORY_MESSAGES = int(os.getenv("AGENT_MAX_HISTORY_MESSAGES") or "12")
LLM_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS") or "10")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(APP_NAME)

KEYWORD_WEIGHTS = {
    "account": 1,
    "bank": 1,
    "blocked": 2,
    "suspended": 2,
    "verify": 2,
    "verification": 2,
    "kyc": 3,
    "otp": 4,
    "pin": 3,
    "upi": 3,
    "refund": 2,
    "urgent": 2,
    "immediately": 2,
    "today": 1,
    "click": 2,
    "link": 2,
    "prize": 2,
    "lottery": 2,
    "offer": 1,
    "reward": 2,
    "cashback": 2,
    "penalty": 2,
    "police": 2,
    "customs": 2,
    "tax": 2,
    "loan": 1,
    "credit": 1,
    "suspicion": 2,
    "suspicious": 2,
    "wallet": 2,
    "invoice": 2,
}

URL_PATTERN = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
UPI_URL_PARAM = re.compile(r"(?i)[?&]pa=([a-z0-9.\-_]+@[a-z0-9]+)")
UPI_PATTERN = re.compile(r"(?i)\b[a-z0-9.\-_]{2,}@[a-z0-9]{2,}\b")
PHONE_PATTERN = re.compile(r"\b(?:\+?\d{1,3}[\s-]?)?(?:\d{10})\b")
BANK_PATTERN = re.compile(r"\b\d{9,18}\b")
IFSC_PATTERN = re.compile(r"\b[A-Z]{4}0[0-9A-Z]{6}\b")
OTP_PATTERN = re.compile(r"\b(?:otp|one\s*time\s*password|verification\s*code)\b", re.IGNORECASE)

SUSPECT_THRESHOLD = 4
STRONG_THRESHOLD = 7

COUNTRY_PREFIXES = {
    "91": ("IN", "India"),
    "1": ("US", "United States"),
    "44": ("GB", "United Kingdom"),
    "61": ("AU", "Australia"),
    "65": ("SG", "Singapore"),
    "880": ("BD", "Bangladesh"),
    "92": ("PK", "Pakistan"),
    "94": ("LK", "Sri Lanka"),
    "971": ("AE", "United Arab Emirates"),
}


@dataclass(frozen=True)
class Persona:
    id: str
    display_name: str
    age_profile: str
    style_rules: str
    goal_bias: str


PERSONAS: List[Persona] = [
    Persona(
        id="retired_teacher",
        display_name="Arthur D'Souza",
        age_profile="65-year-old retired teacher",
        style_rules=(
            "Write short, polite messages. Sound slightly confused with technology and ask for"
            " repeated instructions."
        ),
        goal_bias="Prioritize asking for UPI ID and official helpline reference.",
    ),
    Persona(
        id="busy_shop_owner",
        display_name="Meena Traders",
        age_profile="42-year-old small shop owner",
        style_rules=(
            "Be practical and rushed. Mention customers and ask the scammer to quickly resend"
            " exact payment details."
        ),
        goal_bias="Prioritize collecting payment account details and callback number.",
    ),
    Persona(
        id="supportive_parent",
        display_name="Ravi Nair",
        age_profile="51-year-old parent handling family banking",
        style_rules=(
            "Stay cooperative but cautious. Ask for confirmation links, official contacts, and"
            " reference IDs."
        ),
        goal_bias="Prioritize phishing links and phone numbers before payment details.",
    ),
]

app = FastAPI(title=APP_NAME)


class Message(BaseModel):
    sender: Literal["scammer", "user"]
    text: str
    timestamp: Optional[Union[int, str]] = None


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class MessageEvent(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)
    metadata: Optional[Metadata] = None


class DashboardIntelCounts(BaseModel):
    bankAccounts: int
    upiIds: int
    phishingLinks: int
    phoneNumbers: int


class DashboardSummary(BaseModel):
    activeEngagements: int
    totalSessions: int
    finalizedSessions: int
    totalScammerTimeWastedSeconds: int
    totalExtracted: DashboardIntelCounts


class DashboardSessionCard(BaseModel):
    sessionId: str
    persona: str
    scamDetected: bool
    engagementComplete: bool
    messageCount: int
    lastUpdated: int
    intelCounts: DashboardIntelCounts


class DashboardTranscriptEntry(BaseModel):
    sender: str
    text: str
    timestamp: Union[int, str]
    provider: Optional[str] = None


class DashboardSessionDetail(BaseModel):
    sessionId: str
    personaId: str
    persona: str
    scamDetected: bool
    engagementComplete: bool
    replyProvider: str
    callbackSent: bool
    totalMessages: int
    timeWastedSeconds: int
    extractedIntelligence: Dict[str, List[str]]
    transcript: List[DashboardTranscriptEntry]


class DashboardMapPoint(BaseModel):
    countryCode: str
    countryName: str
    count: int


@dataclass
class TranscriptMessage:
    sender: str
    text: str
    timestamp: Union[int, str]
    provider: Optional[str] = None


@dataclass
class Intelligence:
    bank_accounts: set = field(default_factory=set)
    upi_ids: set = field(default_factory=set)
    phishing_links: set = field(default_factory=set)
    phone_numbers: set = field(default_factory=set)
    suspicious_keywords: set = field(default_factory=set)

    def has_actionable(self) -> bool:
        return any([self.bank_accounts, self.upi_ids, self.phishing_links, self.phone_numbers])

    def actionable_category_count(self) -> int:
        return sum(
            [
                1 if self.bank_accounts else 0,
                1 if self.upi_ids else 0,
                1 if self.phishing_links else 0,
                1 if self.phone_numbers else 0,
            ]
        )

    def has_high_value(self) -> bool:
        return any([self.bank_accounts, self.upi_ids, self.phishing_links])

    def to_payload(self) -> Dict[str, List[str]]:
        return {
            "bankAccounts": sorted(self.bank_accounts),
            "upiIds": sorted(self.upi_ids),
            "phishingLinks": sorted(self.phishing_links),
            "phoneNumbers": sorted(self.phone_numbers),
            "suspiciousKeywords": sorted(self.suspicious_keywords),
        }


@dataclass
class SessionState:
    session_id: str
    persona_id: str
    persona_label: str
    scam_detected: bool = False
    agent_turns: int = 0
    last_score: int = 0
    scammer_messages: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    first_scam_timestamp: Optional[float] = None
    finalized_timestamp: Optional[float] = None
    transcript: List[TranscriptMessage] = field(default_factory=list)
    intel: Intelligence = field(default_factory=Intelligence)
    agent_notes: str = ""
    finalized: bool = False
    callback_sent: bool = False
    callback_payload_signature: Optional[str] = None
    reply_provider: str = "rules"


SESSION_STORE: Dict[str, SessionState] = {}


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _require_api_key(x_api_key: Optional[str]) -> None:
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _require_dashboard_key(x_dashboard_key: Optional[str]) -> None:
    if not DASHBOARD_KEY:
        raise HTTPException(status_code=503, detail="Dashboard key is not configured")
    if not x_dashboard_key or x_dashboard_key != DASHBOARD_KEY:
        raise HTTPException(status_code=401, detail="Invalid dashboard key")


def _normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    if digits.startswith("91") and len(digits) == 12:
        return "+" + digits
    if len(digits) == 10:
        return "+91" + digits
    if digits:
        return "+" + digits
    return raw


def _collect_texts(message: Message, history: List[Message]) -> List[str]:
    texts = [m.text for m in history if m.text and m.sender == "scammer"]
    if message.text and message.sender == "scammer":
        texts.append(message.text)
    return texts


def assign_persona(session_id: str) -> Persona:
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    index = int(digest[:8], 16) % len(PERSONAS)
    return PERSONAS[index]


def ensure_session_state(session_id: str) -> SessionState:
    state = SESSION_STORE.get(session_id)
    if state:
        return state

    persona = assign_persona(session_id)
    state = SessionState(
        session_id=session_id,
        persona_id=persona.id,
        persona_label=f"{persona.display_name} ({persona.age_profile})",
    )
    SESSION_STORE[session_id] = state
    return state


def _append_transcript(
    state: SessionState,
    sender: str,
    text: str,
    timestamp: Optional[Union[int, str]] = None,
    provider: Optional[str] = None,
) -> None:
    if not text:
        return
    entry = TranscriptMessage(
        sender=sender,
        text=text,
        timestamp=timestamp if timestamp is not None else int(time.time() * 1000),
        provider=provider,
    )
    if state.transcript:
        last = state.transcript[-1]
        if last.sender == entry.sender and last.text == entry.text and str(last.timestamp) == str(entry.timestamp):
            return
    state.transcript.append(entry)


def _seed_history_if_needed(state: SessionState, history: List[Message]) -> None:
    if state.transcript:
        return
    for msg in history:
        _append_transcript(state, msg.sender, msg.text, msg.timestamp)


def detect_scam(texts: List[str]) -> Dict[str, Union[bool, int, List[str]]]:
    combined = " ".join(texts)
    lowered = combined.lower()
    score = 0
    triggers: List[str] = []

    for keyword, weight in KEYWORD_WEIGHTS.items():
        if keyword in lowered:
            score += weight
            triggers.append(keyword)

    if URL_PATTERN.search(combined):
        score += 3
        triggers.append("link")

    if UPI_PATTERN.search(combined) or UPI_URL_PARAM.search(combined):
        score += 4
        triggers.append("upi")

    if OTP_PATTERN.search(combined):
        score += 4
        triggers.append("otp")

    if PHONE_PATTERN.search(combined):
        score += 1
        triggers.append("phone")

    if BANK_PATTERN.search(combined):
        score += 2
        triggers.append("account")

    if IFSC_PATTERN.search(combined):
        score += 2
        triggers.append("ifsc")

    return {"scamDetected": score >= SUSPECT_THRESHOLD, "score": score, "triggers": triggers}


def extract_intelligence(texts: List[str], intel: Intelligence) -> None:
    combined = " ".join(texts)

    for match in URL_PATTERN.findall(combined):
        intel.phishing_links.add(match.rstrip("),.;"))

    for match in UPI_URL_PARAM.findall(combined):
        intel.upi_ids.add(match.lower())

    for match in UPI_PATTERN.findall(combined):
        intel.upi_ids.add(match.lower())

    phone_digits = set()
    for match in PHONE_PATTERN.findall(combined):
        normalized = _normalize_phone(match)
        intel.phone_numbers.add(normalized)
        phone_digits.add(re.sub(r"\D", "", normalized))

    for match in BANK_PATTERN.findall(combined):
        # Prevent phone numbers from being misclassified as bank accounts.
        if any(digits.endswith(match) for digits in phone_digits):
            continue
        intel.bank_accounts.add(match)

    for match in IFSC_PATTERN.findall(combined):
        intel.bank_accounts.add(match)

    lowered = combined.lower()
    for keyword in KEYWORD_WEIGHTS:
        if keyword in lowered:
            intel.suspicious_keywords.add(keyword)


def _missing_intel_targets(intel: Intelligence) -> List[str]:
    missing = []
    if not intel.upi_ids:
        missing.append("upi")
    if not intel.phishing_links:
        missing.append("link")
    if not intel.phone_numbers:
        missing.append("phone")
    if not intel.bank_accounts:
        missing.append("account")
    return missing


def build_tactical_hint(missing_targets: List[str]) -> str:
    if "upi" in missing_targets:
        return "Ask naturally for their UPI handle and payment instruction details."
    if "link" in missing_targets:
        return "Ask for the exact verification link again and claim it did not open."
    if "phone" in missing_targets:
        return "Ask for a callback number and official contact for confirmation."
    if "account" in missing_targets:
        return "Ask for account number or IFSC in order to proceed with payment."
    return "Keep them engaged with short clarifying questions and avoid ending the conversation."


def _system_prompt(persona: Persona, metadata: Optional[Metadata], tactical_hint: str) -> str:
    channel = metadata.channel if metadata and metadata.channel else "Unknown"
    locale = metadata.locale if metadata and metadata.locale else "Unknown"
    language = metadata.language if metadata and metadata.language else "English"

    return (
        "You are role-playing as a potential scam victim. Stay believable, concise, and human. "
        "Do not disclose that you are an AI, bot, or honeypot. Do not provide illegal or harmful instructions. "
        "Do not insult or harass. Keep reply under 35 words unless clarification is needed. "
        f"Persona: {persona.display_name}, {persona.age_profile}. "
        f"Style: {persona.style_rules} "
        f"Goal bias: {persona.goal_bias} "
        f"Context channel={channel}, locale={locale}, language={language}. "
        f"Internal tactic: {tactical_hint}"
    )


def _build_llm_messages(
    state: SessionState,
    metadata: Optional[Metadata],
    missing_targets: List[str],
) -> List[Dict[str, str]]:
    persona = next((p for p in PERSONAS if p.id == state.persona_id), PERSONAS[0])
    messages: List[Dict[str, str]] = [
        {
            "role": "system",
            "content": _system_prompt(persona, metadata, build_tactical_hint(missing_targets)),
        }
    ]

    for msg in state.transcript[-AGENT_MAX_HISTORY_MESSAGES:]:
        role = "user" if msg.sender == "scammer" else "assistant"
        messages.append({"role": role, "content": msg.text})

    return messages


def _sanitize_reply(text: Optional[str]) -> str:
    if not text:
        return ""
    cleaned = " ".join(text.replace("\n", " ").strip().split())
    lower = cleaned.lower()
    blocked_markers = ["as an ai", "language model", "honeypot", "bot"]
    if any(marker in lower for marker in blocked_markers):
        return ""
    return cleaned[:240]


def generate_with_openai(messages: List[Dict[str, str]]) -> Optional[str]:
    if not OPENAI_API_KEY:
        return None

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": OPENAI_MODEL,
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 120,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=LLM_TIMEOUT_SECONDS)
        if response.status_code >= 400:
            logger.warning("OpenAI reply failed: status=%s body=%s", response.status_code, response.text[:200])
            return None
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        return _sanitize_reply(content)
    except Exception as exc:
        logger.warning("OpenAI request failed: %s", exc)
        return None


def generate_with_gemini(messages: List[Dict[str, str]]) -> Optional[str]:
    if not GEMINI_API_KEY:
        return None

    system_parts = [m["content"] for m in messages if m["role"] == "system"]
    dialog = [m for m in messages if m["role"] != "system"]

    contents = []
    for msg in dialog:
        role = "user" if msg["role"] == "user" else "model"
        contents.append({"role": role, "parts": [{"text": msg["content"]}]})

    if not contents:
        contents.append({"role": "user", "parts": [{"text": "Hello"}]})

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    )
    payload = {
        "system_instruction": {"parts": [{"text": "\n".join(system_parts)}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.7, "maxOutputTokens": 120},
    }

    try:
        response = requests.post(url, json=payload, timeout=LLM_TIMEOUT_SECONDS)
        if response.status_code >= 400:
            logger.warning("Gemini reply failed: status=%s body=%s", response.status_code, response.text[:200])
            return None
        data = response.json()
        candidates = data.get("candidates") or []
        if not candidates:
            return None
        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            return None
        content = parts[0].get("text", "")
        return _sanitize_reply(content)
    except Exception as exc:
        logger.warning("Gemini request failed: %s", exc)
        return None


def _last_agent_reply(state: SessionState) -> str:
    for entry in reversed(state.transcript):
        if entry.sender == "user":
            return entry.text.strip()
    return ""


def _pick_non_repeating(candidates: List[str], last_reply: str) -> str:
    for candidate in candidates:
        if candidate != last_reply:
            return candidate
    return random.choice(candidates)


def generate_rule_based_reply(state: SessionState) -> str:
    missing = _missing_intel_targets(state.intel)
    last_reply = _last_agent_reply(state)

    if state.agent_turns == 0:
        return (
            "Hi, I just saw your message. Which bank is this about? "
            "Please share the official helpline or reference number so I can verify."
        )

    if state.agent_turns == 1:
        if "link" in missing:
            return _pick_non_repeating(
                [
                    "Can you send the verification link again? It is not opening on my phone.",
                    "Please resend the link once more. It failed to load for me.",
                ],
                last_reply,
            )
        elif "upi" in missing:
            return _pick_non_repeating(
                [
                    "My UPI app is not showing any request. What UPI ID should I use?",
                    "I can pay now. Please share your exact UPI handle again.",
                ],
                last_reply,
            )
        return "Could you repeat the exact steps once? I do not want to make a mistake."

    if state.agent_turns == 2:
        if "phone" in missing:
            return _pick_non_repeating(
                [
                    "Is there a number I can call back? My connection keeps dropping.",
                    "Please share a callback number. The line keeps disconnecting.",
                ],
                last_reply,
            )
        elif "account" in missing:
            return _pick_non_repeating(
                [
                    "Before I proceed, can you confirm the account number or IFSC for verification?",
                    "Share the account number or IFSC once so I can complete this safely.",
                ],
                last_reply,
            )
        return "I am about to proceed, but I am at work. Please resend the details."

    fallback_pool = [
        "Sorry, I am outside right now. Can you resend the details once more?",
        "My banking app is slow today. Can you keep the request open and share the reference ID?",
        "Just to be safe, can you confirm the official contact number again?",
        "I want to complete this correctly. Please share the exact steps or link once more.",
    ]

    if "upi" in missing:
        return _pick_non_repeating(
            [
                "I am ready now. Please send the UPI ID and the exact amount again.",
                "Please confirm the UPI ID once more with the amount so I can transfer now.",
                "I can do it now. Share the UPI handle and amount one last time.",
            ],
            last_reply,
        )
    elif "link" in missing:
        return _pick_non_repeating(
            [
                "I still cannot open the link. Please send it again or the official site.",
                "The link still fails for me. Please resend it carefully.",
            ],
            last_reply,
        )
    elif "phone" in missing:
        return _pick_non_repeating(
            [
                "Can you share a callback number? I do not want to miss any update.",
                "Please send a direct number so I can call immediately.",
            ],
            last_reply,
        )

    return _pick_non_repeating(fallback_pool, last_reply)


def generate_agent_reply(state: SessionState, metadata: Optional[Metadata]) -> Tuple[str, str]:
    missing_targets = _missing_intel_targets(state.intel)
    llm_messages = _build_llm_messages(state, metadata, missing_targets)

    openai_reply = generate_with_openai(llm_messages)
    if openai_reply:
        return openai_reply, "openai"

    gemini_reply = generate_with_gemini(llm_messages)
    if gemini_reply:
        return gemini_reply, "gemini"

    return generate_rule_based_reply(state), "rules"


def build_agent_notes(state: SessionState) -> str:
    notes = []
    if "urgent" in state.intel.suspicious_keywords or "immediately" in state.intel.suspicious_keywords:
        notes.append("Used urgency tactics")
    if "verify" in state.intel.suspicious_keywords or "verification" in state.intel.suspicious_keywords:
        notes.append("Pushed for verification")
    if state.intel.upi_ids:
        notes.append("Requested UPI payment")
    if state.intel.phishing_links:
        notes.append("Shared a link")
    if state.intel.phone_numbers:
        notes.append("Provided phone contact")
    if state.intel.bank_accounts:
        notes.append("Shared account details")
    if not notes:
        notes.append("Likely phishing attempt with generic verification language")
    return "; ".join(notes)


def should_finalize(state: SessionState) -> bool:
    if state.finalized or not state.scam_detected:
        return False

    actionable_categories = state.intel.actionable_category_count()
    has_high_value = state.intel.has_high_value()

    # Hard stop to avoid never-ending sessions.
    if state.agent_turns >= 8:
        return True

    # Strong extraction signal: multiple actionable categories quickly collected.
    if actionable_categories >= 3 and state.agent_turns >= 2:
        return True

    # Balanced extraction signal: at least one high-value indicator plus another actionable signal.
    if has_high_value and actionable_categories >= 2 and state.agent_turns >= 3:
        return True

    # Conversation-depth fallback when high-value intel exists.
    if has_high_value and state.scammer_messages >= 4 and state.agent_turns >= 4:
        return True

    return False


def build_callback_payload(state: SessionState, total_messages: int) -> Dict[str, Union[str, bool, int, Dict[str, List[str]]]]:
    return {
        "sessionId": state.session_id,
        "scamDetected": state.scam_detected,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": state.intel.to_payload(),
        "agentNotes": state.agent_notes,
    }


def callback_payload_signature(payload: Dict[str, Union[str, bool, int, Dict[str, List[str]]]]) -> str:
    serialized = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def callback_has_updates(state: SessionState, total_messages: int) -> bool:
    payload = build_callback_payload(state, total_messages)
    signature = callback_payload_signature(payload)
    return signature != state.callback_payload_signature


def send_final_callback(state: SessionState, total_messages: int) -> None:
    payload = build_callback_payload(state, total_messages)
    payload_signature = callback_payload_signature(payload)

    if payload_signature == state.callback_payload_signature:
        return

    try:
        response = requests.post(CALLBACK_ENDPOINT, json=payload, timeout=5)
        response.raise_for_status()
        state.callback_sent = True
        state.callback_payload_signature = payload_signature
        logger.info("Final callback sent for session %s", state.session_id)
    except Exception as exc:
        logger.warning("Failed to send final callback for %s: %s", state.session_id, exc)


def compute_total_messages(event: MessageEvent, include_reply: bool = True) -> int:
    total = len(event.conversationHistory) + 1
    if include_reply:
        total += 1
    return total


def _session_time_wasted_seconds(state: SessionState, now_ts: float) -> int:
    if not state.scam_detected:
        return 0
    start = state.first_scam_timestamp or state.updated_at
    end = state.finalized_timestamp or now_ts
    return max(0, int(end - start))


def _intel_counts(intel: Intelligence) -> DashboardIntelCounts:
    return DashboardIntelCounts(
        bankAccounts=len(intel.bank_accounts),
        upiIds=len(intel.upi_ids),
        phishingLinks=len(intel.phishing_links),
        phoneNumbers=len(intel.phone_numbers),
    )


def _get_country_from_phone(phone: str) -> Tuple[str, str]:
    digits = re.sub(r"\D", "", phone)
    if len(digits) == 10:
        return COUNTRY_PREFIXES["91"]
    for prefix in sorted(COUNTRY_PREFIXES.keys(), key=len, reverse=True):
        if digits.startswith(prefix):
            return COUNTRY_PREFIXES[prefix]
    return "UN", "Unknown"


def _dashboard_summary() -> DashboardSummary:
    now_ts = time.time()
    active = 0
    finalized = 0
    total_wasted = 0

    all_bank = set()
    all_upi = set()
    all_links = set()
    all_phones = set()

    for state in SESSION_STORE.values():
        if state.scam_detected and not state.finalized:
            active += 1
        if state.finalized:
            finalized += 1
        total_wasted += _session_time_wasted_seconds(state, now_ts)

        all_bank.update(state.intel.bank_accounts)
        all_upi.update(state.intel.upi_ids)
        all_links.update(state.intel.phishing_links)
        all_phones.update(state.intel.phone_numbers)

    return DashboardSummary(
        activeEngagements=active,
        totalSessions=len(SESSION_STORE),
        finalizedSessions=finalized,
        totalScammerTimeWastedSeconds=total_wasted,
        totalExtracted=DashboardIntelCounts(
            bankAccounts=len(all_bank),
            upiIds=len(all_upi),
            phishingLinks=len(all_links),
            phoneNumbers=len(all_phones),
        ),
    )


def _session_card(state: SessionState) -> DashboardSessionCard:
    return DashboardSessionCard(
        sessionId=state.session_id,
        persona=state.persona_label,
        scamDetected=state.scam_detected,
        engagementComplete=state.finalized,
        messageCount=len(state.transcript),
        lastUpdated=int(state.updated_at),
        intelCounts=_intel_counts(state.intel),
    )


def _session_detail(state: SessionState) -> DashboardSessionDetail:
    now_ts = time.time()
    return DashboardSessionDetail(
        sessionId=state.session_id,
        personaId=state.persona_id,
        persona=state.persona_label,
        scamDetected=state.scam_detected,
        engagementComplete=state.finalized,
        replyProvider=state.reply_provider,
        callbackSent=state.callback_sent,
        totalMessages=len(state.transcript),
        timeWastedSeconds=_session_time_wasted_seconds(state, now_ts),
        extractedIntelligence=state.intel.to_payload(),
        transcript=[
            DashboardTranscriptEntry(
                sender=t.sender,
                text=t.text,
                timestamp=t.timestamp,
                provider=t.provider,
            )
            for t in state.transcript
        ],
    )


def _map_points() -> List[DashboardMapPoint]:
    counts: Dict[str, Dict[str, Union[str, int]]] = {}
    for state in SESSION_STORE.values():
        for phone in state.intel.phone_numbers:
            country_code, country_name = _get_country_from_phone(phone)
            if country_code not in counts:
                counts[country_code] = {
                    "countryCode": country_code,
                    "countryName": country_name,
                    "count": 0,
                }
            counts[country_code]["count"] = int(counts[country_code]["count"]) + 1

    result = [DashboardMapPoint(**value) for value in counts.values()]
    result.sort(key=lambda item: item.count, reverse=True)
    return result


@app.get("/health")
async def healthcheck() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/dashboard")
async def dashboard_page() -> FileResponse:
    file_path = os.path.join(STATIC_DIR, "dashboard.html")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Dashboard UI not found")
    return FileResponse(file_path)


@app.get("/dashboard/api/summary", response_model=DashboardSummary)
async def dashboard_summary(x_dashboard_key: Optional[str] = Header(None)) -> DashboardSummary:
    _require_dashboard_key(x_dashboard_key)
    return _dashboard_summary()


@app.get("/dashboard/api/sessions", response_model=List[DashboardSessionCard])
async def dashboard_sessions(
    limit: int = Query(default=50, ge=1, le=200),
    x_dashboard_key: Optional[str] = Header(None),
) -> List[DashboardSessionCard]:
    _require_dashboard_key(x_dashboard_key)
    sessions = sorted(SESSION_STORE.values(), key=lambda item: item.updated_at, reverse=True)
    return [_session_card(state) for state in sessions[:limit]]


@app.get("/dashboard/api/sessions/{session_id}", response_model=DashboardSessionDetail)
async def dashboard_session_detail(
    session_id: str,
    x_dashboard_key: Optional[str] = Header(None),
) -> DashboardSessionDetail:
    _require_dashboard_key(x_dashboard_key)
    state = SESSION_STORE.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail="Session not found")
    return _session_detail(state)


@app.get("/dashboard/api/map", response_model=List[DashboardMapPoint])
async def dashboard_map(x_dashboard_key: Optional[str] = Header(None)) -> List[DashboardMapPoint]:
    _require_dashboard_key(x_dashboard_key)
    return _map_points()


@app.post("/api/message")
async def handle_message(event: MessageEvent, x_api_key: Optional[str] = Header(None)):
    _require_api_key(x_api_key)

    state = ensure_session_state(event.sessionId)
    state.updated_at = time.time()

    _seed_history_if_needed(state, event.conversationHistory)
    _append_transcript(state, event.message.sender, event.message.text, event.message.timestamp)

    texts = _collect_texts(event.message, event.conversationHistory)
    detection = detect_scam(texts)
    state.last_score = int(detection["score"])

    if detection["scamDetected"] and not state.scam_detected:
        state.first_scam_timestamp = time.time()

    if detection["scamDetected"]:
        state.scam_detected = True

    if event.message.sender == "scammer":
        state.scammer_messages += 1

    extract_intelligence(texts, state.intel)

    if state.scam_detected:
        reply, provider = generate_agent_reply(state, event.metadata)
    else:
        reply, provider = (
            "Sorry, I am not sure I understand. Can you clarify what this is about?",
            "rules",
        )

    state.reply_provider = provider

    if state.scam_detected:
        state.agent_turns += 1

    _append_transcript(state, "user", reply, provider=provider)

    total_messages = compute_total_messages(event, include_reply=True)

    if should_finalize(state):
        state.finalized = True
        state.finalized_timestamp = time.time()

    if state.finalized:
        state.agent_notes = build_agent_notes(state)
        if callback_has_updates(state, total_messages):
            send_final_callback(state, total_messages)

    response = {
        "status": "success",
        "reply": reply,
    }

    if EXTENDED_RESPONSE:
        response.update(
            {
                "scamDetected": state.scam_detected,
                "engagementComplete": state.finalized,
                "extractedIntelligence": state.intel.to_payload(),
                "totalMessagesExchanged": total_messages,
                "persona": state.persona_label,
                "replyProvider": state.reply_provider,
            }
        )

    return response


@app.post("/")
async def root_entry(event: MessageEvent, x_api_key: Optional[str] = Header(None)):
    return await handle_message(event, x_api_key)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
