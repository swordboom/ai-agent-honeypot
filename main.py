import os
import re
import time
import random
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Literal

import requests
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

APP_NAME = "Agentic Honey-Pot"

API_KEY = os.getenv("HONEY_POT_API_KEY") or os.getenv("API_KEY") or "dev-key"
EXTENDED_RESPONSE = str(os.getenv("HONEY_POT_EXTENDED_RESPONSE", "")).lower() in (
    "1",
    "true",
    "yes",
)
CALLBACK_ENDPOINT = os.getenv(
    "HONEY_POT_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
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
UPI_URL_PARAM = re.compile(r'(?i)[?&]pa=([a-z0-9.\-_]+@[a-z0-9]+)')
UPI_PATTERN = re.compile(
    r'(?i)\b[a-z0-9.\-_]{2,}@(?:upi|ybl|ibl|okaxis|oksbi|okicici|paytm|phonepe|axl|apl)\b'
)
PHONE_PATTERN = re.compile(r"\b(?:\+?\d{1,3}[\s-]?)?(?:\d{10})\b")
BANK_PATTERN = re.compile(r"\b\d{9,18}\b")
IFSC_PATTERN = re.compile(r"\b[A-Z]{4}0[0-9A-Z]{6}\b")
OTP_PATTERN = re.compile(r"\b(?:otp|one\s*time\s*password|verification\s*code)\b", re.IGNORECASE)

SUSPECT_THRESHOLD = 4
STRONG_THRESHOLD = 7

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


@dataclass
class Intelligence:
    bank_accounts: set = field(default_factory=set)
    upi_ids: set = field(default_factory=set)
    phishing_links: set = field(default_factory=set)
    phone_numbers: set = field(default_factory=set)
    suspicious_keywords: set = field(default_factory=set)

    def has_actionable(self) -> bool:
        return any(
            [
                self.bank_accounts,
                self.upi_ids,
                self.phishing_links,
                self.phone_numbers,
            ]
        )

    def has_any(self) -> bool:
        return self.has_actionable() or bool(self.suspicious_keywords)

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
    scam_detected: bool = False
    agent_turns: int = 0
    last_score: int = 0
    scammer_messages: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    intel: Intelligence = field(default_factory=Intelligence)
    agent_notes: str = ""
    finalized: bool = False
    callback_sent: bool = False


SESSION_STORE: Dict[str, SessionState] = {}


def _require_api_key(x_api_key: Optional[str]) -> None:
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    if digits.startswith("91") and len(digits) == 12:
        return "+" + digits
    if len(digits) == 10:
        return "+91" + digits
    if len(digits) > 0 and not digits.startswith("+"):
        return "+" + digits
    return raw


def _collect_texts(message: Message, history: List[Message]) -> List[str]:
    texts = [m.text for m in history if m.text and m.sender == "scammer"]
    if message.text and message.sender == "scammer":
        texts.append(message.text)
    return texts


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

    if UPI_PATTERN.search(combined):
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

    scam_detected = score >= SUSPECT_THRESHOLD
    return {"scamDetected": scam_detected, "score": score, "triggers": triggers}


def extract_intelligence(texts: List[str], intel: Intelligence) -> None:
    combined = " ".join(texts)

    for match in URL_PATTERN.findall(combined):
        cleaned = match.rstrip("),.;")
        intel.phishing_links.add(cleaned)

    # Extract UPI IDs from URL parameters (e.g., ?pa=merchant@ybl)
    for match in UPI_URL_PARAM.findall(combined):
        intel.upi_ids.add(match.lower())

    # Extract UPI IDs from plain text (e.g., "pay to user@paytm")
    for match in UPI_PATTERN.findall(combined):
        intel.upi_ids.add(match.lower())

    for match in PHONE_PATTERN.findall(combined):
        intel.phone_numbers.add(_normalize_phone(match))

    for match in BANK_PATTERN.findall(combined):
        if len(match) >= 9:
            intel.bank_accounts.add(match)

    for match in IFSC_PATTERN.findall(combined):
        intel.bank_accounts.add(match)

    lowered = combined.lower()
    for keyword in KEYWORD_WEIGHTS:
        if keyword in lowered:
            intel.suspicious_keywords.add(keyword)


def generate_reply(state: SessionState, message: Message, metadata: Optional[Metadata]) -> str:
    locale = (metadata.locale if metadata else None) or ""
    channel = (metadata.channel if metadata else None) or ""

    missing = []
    if not state.intel.upi_ids:
        missing.append("upi")
    if not state.intel.phishing_links:
        missing.append("link")
    if not state.intel.phone_numbers:
        missing.append("phone")
    if not state.intel.bank_accounts:
        missing.append("account")

    if state.agent_turns == 0:
        return (
            "Hi, I just saw your message. Which bank is this about? "
            "Please share the official helpline or reference number so I can verify." 
        )

    if state.agent_turns == 1:
        if "link" in missing:
            return "Can you send the verification link again? It is not opening on my phone."
        if "upi" in missing:
            return "My UPI app is not showing any request. What UPI ID should I use?"
        return "Could you repeat the exact steps once? I do not want to make a mistake."

    if state.agent_turns == 2:
        if "phone" in missing:
            return "Is there a number I can call back? My connection keeps dropping."
        if "account" in missing:
            return "Before I proceed, can you confirm the account number or IFSC for verification?"
        return "I am about to proceed, but I am at work. Please resend the details." 

    fallback_pool = [
        "Sorry, I am outside right now. Can you resend the details once more?",
        "My banking app is slow today. Can you keep the request open and share the reference ID?",
        "Just to be safe, can you confirm the official contact number again?",
        "I want to complete this correctly. Please share the exact steps or link once more.",
    ]

    if "upi" in missing:
        return "I am ready now. Please send the UPI ID and the exact amount again."
    if "link" in missing:
        return "I still cannot open the link. Please send it again or the official site."
    if "phone" in missing:
        return "Can you share a callback number? I do not want to miss any update."

    return random.choice(fallback_pool)


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

    has_actionable = state.intel.has_actionable()

    if state.agent_turns >= 6:
        return True

    if state.agent_turns >= 2 and has_actionable:
        return True

    if state.agent_turns >= 1 and has_actionable and state.last_score >= STRONG_THRESHOLD:
        return True

    return False


def send_final_callback(state: SessionState, total_messages: int) -> None:
    payload = {
        "sessionId": state.session_id,
        "scamDetected": state.scam_detected,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": state.intel.to_payload(),
        "agentNotes": state.agent_notes,
    }

    try:
        response = requests.post(CALLBACK_ENDPOINT, json=payload, timeout=5)
        response.raise_for_status()
        state.callback_sent = True
        logger.info("Final callback sent for session %s", state.session_id)
    except Exception as exc:
        logger.warning("Failed to send final callback for %s: %s", state.session_id, exc)


def compute_total_messages(event: MessageEvent, include_reply: bool = True) -> int:
    total = len(event.conversationHistory) + 1
    if include_reply:
        total += 1
    return total


@app.get("/health")
async def healthcheck():
    return {"status": "ok"}


@app.post("/api/message")
async def handle_message(event: MessageEvent, x_api_key: Optional[str] = Header(None)):
    _require_api_key(x_api_key)

    state = SESSION_STORE.get(event.sessionId)
    if not state:
        state = SessionState(session_id=event.sessionId)
        SESSION_STORE[event.sessionId] = state

    state.updated_at = time.time()

    texts = _collect_texts(event.message, event.conversationHistory)
    detection = detect_scam(texts)
    state.last_score = int(detection["score"])

    if detection["scamDetected"]:
        state.scam_detected = True

    if event.message.sender == "scammer":
        state.scammer_messages += 1

    extract_intelligence(texts, state.intel)

    agent_active = state.scam_detected

    if agent_active:
        reply = generate_reply(state, event.message, event.metadata)
    else:
        reply = "Sorry, I am not sure I understand. Can you clarify what this is about?"

    if agent_active:
        state.agent_turns += 1

    total_messages = compute_total_messages(event, include_reply=True)

    if should_finalize(state):
        state.finalized = True
        state.agent_notes = build_agent_notes(state)
        if not state.callback_sent:
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
            }
        )

    return response

@app.post("/")
async def root_entry(event: MessageEvent, x_api_key: Optional[str] = Header(None)):
    return await handle_message(event, x_api_key)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))