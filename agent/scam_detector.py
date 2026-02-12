import re
from dataclasses import dataclass
from typing import Dict, List, Sequence, Union


URL_PATTERN = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
UPI_URL_PARAM = re.compile(r"(?i)[?&]pa=([a-z0-9.\-_]+@[a-z0-9]+)")
UPI_PATTERN = re.compile(r"(?i)\b[a-z0-9.\-_]{2,}@[a-z0-9]{2,}\b(?!\.[a-z]{2,})")
PHONE_PATTERN = re.compile(r"\b(?:\+?\d{1,3}[\s-]?)?(?:\d{10})\b")
BANK_PATTERN = re.compile(r"\b\d{9,18}\b")
IFSC_PATTERN = re.compile(r"\b[A-Z]{4}0[0-9A-Z]{6}\b")
OTP_PATTERN = re.compile(r"\b(?:otp|one\s*time\s*password|verification\s*code)\b", re.IGNORECASE)


KEYWORD_WEIGHTS: Dict[str, int] = {
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
    "wallet": 2,
    "invoice": 2,
}


@dataclass(frozen=True)
class ScamDetectionResult:
    is_scam: bool
    confidence: float
    category: str
    score: int
    triggers: List[str]
    suspicious_keywords: List[str]


class ScamDetector:
    def __init__(self, suspect_threshold: int = 4):
        self.suspect_threshold = suspect_threshold

    def detect(self, texts: Union[str, Sequence[str]]) -> ScamDetectionResult:
        combined = texts if isinstance(texts, str) else " ".join(texts)
        lowered = combined.lower()

        score = 0
        triggers: List[str] = []
        suspicious: List[str] = []

        for keyword, weight in KEYWORD_WEIGHTS.items():
            if keyword in lowered:
                score += weight
                triggers.append(keyword)
                suspicious.append(keyword)

        if URL_PATTERN.search(combined):
            score += 3
            triggers.append("link")
            suspicious.append("link")

        if UPI_PATTERN.search(combined) or UPI_URL_PARAM.search(combined):
            score += 4
            triggers.append("upi")
            suspicious.append("upi")

        if OTP_PATTERN.search(combined):
            score += 4
            triggers.append("otp")
            suspicious.append("otp")

        if PHONE_PATTERN.search(combined):
            score += 1
            triggers.append("phone")

        if BANK_PATTERN.search(combined):
            score += 2
            triggers.append("account")

        if IFSC_PATTERN.search(combined):
            score += 2
            triggers.append("ifsc")

        triggers = sorted(set(triggers))
        suspicious = sorted(set(suspicious))

        confidence = min(1.0, score / 10.0)
        is_scam = score >= self.suspect_threshold
        category = self._category_from_signals(lowered, triggers, suspicious)

        return ScamDetectionResult(
            is_scam=is_scam,
            confidence=round(confidence, 2),
            category=category,
            score=score,
            triggers=triggers,
            suspicious_keywords=suspicious,
        )

    def _category_from_signals(self, lowered: str, triggers: List[str], suspicious: List[str]) -> str:
        if "upi" in triggers or "upi" in suspicious:
            return "UPI_FRAUD"
        if "link" in triggers or "click" in lowered:
            return "PHISHING"
        if "kyc" in suspicious:
            return "KYC_FRAUD"
        if "prize" in suspicious or "lottery" in suspicious:
            return "LOTTERY_SCAM"
        if "refund" in suspicious or "cashback" in suspicious:
            return "REFUND_SCAM"
        if "bank" in lowered or "account" in lowered:
            return "BANK_FRAUD"
        return "GENERIC_SCAM"
