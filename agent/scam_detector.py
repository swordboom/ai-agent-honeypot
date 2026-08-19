import re
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Union

from agent.multilingual import detect_language, scan as multilingual_scan


URL_PATTERN = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
UPI_URL_PARAM = re.compile(r"(?i)[?&]pa=([a-z0-9.\-_]+@[a-z0-9]+)")
UPI_PATTERN = re.compile(r"(?i)\b[a-z0-9.\-_]{2,}@[a-z0-9]{2,}\b(?!\.[a-z]{2,})")
PHONE_PATTERN = re.compile(r"\+?\d[\d -]{8,14}\d")
BANK_PATTERN = re.compile(r"\b\d{9,18}\b")
IFSC_PATTERN = re.compile(r"\b[A-Z]{4}0[0-9A-Z]{6}\b")
OTP_PATTERN = re.compile(r"\b(?:otp|one\s*time\s*password|verification\s*code)\b", re.IGNORECASE)
# A crypto address in an unsolicited message is as strong a signal as a UPI handle.
CRYPTO_PATTERN = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,42}\b|\b0x[a-fA-F0-9]{40}\b")


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
    "arrest": 3,
    "warrant": 3,
    "cbi": 3,
    "narcotics": 3,
    "bitcoin": 2,
    "btc": 2,
    "usdt": 2,
    "crypto": 2,
    "doubling": 3,
    "guaranteed": 2,
    "investment": 2,
    "profit": 2,
    "parcel": 2,
    "aadhaar": 2,
}


@dataclass(frozen=True)
class ScamDetectionResult:
    is_scam: bool
    confidence: float
    category: str
    score: int
    triggers: List[str]
    suspicious_keywords: List[str]
    language: str = "en"
    language_name: str = "English"
    language_confidence: float = 0.0
    vernacular_score: int = 0
    vernacular_terms: List[str] = field(default_factory=list)


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

        if CRYPTO_PATTERN.search(combined):
            score += 4
            triggers.append("wallet")
            suspicious.append("wallet")

        # Feature 11: vernacular scam vocabulary scores on the same scale as English.
        vernacular = multilingual_scan(combined)
        language = detect_language(combined)
        if vernacular.score:
            score += vernacular.score
            triggers.extend(vernacular.matched_terms)
            triggers.extend(f"lang:{code}" for code in vernacular.languages_hit)
            suspicious.extend(vernacular.matched_terms)

        triggers = sorted(set(triggers))
        suspicious = sorted(set(suspicious))

        confidence = min(1.0, score / 10.0)
        is_scam = score >= self.suspect_threshold
        category = self._category_from_signals(lowered, triggers, suspicious)
        if category == "GENERIC_SCAM" and vernacular.category_hint:
            category = vernacular.category_hint

        return ScamDetectionResult(
            is_scam=is_scam,
            confidence=round(confidence, 2),
            category=category,
            score=score,
            triggers=triggers,
            suspicious_keywords=suspicious,
            language=language.code,
            language_name=language.name,
            language_confidence=language.confidence,
            vernacular_score=vernacular.score,
            vernacular_terms=vernacular.matched_terms,
        )

    def _category_from_signals(self, lowered: str, triggers: List[str], suspicious: List[str]) -> str:
        if "arrest" in suspicious or "warrant" in suspicious or "narcotics" in suspicious:
            return "DIGITAL_ARREST"
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
        if "wallet" in suspicious or "bitcoin" in suspicious or "crypto" in suspicious:
            return "CRYPTO_SCAM"
        if "bank" in lowered or "account" in lowered:
            return "BANK_FRAUD"
        return "GENERIC_SCAM"
