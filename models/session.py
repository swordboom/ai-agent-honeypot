import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union


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

    reference_ids: set = field(default_factory=set)
    amounts: set = field(default_factory=set)
    emails: set = field(default_factory=set)
    crypto_wallets: set = field(default_factory=set)
    domains: set = field(default_factory=set)
    ifsc_codes: set = field(default_factory=set)

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

    def to_callback_payload(self) -> Dict[str, List[str]]:
        return {
            # GUVI schema only provides "bankAccounts"; include IFSC codes here as well.
            "bankAccounts": sorted(self.bank_accounts.union(self.ifsc_codes)),
            "upiIds": sorted(self.upi_ids),
            "phishingLinks": sorted(self.phishing_links),
            "phoneNumbers": sorted(self.phone_numbers),
            "suspiciousKeywords": sorted(self.suspicious_keywords),
        }

    def to_extended_payload(self) -> Dict[str, List[str]]:
        return {
            "referenceIds": sorted(self.reference_ids),
            "amounts": sorted(self.amounts),
            "emails": sorted(self.emails),
            "cryptoWallets": sorted(self.crypto_wallets),
            "domains": sorted(self.domains),
            "ifscCodes": sorted(self.ifsc_codes),
        }

    def merge_callback_payload(self, payload: Dict[str, List[str]]) -> None:
        self.bank_accounts.update(payload.get("bankAccounts", []))
        self.upi_ids.update(payload.get("upiIds", []))
        self.phishing_links.update(payload.get("phishingLinks", []))
        self.phone_numbers.update(payload.get("phoneNumbers", []))
        self.suspicious_keywords.update(payload.get("suspiciousKeywords", []))

    def merge_extended_payload(self, payload: Dict[str, List[str]]) -> None:
        self.reference_ids.update(payload.get("referenceIds", []))
        self.amounts.update(payload.get("amounts", []))
        self.emails.update(payload.get("emails", []))
        self.crypto_wallets.update(payload.get("cryptoWallets", []))
        self.domains.update(payload.get("domains", []))
        self.ifsc_codes.update(payload.get("ifscCodes", []))


@dataclass
class SessionState:
    session_id: str
    persona_id: str
    persona_label: str

    scam_detected: bool = False
    scam_confidence: float = 0.0
    scam_category: str = "UNKNOWN"
    scam_triggers: List[str] = field(default_factory=list)

    agent_turns: int = 0
    scammer_messages: int = 0

    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    first_scam_timestamp: Optional[float] = None
    finalized_timestamp: Optional[float] = None

    transcript: List[TranscriptMessage] = field(default_factory=list)
    intel: Intelligence = field(default_factory=Intelligence)

    agent_notes: str = ""
    finalized: bool = False
    closed: bool = False
    final_total_messages_exchanged: Optional[int] = None

    reply_provider: str = "rules"

    last_llm_extraction_at: Optional[float] = None

    callback_sent: bool = False
    callback_payload_signature: Optional[str] = None
    callback_updates: int = 0
    callback_attempts: int = 0
    callback_last_status: Optional[int] = None
    callback_last_error: Optional[str] = None
    callback_last_sent_at: Optional[float] = None
