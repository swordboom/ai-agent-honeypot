import re
from typing import Iterable, Optional
from urllib.parse import urlparse

from models.session import Intelligence


URL_PATTERN = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
UPI_URL_PARAM = re.compile(r"(?i)[?&]pa=([a-z0-9.\-_]+@[a-z0-9]+)")
# Avoid matching email addresses like "name@gmail.com" (would otherwise match "name@gmail").
UPI_PATTERN = re.compile(r"(?i)\b[a-z0-9.\-_]{2,}@[a-z0-9]{2,}\b(?!\.[a-z]{2,})")
PHONE_PATTERN = re.compile(r"\b(?:\+?\d{1,3}[\s-]?)?(?:\d{10})\b")
BANK_PATTERN = re.compile(r"\b\d{9,18}\b")
IFSC_PATTERN = re.compile(r"\b[A-Z]{4}0[0-9A-Z]{6}\b")

REFERENCE_ID_PATTERN = re.compile(r"(?i)\b(?:ref(?:erence)?\s*id\s*[:\-]?\s*)?([A-Z]{2,5}\d{3,})\b")
# Currency can appear as ₹, Rs, or INR. Use \u20B9 escape for portability (keeps source ASCII).
AMOUNT_PATTERN = re.compile("(?i)\\b(?:\u20B9|rs\\.?|inr)\\s*[\\d,]+(?:\\.\\d{1,2})?\\b")

BTC_PATTERN = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,42}\b")
ETH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

SUSPICIOUS_TLDS = {
    "xyz",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "work",
    "click",
    "site",
    "online",
    "info",
    "link",
}


def _normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    if digits.startswith("91") and len(digits) == 12:
        return "+" + digits
    if len(digits) == 10:
        return "+91" + digits
    if digits:
        return "+" + digits
    return raw


def _url_to_domain(url: str) -> Optional[str]:
    normalized = url
    if normalized.lower().startswith("www."):
        normalized = "http://" + normalized
    try:
        parsed = urlparse(normalized)
        host = parsed.netloc or ""
        host = host.split("@")[-1]
        host = host.split(":")[0]
        return host.lower() or None
    except Exception:
        return None


def extract_intelligence(texts: Iterable[str], intel: Intelligence) -> None:
    combined = " ".join([t for t in texts if t])

    for match in URL_PATTERN.findall(combined):
        cleaned = match.rstrip("),.;")
        intel.phishing_links.add(cleaned)
        domain = _url_to_domain(cleaned)
        if domain:
            intel.domains.add(domain)

    for match in EMAIL_PATTERN.findall(combined):
        intel.emails.add(match.lower())

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
        # Filter repeated/sequential noise quickly.
        if match == match[0] * len(match):
            continue
        intel.bank_accounts.add(match)

    for match in IFSC_PATTERN.findall(combined):
        intel.ifsc_codes.add(match)

    for match in REFERENCE_ID_PATTERN.findall(combined):
        if match and len(match) >= 6:
            intel.reference_ids.add(match.upper())

    for match in AMOUNT_PATTERN.findall(combined):
        intel.amounts.add(match.replace(" ", ""))

    for match in BTC_PATTERN.findall(combined):
        intel.crypto_wallets.add(match)

    for match in ETH_PATTERN.findall(combined):
        intel.crypto_wallets.add(match)

    lowered = combined.lower()
    for tld in SUSPICIOUS_TLDS:
        if f".{tld}" in lowered:
            intel.suspicious_keywords.add(f"tld:{tld}")
