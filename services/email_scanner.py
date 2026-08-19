"""
Email phishing header analyser.

Parses a raw email (RFC 2822 format — paste from "View Source" in any mail client)
and checks for phishing signals:
  - Display-name spoofing  (bank name in From, sending via gmail)
  - Reply-To domain mismatch
  - SPF / DKIM / DMARC failures read from the Authentication-Results header
  - Urgency language in subject and body
  - Suspicious URLs in the body (piped through the URL analyser)

When risk >= 20 the sender domain is registered in the correlation engine so
that a phishing email and a related honeypot conversation can collapse into one
incident if they share a domain.
"""

import hashlib
import re
import time
from email import message_from_string
from email.utils import parseaddr
from typing import Dict, List, Optional, Tuple

from models.session import SessionState
from services.session_manager import SessionManager
from services.url_scanner import analyse_url

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_URGENCY_RE = re.compile(
    r"\b(urgent|immediately|action required|verify now|suspended|blocked|"
    r"expires|deadline|24 hours|last chance|important notice|account limited|"
    r"security alert|login attempt|your account|otp|verify your)\b",
    re.IGNORECASE,
)

_BRAND_NAMES = [
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "uidai",
    "income tax", "npci", "rbi", "amazon", "google", "microsoft",
    "bank", "irctc",
]

_FREE_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "rediffmail.com", "ymail.com", "protonmail.com", "icloud.com",
}


def _get_domain(addr_field: str) -> str:
    _, addr = parseaddr(addr_field)
    addr = addr.strip("<>").lower()
    return addr.split("@", 1)[-1] if "@" in addr else ""


def _auth_results(headers: Dict) -> Dict[str, Optional[str]]:
    raw = (
        headers.get("Authentication-Results")
        or headers.get("authentication-results")
        or ""
    )
    low = raw.lower()

    def _pick(key: str) -> Optional[str]:
        for val in ("pass", "fail", "softfail", "neutral", "none"):
            if f"{key}={val}" in low:
                return val
        return None

    return {"spf": _pick("spf"), "dkim": _pick("dkim"), "dmarc": _pick("dmarc")}


def _extract_body(msg) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    parts.append(
                        part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    )
                except Exception:
                    pass
        return " ".join(parts)
    try:
        payload = msg.get_payload(decode=True)
        return (
            payload.decode("utf-8", errors="ignore")
            if payload
            else str(msg.get_payload() or "")
        )
    except Exception:
        return str(msg.get_payload() or "")


_HEADER_PREFIXES = (
    "from:", "to:", "cc:", "subject:", "date:", "message-id:", "received:",
    "mime-version:", "content-type:", "authentication-results:", "reply-to:",
    "return-path:", "dkim-signature:", "x-mailer:", "x-spam-",
)

_FORWARD_MARKERS = (
    "forwarded message", "begin forwarded", "original message",
    "-----original", "--------", "________________________________",
)


def _looks_like_email(raw: str) -> bool:
    """
    Return True if the text contains recognisable RFC 2822 headers.
    Handles Gmail-forwarded emails (dashes + inline From/Subject block)
    and Outlook 'Show Source' style by scanning the whole text when a
    forwarding marker is detected in the first five lines.
    """
    lines = raw.strip().splitlines()
    # If a forwarding decorator is present, the real headers may appear
    # anywhere in the text — search all lines.
    first_five = " ".join(lines[:5]).lower()
    search_range = lines if any(m in first_five for m in _FORWARD_MARKERS) else lines[:30]
    return any(line.lower().startswith(_HEADER_PREFIXES) for line in search_range)


def _strip_forward_preamble(raw: str) -> str:
    """
    Remove forwarding decorators so that message_from_string sees clean
    RFC 2822 headers as the very first line.

    Gmail 'forwarded message' block looks like:
        ---------- Forwarded message ---------
        From: SBI Bank <noreply@sbi.co.in>
        ...
    Outlook inline-forward starts with:
        -----Original Message-----
        From: ...
    """
    lines = raw.splitlines()
    for i, line in enumerate(lines):
        if line.strip().lower().startswith(_HEADER_PREFIXES):
            return "\n".join(lines[i:])
    return raw


def analyse_email(raw_email: str) -> Dict:
    """Pure analysis — does NOT touch the session store."""
    raw_stripped = raw_email.strip()

    # Reject plain URLs pasted into the email box
    if raw_stripped.startswith(("http://", "https://", "www.", "ftp://")):
        return {
            "riskScore": 0,
            "riskLevel": "INVALID",
            "category": "INVALID_INPUT",
            "indicators": [
                "This looks like a URL, not an email. "
                "Use the URL / Domain Scanner panel instead."
            ],
            "extractedUrls": [],
            "suspiciousUrls": [],
        }

    # Reject anything without recognisable email headers
    if not _looks_like_email(raw_stripped):
        return {
            "riskScore": 0,
            "riskLevel": "INVALID",
            "category": "INVALID_INPUT",
            "indicators": [
                "No email headers found. Paste the raw email source, not just the body.",
                "Gmail: open the email → ⋮ (three dots) → 'Show original' → Copy all.",
                "Outlook: open email → File → Properties → copy the 'Internet headers' box.",
                "Forwarded emails also work — paste the full forwarded block including From/Subject lines.",
            ],
            "extractedUrls": [],
            "suspiciousUrls": [],
        }

    try:
        msg = message_from_string(_strip_forward_preamble(raw_email))
    except Exception:
        return {
            "riskScore": 0,
            "riskLevel": "LOW",
            "category": "PARSE_ERROR",
            "indicators": ["Could not parse the email — check the raw format"],
            "extractedUrls": [],
            "suspiciousUrls": [],
        }

    headers = dict(msg.items())
    indicators: List[str] = []
    score = 0

    from_raw = headers.get("From") or headers.get("from") or ""
    display_name, _ = parseaddr(from_raw)
    from_domain = _get_domain(from_raw)

    reply_to_raw = headers.get("Reply-To") or headers.get("reply-to") or ""
    reply_domain = _get_domain(reply_to_raw) if reply_to_raw else ""

    subject = headers.get("Subject") or headers.get("subject") or ""

    # Display-name spoofing
    display_name_mismatch = False
    if display_name and from_domain:
        brand_in_name = any(b in display_name.lower() for b in _BRAND_NAMES)
        if brand_in_name and from_domain in _FREE_DOMAINS:
            indicators.append(
                f"Display-name spoofing: '{display_name}' sent from {from_domain}"
            )
            display_name_mismatch = True
            score += 40

    # Reply-To mismatch
    reply_to_mismatch = False
    if reply_domain and from_domain and reply_domain != from_domain:
        indicators.append(
            f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})"
        )
        reply_to_mismatch = True
        score += 25

    # Auth header failures
    auth = _auth_results(headers)
    if auth["spf"] in ("fail", "softfail"):
        indicators.append(f"SPF {auth['spf']} — sender not authorised by domain")
        score += 30
    if auth["dkim"] == "fail":
        indicators.append("DKIM signature failed — message may be tampered")
        score += 30
    if auth["dmarc"] == "fail":
        indicators.append("DMARC policy failed")
        score += 20

    # Urgency in subject
    if _URGENCY_RE.search(subject):
        indicators.append(f"Urgency language in subject: \"{subject[:80]}\"")
        score += 15

    # Body: extract and score URLs
    body = _extract_body(msg)
    extracted_urls = _URL_RE.findall(body)[:10]
    suspicious_urls: List[str] = []

    for url in extracted_urls:
        url_result = analyse_url(url)
        if url_result["riskScore"] >= 20:
            suspicious_urls.append(url)
            indicators.append(
                f"Suspicious URL in body: {url_result['domain']} "
                f"(score {url_result['riskScore']} — {', '.join(url_result['indicators'][:2])})"
            )
            score += min(20, url_result["riskScore"] // 4)

    # Urgency in body (only if not already flagged via subject)
    body_urgency = _URGENCY_RE.findall(body)
    if body_urgency and not _URGENCY_RE.search(subject):
        indicators.append(
            f"Urgency language in body: {', '.join(set(m.lower() for m in body_urgency[:3]))}"
        )
        score += 10

    score = min(100, score)

    if score >= 70:
        risk_level, category = "CRITICAL", "PHISHING_EMAIL"
    elif score >= 45:
        risk_level, category = "HIGH", "PHISHING_EMAIL"
    elif score >= 20:
        risk_level, category = "MEDIUM", "SUSPICIOUS_EMAIL"
    else:
        risk_level, category = "LOW", "BENIGN"

    return {
        "riskScore": score,
        "riskLevel": risk_level,
        "category": category,
        "fromDomain": from_domain,
        "displayName": display_name,
        "displayNameMismatch": display_name_mismatch,
        "replyToDomain": reply_domain,
        "replyToMismatch": reply_to_mismatch,
        "subject": subject,
        "spfResult": auth["spf"],
        "dkimResult": auth["dkim"],
        "dmarcResult": auth["dmarc"],
        "extractedUrls": extracted_urls,
        "suspiciousUrls": suspicious_urls,
        "indicators": indicators,
    }


def ingest_email_scan(
    raw_email: str, session_manager: SessionManager
) -> Tuple[Dict, Optional[str]]:
    """
    Analyse an email and, when risk >= 20, register the sender domain in the
    correlation engine. Returns (result, session_id or None).
    """
    result = analyse_email(raw_email)
    if result["riskScore"] < 20:
        return result, None

    domain_key = result.get("fromDomain") or "unknown"
    sid = "email-" + hashlib.sha256(domain_key.encode()).hexdigest()[:12]

    def factory(session_id: str) -> SessionState:
        return SessionState(
            session_id=session_id,
            persona_id="email-scanner",
            persona_label="Email Scanner",
            source_type="technical",
            event_type="EMAIL_SCAN",
            source_identifier=domain_key,
        )

    state = session_manager.get_or_create(sid, factory)

    def _update_intel(intel) -> None:
        if domain_key and domain_key != "unknown":
            intel.domains.add(domain_key)
        for url in result.get("suspiciousUrls", []):
            intel.phishing_links.add(url)
        if result.get("fromDomain"):
            intel.emails.add(f"scanner@{result['fromDomain']}")

    session_manager.update_intel(state, _update_intel)
    session_manager.update_detection(
        state,
        is_scam=True,
        confidence=round(result["riskScore"] / 100, 2),
        category=result["category"],
        triggers=result["indicators"][:4],
        suspicious_keywords=[],
        rolling_score=float(result["riskScore"]),
        rule_score=float(result["riskScore"]),
        behavior_score=0.0,
        strategy_state="Email scan",
    )

    if not state.finalized:
        session_manager.finalize_technical(state, time.time())

    return result, sid
