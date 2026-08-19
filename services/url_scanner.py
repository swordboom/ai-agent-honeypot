"""
Phishing URL infrastructure analyser.

Checks a URL for malicious signals entirely offline (no DNS / HTTP calls):
  - Free / abused TLD
  - Suspicious brand and service keywords in the domain
  - Lookalike impersonation of known Indian banks and govt services
  - IP address used as host
  - Excessive subdomain depth
  - Hyphen-heavy domain (common phishing pattern)
  - Non-standard port
  - Unusual URL length

When risk score >= 20 the result is ingested as a technical SessionState so
the domain enters the shared correlation engine automatically.
"""

import hashlib
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from models.session import SessionState
from services.session_manager import SessionManager

_ABUSED_TLDS = {
    ".tk", ".ml", ".cf", ".gq", ".ga", ".pw", ".top", ".xyz",
    ".club", ".work", ".party", ".loan", ".download", ".stream",
    ".link", ".click", ".live", ".site", ".online", ".tech",
    ".icu", ".buzz", ".fun", ".rest", ".vip", ".monster",
}

_SUSPICIOUS_KEYWORDS = [
    "kyc", "verify", "verification", "secure", "security", "login",
    "signin", "account", "update", "otp", "bank", "wallet", "payment",
    "pay", "fund", "sbi", "hdfc", "icici", "axis", "pnb", "kotak",
    "boi", "canara", "uidai", "aadhar", "aadhaar", "pan", "incometax",
    "refund", "reward", "prize", "lottery", "winner", "claim",
    "support", "helpdesk", "customer", "alert", "urgent",
    "suspended", "blocked", "restricted", "paytm", "phonepe",
    "rbi", "npci", "sebi", "irctc", "neft", "imps",
]

# brand keyword -> canonical domain, for lookalike detection
_BRAND_DOMAINS: Dict[str, str] = {
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "axis": "axisbank.com",
    "paytm": "paytm.com",
    "phonepe": "phonepe.com",
    "npci": "npci.org.in",
    "uidai": "uidai.gov.in",
    "incometax": "incometax.gov.in",
    "irctc": "irctc.co.in",
    "rbi": "rbi.org.in",
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _normalise(raw: str) -> str:
    url = raw.strip()
    if "://" not in url:
        url = "http://" + url
    return url


def _parse(url: str) -> Tuple[str, str, str]:
    """Return (host, tld, netloc)."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    parts = host.split(".")
    tld = ("." + parts[-1]) if len(parts) >= 2 else ""
    return host, tld, parsed.netloc


def _lookalike_hits(host: str) -> List[str]:
    return [
        f"impersonates {canonical}"
        for brand, canonical in _BRAND_DOMAINS.items()
        if brand in host and host != canonical
    ]


def analyse_url(raw_url: str) -> Dict:
    """Pure analysis — does NOT touch the session store."""
    raw_stripped = raw_url.strip()

    # Reject multi-line input — that's an email, not a URL
    if "\n" in raw_stripped:
        return {
            "url": raw_stripped[:60] + ("…" if len(raw_stripped) > 60 else ""),
            "domain": "",
            "tld": "",
            "riskScore": 0,
            "riskLevel": "INVALID",
            "category": "INVALID_INPUT",
            "isIpHost": False,
            "indicators": [
                "Input spans multiple lines — this looks like an email, not a URL. "
                "Use the Email Phishing Analyser panel instead."
            ],
            "suspiciousKeywords": [],
        }

    url = _normalise(raw_stripped)
    host, tld, netloc = _parse(url)
    indicators: List[str] = []
    score = 0

    is_ip = bool(_IP_RE.match(host))
    if is_ip:
        indicators.append("IP address used as host instead of a domain name")
        score += 35

    if tld in _ABUSED_TLDS:
        indicators.append(f"Free / commonly abused TLD: {tld}")
        score += 25

    kws = [kw for kw in _SUSPICIOUS_KEYWORDS if kw in host]
    for kw in kws[:4]:
        indicators.append(f"Suspicious keyword in domain: '{kw}'")
    score += min(30, len(kws) * 7)

    for hit in _lookalike_hits(host):
        indicators.append(hit)
        score += 30

    depth = max(0, len(host.split(".")) - 2)
    if depth >= 3:
        indicators.append(f"Excessive subdomain depth ({depth} levels)")
        score += 15
    elif depth == 2:
        indicators.append("Deep subdomain nesting")
        score += 7

    if ":" in netloc:
        port_part = netloc.split(":")[-1]
        if port_part not in ("80", "443", ""):
            indicators.append(f"Non-standard port: {port_part}")
            score += 15

    hyphens = host.count("-")
    if hyphens >= 3:
        indicators.append(f"Hyphen-heavy domain ({hyphens} hyphens — common in phishing kits)")
        score += 12
    elif hyphens == 2:
        score += 5

    if len(url) > 120:
        indicators.append("Unusually long URL")
        score += 5

    score = min(100, score)

    if score >= 70:
        risk_level, category = "CRITICAL", "PHISHING"
    elif score >= 45:
        risk_level, category = "HIGH", "PHISHING"
    elif score >= 20:
        risk_level, category = "MEDIUM", "SUSPICIOUS_URL"
    else:
        risk_level, category = "LOW", "BENIGN"

    return {
        "url": url,
        "domain": host,
        "tld": tld,
        "riskScore": score,
        "riskLevel": risk_level,
        "category": category,
        "isIpHost": is_ip,
        "indicators": indicators,
        "suspiciousKeywords": kws,
    }


def ingest_url_scan(raw_url: str, session_manager: SessionManager) -> Tuple[Dict, Optional[str]]:
    """
    Analyse a URL and, when risk >= 20, create a minimal SessionState so the
    domain enters the correlation engine. Returns (result, session_id or None).
    Repeated scans of the same domain update the same session (stable key).
    """
    result = analyse_url(raw_url)
    if result["riskScore"] < 20:
        return result, None

    sid = "url-" + hashlib.sha256(result["domain"].encode()).hexdigest()[:12]

    def factory(session_id: str) -> SessionState:
        return SessionState(
            session_id=session_id,
            persona_id="url-scanner",
            persona_label="URL Scanner",
            source_type="technical",
            event_type="URL_SCAN",
            source_identifier=result["domain"],
        )

    state = session_manager.get_or_create(sid, factory)
    session_manager.update_intel(state, lambda intel: intel.phishing_links.add(result["url"]))
    session_manager.update_detection(
        state,
        is_scam=True,
        confidence=round(result["riskScore"] / 100, 2),
        category=result["category"],
        triggers=result["indicators"][:4],
        suspicious_keywords=result["suspiciousKeywords"],
        rolling_score=float(result["riskScore"]),
        rule_score=float(result["riskScore"]),
        behavior_score=0.0,
        strategy_state="URL scan",
    )

    if not state.finalized:
        session_manager.finalize_technical(state, time.time())

    return result, sid
