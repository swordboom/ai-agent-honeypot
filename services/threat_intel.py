"""
Offline threat-intelligence enrichment (SOC pillar: automated investigation).

A SOC does not just say "this domain is suspicious" - it *enriches* the indicator:
what is the TLD reputation, is it a look-alike of a known brand, is the IP a bogon,
does it match a known-bad feed. That enrichment is what turns a raw indicator into
something an analyst can act on and a verdict a machine can defend.

Everything here is deterministic and **offline** - no DNS, no HTTP, no external feed
call. The "feed" is a small curated bundle of known-abused infrastructure shipped in
this module, so the whole SOC works on a box with no outbound internet (the same
constraint the dashboard charts honour). Swap `_KNOWN_BAD_*` for a real feed pull
behind the same `enrich_indicator` signature when a network is available.
"""

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# Verdict bands for a single enriched indicator.
VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_UNKNOWN = "UNKNOWN"
VERDICT_BENIGN = "BENIGN"

# ---------------------------------------------------------------------------
# Bundled offline "threat feed". These stand in for a MISP/STIX pull; the point
# is that enrichment can corroborate an indicator against prior knowledge with no
# network. Keep entries lowercase.
# ---------------------------------------------------------------------------

# TLDs repeatedly abused for free throwaway phishing hosts.
_ABUSED_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click", "link", "rest"}

# Known-bad domains/hosts (curated sample of the kind a feed would carry).
_KNOWN_BAD_DOMAINS = {
    "sbi-verify.tk", "kyc-update.xyz", "hdfc-secure.ml", "paytm-kyc.tk",
    "icici-verify.top", "npci-refund.xyz", "axis-secure.cf",
}

# Reserved / bogon IPv4 prefixes (CIDR, first-octet or two-octet match). An
# attack "sourced" from one of these is spoofed or internal - itself a signal.
_BOGON_PREFIXES = (
    ("0.", "this-network"),
    ("10.", "rfc1918-private"),
    ("127.", "loopback"),
    ("169.254.", "link-local"),
    ("192.168.", "rfc1918-private"),
    ("255.", "broadcast"),
)
_BOGON_16 = {
    **{f"172.{b}.": "rfc1918-private" for b in range(16, 32)},
    **{f"100.{b}.": "cgnat" for b in range(64, 128)},
}

# Indian financial brands used as bait. Look-alike domains impersonate these.
_BRANDS = (
    "sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "gpay",
    "npci", "rbi", "sbicard", "pnb", "bob", "canara", "yesbank", "idfc",
)

# Legitimate registrable domains for those brands. A label that *contains* a brand
# but is not one of these is a look-alike.
_BRAND_LEGIT_DOMAINS = {
    "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "paytm.com", "phonepe.com", "pay.google.com", "npci.org.in",
    "rbi.org.in", "pnbindia.in", "bankofbaroda.in", "canarabank.com",
    "yesbank.in", "idfcfirstbank.com",
}

# Free/disposable email providers - fine on their own, but a "bank" mailing from
# one is display-name spoofing.
_FREEMAIL_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "rediffmail.com"}
_DISPOSABLE_EMAIL_DOMAINS = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com"}

# UPI handle suffixes that are legitimate PSPs; the local-part is what to read.
_UPI_SUSPICIOUS_LOCALPART = re.compile(
    r"(refund|kyc|verify|support|help|update|secure|prize|reward|lottery|gift|claim|blockchain)",
    re.IGNORECASE,
)

_DOMAIN_RE = re.compile(r"(?i)^(?:https?://)?(?:www\.)?([a-z0-9.\-]+)")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass
class Enrichment:
    """The enriched view of one indicator."""

    kind: str
    value: str
    verdict: str
    score: int  # 0-100 reputation risk (higher = worse)
    reasons: List[str] = field(default_factory=list)
    feed_matches: List[str] = field(default_factory=list)
    attributes: Dict[str, object] = field(default_factory=dict)

    def to_payload(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "value": self.value,
            "verdict": self.verdict,
            "score": self.score,
            "reasons": self.reasons,
            "feedMatches": self.feed_matches,
            "attributes": self.attributes,
        }


def _verdict_from_score(score: int, feed_hit: bool) -> str:
    if feed_hit or score >= 70:
        return VERDICT_MALICIOUS
    if score >= 40:
        return VERDICT_SUSPICIOUS
    if score >= 15:
        return VERDICT_UNKNOWN
    return VERDICT_BENIGN


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 2)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _registrable(host: str) -> str:
    match = _DOMAIN_RE.match(host.strip())
    return (match.group(1) if match else host.strip()).lower().rstrip(".")


def _brand_lookalike(host: str) -> Tuple[bool, str]:
    """A domain impersonates a brand if a label contains/resembles the brand name
    but the registrable domain is not the brand's real one."""
    if host in _BRAND_LEGIT_DOMAINS:
        return False, ""
    labels = host.split(".")
    for brand in _BRANDS:
        for label in labels:
            if not label:
                continue
            if brand in label or _levenshtein(label, brand) <= 1:
                # It mentions the brand but is not the legitimate domain.
                return True, brand
    return False, ""


def _enrich_domain(value: str) -> Enrichment:
    host = _registrable(value)
    reasons: List[str] = []
    feed: List[str] = []
    score = 0

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    labels = host.split(".")
    core = labels[0] if labels else host
    entropy = _shannon_entropy(core)
    hyphens = host.count("-")
    digits = sum(ch.isdigit() for ch in host)
    depth = max(0, len(labels) - 2)

    if host in _KNOWN_BAD_DOMAINS:
        score += 70
        feed.append("known-bad-domain")
        reasons.append("Listed in the known-bad phishing feed.")

    if tld in _ABUSED_TLDS:
        score += 25
        reasons.append(f"Abused free/cheap TLD .{tld}.")

    looks_like, brand = _brand_lookalike(host)
    if looks_like:
        score += 30
        reasons.append(f"Look-alike of brand '{brand}' but not its official domain.")

    if _IPV4_RE.match(host):
        score += 20
        reasons.append("Bare IP used as a host - legitimate brands use names.")
    if hyphens >= 2:
        score += 10
        reasons.append(f"{hyphens} hyphens - common in generated phishing hosts.")
    if digits >= 3:
        score += 8
        reasons.append(f"{digits} digits in the host.")
    if depth >= 3:
        score += 8
        reasons.append(f"Deep subdomain nesting ({depth} levels).")
    if len(host) >= 30:
        score += 6
        reasons.append("Unusually long host name.")
    if entropy >= 3.5:
        score += 8
        reasons.append(f"High-entropy label (entropy {entropy}) - looks auto-generated.")

    score = min(100, score)
    return Enrichment(
        kind="domain",
        value=host,
        verdict=_verdict_from_score(score, bool(feed)),
        score=score,
        reasons=reasons or ["No adverse signals in the offline feed."],
        feed_matches=feed,
        attributes={
            "tld": tld,
            "entropy": entropy,
            "hyphens": hyphens,
            "digits": digits,
            "subdomainDepth": depth,
            "brandImpersonated": brand or None,
        },
    )


def _enrich_ip(value: str) -> Enrichment:
    ip = value.strip()
    reasons: List[str] = []
    feed: List[str] = []
    score = 0
    classification = "public"

    for prefix, label in _BOGON_16.items():
        if ip.startswith(prefix):
            classification = label
            break
    else:
        for prefix, label in _BOGON_PREFIXES:
            if ip.startswith(prefix):
                classification = label
                break

    if classification != "public":
        score += 45
        feed.append("bogon")
        reasons.append(f"Non-routable source ({classification}) - spoofed or internal origin.")
    else:
        reasons.append("Public routable address.")

    # An octet out of range is a malformed/forged indicator.
    if _IPV4_RE.match(ip):
        if any(int(o) > 255 for o in ip.split(".")):
            score += 20
            reasons.append("Malformed IP (octet > 255).")
    else:
        score += 10
        reasons.append("Not a well-formed IPv4 address.")

    score = min(100, score)
    return Enrichment(
        kind="ip",
        value=ip,
        verdict=_verdict_from_score(score, bool(feed)),
        score=score,
        reasons=reasons,
        feed_matches=feed,
        attributes={"classification": classification},
    )


def _enrich_email(value: str) -> Enrichment:
    email = value.strip().lower()
    reasons: List[str] = []
    feed: List[str] = []
    score = 0
    domain = email.split("@", 1)[1] if "@" in email else ""

    if domain in _DISPOSABLE_EMAIL_DOMAINS:
        score += 55
        feed.append("disposable-email")
        reasons.append(f"Disposable/throwaway mail provider ({domain}).")
    elif domain in _FREEMAIL_DOMAINS:
        score += 20
        reasons.append(f"Free consumer mailbox ({domain}) - a bank would not send from it.")

    looks_like, brand = _brand_lookalike(domain) if domain else (False, "")
    if looks_like:
        score += 30
        reasons.append(f"Sender domain impersonates brand '{brand}'.")

    local = email.split("@", 1)[0] if "@" in email else email
    if _UPI_SUSPICIOUS_LOCALPART.search(local):
        score += 10
        reasons.append("Alarming local-part (verify/kyc/refund style).")

    score = min(100, score)
    return Enrichment(
        kind="email",
        value=email,
        verdict=_verdict_from_score(score, bool(feed)),
        score=score,
        reasons=reasons or ["No adverse signals."],
        feed_matches=feed,
        attributes={"domain": domain, "brandImpersonated": brand or None},
    )


def _enrich_upi(value: str) -> Enrichment:
    handle = value.strip().lower()
    reasons: List[str] = []
    score = 0
    local = handle.split("@", 1)[0] if "@" in handle else handle
    psp = handle.split("@", 1)[1] if "@" in handle else ""

    if _UPI_SUSPICIOUS_LOCALPART.search(local):
        score += 35
        reasons.append("Handle name is a lure keyword (refund/kyc/prize/verify).")
    if any(ch.isdigit() for ch in local) and len(re.sub(r"\D", "", local)) >= 6:
        score += 10
        reasons.append("Long numeric run in the handle - disposable collection account.")
    # Every captured collection handle in a scam is actionable by definition.
    score += 20
    reasons.append("Captured as a scam collection handle - freezable at the PSP.")

    score = min(100, score)
    return Enrichment(
        kind="upi",
        value=handle,
        verdict=_verdict_from_score(score, False),
        score=score,
        reasons=reasons,
        feed_matches=[],
        attributes={"psp": psp},
    )


def _enrich_generic(kind: str, value: str) -> Enrichment:
    """phone / account / wallet / user / hash / endpoint: captured as attacker-
    controlled, so they carry a baseline actionable score but no feed lookup."""
    return Enrichment(
        kind=kind,
        value=value.strip(),
        verdict=VERDICT_SUSPICIOUS,
        score=30,
        reasons=["Captured attacker-controlled identifier."],
        feed_matches=[],
        attributes={},
    )


_ENRICHERS = {
    "domain": _enrich_domain,
    "ip": _enrich_ip,
    "email": _enrich_email,
    "upi": _enrich_upi,
}


def enrich_indicator(kind: str, value: str) -> Enrichment:
    """Enrich one indicator. `kind` is the union-find prefix used across the app
    (upi, phone, account, wallet, domain, ip, email, user, hash, endpoint)."""
    kind = (kind or "").lower()
    value = (value or "").strip()
    if not value:
        return Enrichment(kind=kind, value=value, verdict=VERDICT_UNKNOWN, score=0, reasons=["Empty indicator."])
    enricher = _ENRICHERS.get(kind)
    if enricher:
        return enricher(value)
    return _enrich_generic(kind, value)


def enrich_indicator_string(indicator: str) -> Enrichment:
    """Enrich a `kind:value` indicator string as emitted by the incident engine."""
    kind, _, value = indicator.partition(":")
    return enrich_indicator(kind, value)


def _self_check() -> None:
    bad = enrich_indicator("domain", "sbi-verify.tk")
    assert bad.verdict == VERDICT_MALICIOUS, bad
    assert "known-bad-domain" in bad.feed_matches, bad

    look = enrich_indicator("domain", "hdfc-secure.example.com")
    assert look.attributes["brandImpersonated"] == "hdfc", look

    good = enrich_indicator("domain", "icicibank.com")
    assert good.verdict in (VERDICT_BENIGN, VERDICT_UNKNOWN), good
    assert good.attributes["brandImpersonated"] is None, good

    bogon = enrich_indicator("ip", "10.0.0.5")
    assert "bogon" in bogon.feed_matches and bogon.score >= 40, bogon
    public = enrich_indicator("ip", "203.0.113.9")
    assert public.attributes["classification"] == "public", public

    spoof = enrich_indicator("email", "alerts@mailinator.com")
    assert spoof.verdict == VERDICT_MALICIOUS, spoof

    upi = enrich_indicator("upi", "refund.dept@ybl")
    assert upi.score >= 40 and upi.attributes["psp"] == "ybl", upi

    s = enrich_indicator_string("domain:kyc-update.xyz")
    assert s.kind == "domain" and s.score > 0, s

    print("threat_intel self-check ok")


if __name__ == "__main__":
    _self_check()
