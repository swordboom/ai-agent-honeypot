"""
Automated investigation (SOC pillar: automated investigation).

Correlation says "these sessions are one incident." Prioritisation says "it scores
57, HIGH." Neither does the investigation an analyst would do next: pivot on each
indicator, enrich it, pull the behaviour of the entities involved, lay the events
out on a timeline, decide whether this is a true positive, and write down what to
look at next. That is what this module automates.

`investigate_incident` takes a declared incident plus the sessions behind it and
returns an `Investigation`: an enrichment per indicator, the UEBA profiles for the
entities involved, an ordered timeline, a verdict with a confidence, a written
narrative, and concrete next investigative steps (distinct from the *response*
actions the incident engine already produces - investigation is "find out",
response is "act").

Pure and offline: it composes threat_intel + behavioral_analytics + the incident,
adds no I/O, and is safe to recompute on every read like everything else here.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from services.behavioral_analytics import EntityProfile, analyze_entities, entities_for_sessions
from services.threat_intel import Enrichment, enrich_indicator_string

# Investigation verdicts - the analyst-facing conclusion.
VERDICT_TRUE_POSITIVE = "TRUE_POSITIVE"
VERDICT_LIKELY = "LIKELY_THREAT"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
VERDICT_BENIGN = "LIKELY_BENIGN"


@dataclass
class TimelineEntry:
    timestamp: float
    source: str
    session_id: str
    summary: str

    def to_payload(self) -> Dict[str, object]:
        return {
            "timestamp": int(self.timestamp),
            "source": self.source,
            "sessionId": self.session_id,
            "summary": self.summary,
        }


@dataclass
class Investigation:
    incident_id: str
    verdict: str
    confidence: float  # 0-1
    narrative: str
    enrichments: List[Enrichment] = field(default_factory=list)
    entity_profiles: List[EntityProfile] = field(default_factory=list)
    timeline: List[TimelineEntry] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    malicious_indicator_count: int = 0
    feed_hit_count: int = 0

    def to_payload(self) -> Dict[str, object]:
        return {
            "incidentId": self.incident_id,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 2),
            "narrative": self.narrative,
            "enrichments": [e.to_payload() for e in self.enrichments],
            "entityProfiles": [p.to_payload() for p in self.entity_profiles],
            "timeline": [t.to_payload() for t in self.timeline],
            "nextSteps": self.next_steps,
            "maliciousIndicatorCount": self.malicious_indicator_count,
            "feedHitCount": self.feed_hit_count,
        }


def _timeline_for(sessions: Sequence, session_ids: Sequence[str]) -> List[TimelineEntry]:
    wanted = set(session_ids)
    entries: List[TimelineEntry] = []
    for state in sessions:
        if state.session_id not in wanted:
            continue
        source = "Technical" if getattr(state, "source_type", "honeypot") == "technical" else "Honeypot"
        ts = state.first_scam_timestamp or state.created_at
        if source == "Technical":
            summary = (
                f"{state.event_type or 'technical event'} from {state.source_identifier or 'unknown source'}"
                f" ({state.event_count} observations, {state.affected_targets} targets)"
            )
        else:
            captured = state.intel.actionable_category_count()
            summary = (
                f"{state.scam_category} engagement in {state.language_name}"
                f" - {state.scammer_messages} scammer msgs, {captured} actionable indicator kind(s)"
            )
        entries.append(TimelineEntry(timestamp=ts, source=source, session_id=state.session_id, summary=summary))
    entries.sort(key=lambda e: e.timestamp)
    return entries


def _verdict_and_confidence(
    incident,
    enrichments: Sequence[Enrichment],
    profiles: Sequence[EntityProfile],
    cross_source: bool,
) -> tuple:
    """Combine the independent lines of evidence into one defensible verdict."""
    feed_hits = sum(1 for e in enrichments if e.feed_matches)
    malicious = sum(1 for e in enrichments if e.verdict == "MALICIOUS")
    max_entity_anomaly = max((p.anomaly_score for p in profiles), default=0)
    detection_conf = float(getattr(incident, "max_confidence", 0.0) or 0.0)

    # Weighted evidence, each capped, summing toward 1.0.
    evidence = 0.0
    evidence += min(0.35, 0.35 * detection_conf)                       # content detection
    evidence += min(0.25, 0.125 * feed_hits)                           # feed corroboration
    evidence += min(0.20, 0.20 * (max_entity_anomaly / 100.0))         # entity behaviour
    evidence += 0.20 if cross_source else 0.0                          # independent-source agreement
    if malicious and not feed_hits:
        evidence += min(0.10, 0.05 * malicious)                        # enrichment-only malice
    confidence = round(min(1.0, evidence), 2)

    if (feed_hits and cross_source) or confidence >= 0.8:
        verdict = VERDICT_TRUE_POSITIVE
    elif confidence >= 0.55:
        verdict = VERDICT_LIKELY
    elif confidence >= 0.3:
        verdict = VERDICT_INCONCLUSIVE
    else:
        verdict = VERDICT_BENIGN
    return verdict, confidence, feed_hits, malicious


def _narrative(incident, enrichments, profiles, timeline, verdict, cross_source) -> str:
    parts: List[str] = []
    parts.append(
        f"{incident.severity} incident '{incident.name}' correlates "
        f"{incident.session_count} session(s) on {len(incident.shared_indicators)} shared indicator(s)."
    )
    if cross_source:
        parts.append(
            "The same indicator was observed independently by the honeypot and the technical "
            "feed, which is strong corroboration that this is a real, coordinated campaign."
        )
    bad = [e for e in enrichments if e.verdict in ("MALICIOUS", "SUSPICIOUS")]
    if bad:
        head = ", ".join(f"{e.value} ({e.verdict.lower()})" for e in bad[:3])
        parts.append(f"Enrichment flags {len(bad)} indicator(s): {head}.")
    hot = [p for p in profiles if p.risk_band in ("CRITICAL", "HIGH")]
    if hot:
        parts.append(
            f"Behavioural analytics rates {len(hot)} entity(ies) high-risk, led by "
            f"{hot[0].kind}:{hot[0].value} (anomaly {hot[0].anomaly_score})."
        )
    if timeline:
        span = int(timeline[-1].timestamp - timeline[0].timestamp)
        parts.append(f"Activity spans {span}s across {len(timeline)} observation(s).")
    parts.append(f"Automated verdict: {verdict.replace('_', ' ').title()}.")
    return " ".join(parts)


def _next_steps(incident, enrichments, profiles, cross_source) -> List[str]:
    steps: List[str] = []
    for e in enrichments:
        if e.kind == "domain" and e.verdict in ("MALICIOUS", "SUSPICIOUS"):
            steps.append(f"Pull passive-DNS and WHOIS for {e.value} and pivot to co-hosted domains.")
        if e.kind == "ip" and e.attributes.get("classification") == "public":
            steps.append(f"Query the SIEM for all authentication activity from {e.value} in the last 24h.")
        if e.kind == "upi":
            steps.append(f"Request the transaction ledger for {e.value} from the PSP to map victim inflows.")
    for p in profiles:
        if p.fan_out >= 5:
            steps.append(f"Review the {p.fan_out} accounts touched by {p.value} for successful logins.")
        if any("successful authentication" in s.lower() for s in p.signals):
            steps.append(f"Force credential reset on accounts linked to {p.value}.")
    if cross_source:
        steps.append("Merge the honeypot transcript and the auth logs into one case file for the analyst.")
    if not steps:
        steps.append("Keep the engagement running to capture a freezable identifier before closing.")
    # De-duplicate while preserving order.
    seen = set()
    unique = []
    for s in steps:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique[:8]


def investigate_incident(
    incident,
    sessions: Sequence,
    profiles: Optional[Sequence[EntityProfile]] = None,
) -> Investigation:
    """Run the automated investigation for one declared incident."""
    if profiles is None:
        profiles = analyze_entities(sessions)

    enrichments = [enrich_indicator_string(i) for i in incident.shared_indicators]
    incident_profiles = entities_for_sessions(profiles, incident.session_ids)
    incident_profiles = sorted(incident_profiles, key=lambda p: -p.anomaly_score)
    timeline = _timeline_for(sessions, incident.session_ids)
    cross_source = getattr(incident, "source_type", "Honeypot") == "Mixed"

    verdict, confidence, feed_hits, malicious = _verdict_and_confidence(
        incident, enrichments, incident_profiles, cross_source
    )
    narrative = _narrative(incident, enrichments, incident_profiles, timeline, verdict, cross_source)
    next_steps = _next_steps(incident, enrichments, incident_profiles, cross_source)

    return Investigation(
        incident_id=incident.incident_id,
        verdict=verdict,
        confidence=confidence,
        narrative=narrative,
        enrichments=enrichments,
        entity_profiles=incident_profiles,
        timeline=timeline,
        next_steps=next_steps,
        malicious_indicator_count=malicious,
        feed_hit_count=feed_hits,
    )


def _self_check() -> None:
    from models.session import SessionState, TranscriptMessage
    from services.incident_engine import declare_incidents

    def chat(sid, upi, domain=None, offset=0):
        s = SessionState(session_id=sid, persona_id="p", persona_label="P")
        s.scam_detected = True
        s.scam_category = "UPI_FRAUD"
        s.scam_confidence = 0.9
        s.first_scam_timestamp = 1000.0 + offset
        s.updated_at = 1000.0 + offset + 30
        s.intel.upi_ids.add(upi)
        if domain:
            s.intel.phishing_links.add(domain)
        s.transcript.append(TranscriptMessage(sender="scammer", text="pay now", timestamp=1))
        return s

    def tech(sid, ip, users, count, domain=None, offset=0):
        s = SessionState(
            session_id=sid, persona_id="technical-feed", persona_label=ip,
            source_type="technical", event_count=count, affected_targets=len(users),
        )
        s.scam_detected = True
        s.scam_category = "CREDENTIAL_STUFFING"
        s.scam_confidence = 0.9
        s.first_scam_timestamp = 1000.0 + offset
        s.finalized_timestamp = 1000.0 + offset + 30
        s.updated_at = 1000.0 + offset + 30
        s.intel.ip_addresses.add(ip)
        for u in users:
            s.intel.usernames.add(u)
        if domain:
            s.intel.domains.add(domain)
        return s

    # Cross-source incident: chat + auth burst share a known-bad domain.
    c = chat("c1", "mule@ybl", domain="http://sbi-verify.tk/login")
    t = tech("t1", "203.0.113.9", [f"user{i}" for i in range(6)], count=40, domain="sbi-verify.tk")
    sessions = [c, t]
    incident = declare_incidents(sessions, now=1200.0)[0]
    inv = investigate_incident(incident, sessions)

    assert inv.incident_id == incident.incident_id
    assert inv.feed_hit_count >= 1, inv  # sbi-verify.tk is in the feed
    assert inv.verdict == VERDICT_TRUE_POSITIVE, inv  # feed hit + cross source
    assert inv.confidence >= 0.55, inv
    assert inv.timeline and inv.timeline[0].timestamp <= inv.timeline[-1].timestamp
    assert any("sbi-verify.tk" in e.value for e in inv.enrichments), inv
    assert inv.next_steps, inv
    payload = inv.to_payload()
    assert payload["verdict"] == VERDICT_TRUE_POSITIVE
    assert isinstance(payload["enrichments"], list) and payload["enrichments"]

    # A lone, low-confidence session should not read as a confirmed true positive.
    weak = SessionState(session_id="w1", persona_id="p", persona_label="P")
    weak.scam_detected = True
    weak.scam_category = "GENERIC_SCAM"
    weak.scam_confidence = 0.3
    weak.first_scam_timestamp = 1000.0
    weak.updated_at = 1030.0
    weak.intel.phone_numbers.add("+919812345678")
    weak_inc = declare_incidents([weak], now=1200.0)[0]
    weak_inv = investigate_incident(weak_inc, [weak])
    assert weak_inv.verdict in (VERDICT_INCONCLUSIVE, VERDICT_BENIGN, VERDICT_LIKELY), weak_inv
    assert weak_inv.confidence < inv.confidence, (weak_inv.confidence, inv.confidence)

    print("investigation self-check ok")


if __name__ == "__main__":
    _self_check()
