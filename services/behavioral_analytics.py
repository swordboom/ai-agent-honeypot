"""
Behavioural analytics / UEBA (SOC pillar: behavioural analytics).

Detection scores a *message*. Correlation scores an *incident*. Neither answers the
question a SOC analyst actually asks about infrastructure: "is this **entity** -
this IP, this account, this UPI handle - behaving abnormally across everything we've
seen?" That is entity behaviour analytics, and it is a different axis from content
scam-detection.

This module builds a profile per entity (keyed by the union-find indicator string)
by rolling up its behaviour across all sessions, then scores anomaly from signals a
UEBA engine would weigh:

  fan-out      one source touching many targets      -> spray / credential stuffing
  fan-in       one target hit from many sources      -> distributed attack on an account
  velocity     events per minute above a baseline    -> automation, not a human
  cross-source the same entity in honeypot AND feed  -> a real campaign, corroborated
  breadth      how many distinct sessions it links   -> hub of a campaign
  failure      auth failures with an eventual success -> a successful break-in
  novelty      first observation inside the window    -> never-before-seen infra

It is deterministic and offline: the "baseline" is a fixed threshold, not a learned
model, for the same reason the incident score uses fixed weights - a learned baseline
only earns its keep once there is labelled operational history to train on.
"""

import re
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

# An entity above this anomaly score is put in front of an analyst.
RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"

# Kinds worth profiling as behavioural entities (financial + technical infra).
_PROFILED_KINDS = ("ip", "user", "upi", "account", "domain", "phone", "email", "wallet")

# events/min above which activity looks automated rather than human.
_VELOCITY_BASELINE_EPM = 5.0

_DOMAIN_RE = re.compile(r"(?i)^(?:https?://)?(?:www\.)?([a-z0-9.\-]+)")


def _link_domain(link: str) -> str:
    match = _DOMAIN_RE.match(link.strip())
    return match.group(1).lower() if match else link.strip().lower()


def _session_entities(state) -> List[str]:
    """The behavioural entities a session touches, as `kind:value` strings.

    Mirrors incident_engine._session_indicators but is intentionally its own copy:
    this layer profiles entities, the incident engine correlates sessions, and the
    two should be free to diverge (e.g. profile phones, never correlate on them)."""
    intel = state.intel
    out: List[str] = []
    out.extend(f"upi:{v.lower()}" for v in intel.upi_ids)
    out.extend(f"account:{v}" for v in intel.bank_accounts)
    out.extend(f"wallet:{v.lower()}" for v in intel.crypto_wallets)
    out.extend(f"domain:{_link_domain(v)}" for v in intel.phishing_links if v)
    out.extend(f"domain:{_link_domain(v)}" for v in intel.domains if v)
    out.extend(f"email:{v.lower()}" for v in intel.emails)
    out.extend(f"phone:{re.sub(r'[^0-9]', '', v)[-10:]}" for v in intel.phone_numbers if v)
    out.extend(f"ip:{v.lower()}" for v in intel.ip_addresses)
    out.extend(f"user:{v.lower()}" for v in intel.usernames)
    return [e for e in out if len(e.split(":", 1)[1]) >= 4 and e.split(":", 1)[0] in _PROFILED_KINDS]


@dataclass
class EntityProfile:
    kind: str
    value: str
    anomaly_score: int  # 0-100
    risk_band: str
    signals: List[str] = field(default_factory=list)
    session_ids: List[str] = field(default_factory=list)
    linked_entities: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    observations: int = 0
    affected_targets: int = 0
    fan_out: int = 0
    fan_in: int = 0
    events_per_minute: float = 0.0

    def to_payload(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "value": self.value,
            "entity": f"{self.kind}:{self.value}",
            "anomalyScore": self.anomaly_score,
            "riskBand": self.risk_band,
            "signals": self.signals,
            "sessionIds": self.session_ids,
            "linkedEntities": self.linked_entities,
            "sources": self.sources,
            "firstSeen": int(self.first_seen),
            "lastSeen": int(self.last_seen),
            "observations": self.observations,
            "affectedTargets": self.affected_targets,
            "fanOut": self.fan_out,
            "fanIn": self.fan_in,
            "eventsPerMinute": self.events_per_minute,
        }


def _risk_band(score: int) -> str:
    if score >= 75:
        return RISK_CRITICAL
    if score >= 50:
        return RISK_HIGH
    if score >= 25:
        return RISK_MEDIUM
    return RISK_LOW


@dataclass
class _Accum:
    kind: str
    value: str
    session_ids: set = field(default_factory=set)
    co_entities: set = field(default_factory=set)
    sources: set = field(default_factory=set)
    first_seen: float = float("inf")
    last_seen: float = 0.0
    observations: int = 0
    affected_targets: int = 0
    saw_success: bool = False
    # targets this entity reached out to / was reached from, for fan-out/in.
    peer_users: set = field(default_factory=set)
    peer_ips: set = field(default_factory=set)


def analyze_entities(sessions: Iterable, now: Optional[float] = None) -> List[EntityProfile]:
    """Build ranked behavioural profiles for every entity across all sessions."""
    now = time.time() if now is None else now
    sessions = list(sessions)
    accums: Dict[str, _Accum] = {}

    for state in sessions:
        entities = _session_entities(state)
        start = state.first_scam_timestamp or state.created_at
        end = state.finalized_timestamp or state.updated_at
        obs = int(getattr(state, "event_count", 1) or 1)
        targets = int(getattr(state, "affected_targets", 1) or 1)
        source = getattr(state, "source_type", "honeypot")
        succeeded = "success" in " ".join(getattr(state, "scam_triggers", []) or []).lower()

        # Entities this session touched, split for fan-out/in maths.
        users = [e.split(":", 1)[1] for e in entities if e.startswith("user:")]
        ips = [e.split(":", 1)[1] for e in entities if e.startswith("ip:")]

        for entity in entities:
            kind, _, value = entity.partition(":")
            acc = accums.setdefault(entity, _Accum(kind=kind, value=value))
            acc.session_ids.add(state.session_id)
            acc.co_entities.update(e for e in entities if e != entity)
            acc.sources.add(source)
            acc.first_seen = min(acc.first_seen, start)
            acc.last_seen = max(acc.last_seen, end)
            acc.observations += obs
            acc.affected_targets += targets
            acc.saw_success = acc.saw_success or succeeded
            if kind == "ip":
                acc.peer_users.update(users)
            if kind == "user":
                acc.peer_ips.update(ips)

    profiles: List[EntityProfile] = []
    for entity, acc in accums.items():
        profiles.append(_score_entity(acc, now))

    profiles.sort(key=lambda p: (-p.anomaly_score, p.kind, p.value))
    return profiles


def _score_entity(acc: _Accum, now: float) -> EntityProfile:
    signals: List[str] = []
    score = 0

    duration = max(0.0, acc.last_seen - acc.first_seen)
    window_minutes = max(1.0, duration / 60.0)
    epm = round(acc.observations / window_minutes, 2)

    session_count = len(acc.session_ids)
    fan_out = len(acc.peer_users)   # an IP -> many accounts
    fan_in = len(acc.peer_ips)      # an account <- many IPs

    # --- signals -----------------------------------------------------------
    if fan_out >= 5:
        score += 30
        signals.append(f"Fan-out to {fan_out} accounts from one source - spray/stuffing pattern.")
    elif fan_out >= 2:
        score += 12
        signals.append(f"Touched {fan_out} distinct accounts.")

    if fan_in >= 5:
        score += 25
        signals.append(f"Targeted from {fan_in} distinct sources - distributed attack.")
    elif fan_in >= 2:
        score += 10
        signals.append(f"Hit from {fan_in} distinct sources.")

    if epm >= _VELOCITY_BASELINE_EPM:
        score += 20
        signals.append(f"{epm} events/min - above the {_VELOCITY_BASELINE_EPM}/min human baseline (automation).")

    if len(acc.sources) > 1:
        score += 25
        signals.append("Seen in BOTH the honeypot and the technical feed - cross-source corroboration.")

    if session_count >= 3:
        score += 15
        signals.append(f"Links {session_count} sessions - a campaign hub.")
    elif session_count == 2:
        score += 8
        signals.append("Shared across 2 sessions.")

    if acc.saw_success:
        score += 20
        signals.append("Associated with a successful authentication after failures - possible breach.")

    if acc.affected_targets >= 10:
        score += 12
        signals.append(f"Reached {acc.affected_targets} targets in total.")

    # Novelty: first seen inside the last 10 minutes of the window.
    if (now - acc.first_seen) <= 600:
        score += 5
        signals.append("First observed within the last 10 minutes - new infrastructure.")

    # Kind carries an intrinsic weight: a mule UPI/account is inherently actionable.
    if acc.kind in ("upi", "account", "wallet"):
        score += 10
        signals.append("Financial collection identifier - directly actionable.")

    if not signals:
        signals.append("No anomalous behaviour beyond baseline presence.")

    score = min(100, score)
    return EntityProfile(
        kind=acc.kind,
        value=acc.value,
        anomaly_score=score,
        risk_band=_risk_band(score),
        signals=signals,
        session_ids=sorted(acc.session_ids),
        linked_entities=sorted(acc.co_entities),
        sources=sorted("Technical" if s == "technical" else "Honeypot" for s in acc.sources),
        first_seen=0.0 if acc.first_seen == float("inf") else acc.first_seen,
        last_seen=acc.last_seen,
        observations=acc.observations,
        affected_targets=acc.affected_targets,
        fan_out=fan_out,
        fan_in=fan_in,
        events_per_minute=epm,
    )


def entities_for_sessions(profiles: Sequence[EntityProfile], session_ids: Iterable[str]) -> List[EntityProfile]:
    """Filter a profile list down to the entities that touch a given session set -
    used to attach UEBA context to one incident."""
    wanted = set(session_ids)
    return [p for p in profiles if wanted.intersection(p.session_ids)]


def risk_band_counts(profiles: Sequence[EntityProfile]) -> Dict[str, int]:
    counts = {RISK_CRITICAL: 0, RISK_HIGH: 0, RISK_MEDIUM: 0, RISK_LOW: 0}
    for p in profiles:
        counts[p.risk_band] += 1
    return counts


def _self_check() -> None:
    from models.session import SessionState

    def tech(sid, ip, users, count, targets, offset=0, success=False):
        s = SessionState(
            session_id=sid, persona_id="technical-feed", persona_label=ip,
            source_type="technical", event_count=count, affected_targets=targets,
        )
        s.scam_detected = True
        s.scam_category = "CREDENTIAL_STUFFING"
        s.first_scam_timestamp = 1000.0 + offset
        s.finalized_timestamp = 1000.0 + offset + 30
        s.updated_at = 1000.0 + offset + 30
        s.intel.ip_addresses.add(ip)
        for u in users:
            s.intel.usernames.add(u)
        if success:
            s.scam_triggers = ["success", "failure_burst"]
        return s

    def chat(sid, upi, domain=None, offset=0):
        s = SessionState(session_id=sid, persona_id="p", persona_label="P")
        s.scam_detected = True
        s.scam_category = "UPI_FRAUD"
        s.first_scam_timestamp = 1000.0 + offset
        s.updated_at = 1000.0 + offset + 30
        s.intel.upi_ids.add(upi)
        if domain:
            s.intel.domains.add(domain)
        return s

    # One IP spraying 8 accounts is a high-anomaly entity.
    spray = tech("t1", "203.0.113.9", [f"user{i}" for i in range(8)], count=50, targets=8, success=True)
    profiles = analyze_entities([spray], now=1200.0)
    ip_profile = next(p for p in profiles if p.kind == "ip")
    assert ip_profile.fan_out == 8, ip_profile
    assert ip_profile.risk_band in (RISK_HIGH, RISK_CRITICAL), ip_profile
    assert any("Fan-out" in s for s in ip_profile.signals), ip_profile

    # Cross-source: the same domain in a chat and a technical event scores the
    # corroboration signal.
    c = chat("c1", "mule@ybl", domain="sbi-verify.tk")
    t = tech("t2", "5.5.5.5", ["a.sharma"], count=40, targets=1)
    t.intel.domains.add("sbi-verify.tk")
    profs = analyze_entities([c, t], now=1200.0)
    dom = next(p for p in profs if p.kind == "domain" and p.value == "sbi-verify.tk")
    assert len(dom.sources) == 2, dom
    assert any("cross-source" in s.lower() for s in dom.signals), dom

    # Filtering to a session set works.
    subset = entities_for_sessions(profs, ["c1"])
    assert all("c1" in p.session_ids for p in subset), subset

    counts = risk_band_counts(profiles)
    assert sum(counts.values()) == len(profiles)

    # Quiet, non-scam sessions produce no entities.
    quiet = SessionState(session_id="q", persona_id="p", persona_label="P")
    assert analyze_entities([quiet]) == []

    print("behavioral_analytics self-check ok")


if __name__ == "__main__":
    _self_check()
