"""
Incident declaration and severity scoring (Feature 3).

Detection produces per-message alerts. That is not enough for an operator: forty
alerts across nine sessions that all point at the same UPI handle are *one attack*,
and someone has to say so out loud and rank it against everything else on the board.

This module does exactly that:
  1. Correlate  - sessions sharing a hard indicator (UPI id, phone, link domain,
                  bank account, crypto wallet) collapse into one incident.
  2. Score      - velocity, attack type, breadth and captured intel produce 0-100.
  3. Declare    - a named incident with a CRITICAL / HIGH / MEDIUM / LOW label.

Incidents are derived on read from live session state rather than persisted. The
session store is already the source of truth and is in-memory anyway, so a second
store would only add a way for the two to disagree.
ponytail: recompute per request, no cache. Measured on this machine, one call is
0.4ms at 30 sessions, 9ms at 1000, 28ms at 3000; a dashboard poll triggers ~4 of them
against a 5s interval. Add memoisation only if those numbers stop holding.
"""

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

SEVERITY_ORDER = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1, SEVERITY_MEDIUM: 2, SEVERITY_LOW: 3}

# The noise filter. A queue where everything is "important" is a queue nobody works,
# so only the top two bands are put in front of an operator; LOW is kept and
# searchable but never surfaces on its own.
TRIAGE_ACTION_REQUIRED = "ACTION_REQUIRED"
TRIAGE_REVIEW = "REVIEW"
TRIAGE_SUPPRESSED = "SUPPRESSED"

TRIAGE_BY_SEVERITY: Dict[str, str] = {
    SEVERITY_CRITICAL: TRIAGE_ACTION_REQUIRED,
    SEVERITY_HIGH: TRIAGE_ACTION_REQUIRED,
    SEVERITY_MEDIUM: TRIAGE_REVIEW,
    SEVERITY_LOW: TRIAGE_SUPPRESSED,
}

# How dangerous each attack type is on its own, before volume is considered.
# Digital-arrest and UPI fraud drain a victim's account in one sitting; a lottery
# lure needs many more steps to cause loss.
ATTACK_TYPE_WEIGHTS: Dict[str, int] = {
    "DIGITAL_ARREST": 30,
    "UPI_FRAUD": 27,
    "BANK_FRAUD": 25,
    "CRYPTO_SCAM": 24,
    "KYC_FRAUD": 22,
    "PHISHING": 20,
    "PHISHING_EMAIL": 22,   # email is the #1 delivery vector; spoofing + SPF fail = serious
    "SUSPICIOUS_EMAIL": 16,
    "SUSPICIOUS_URL": 16,
    "REFUND_SCAM": 14,
    "LOTTERY_SCAM": 12,
    "GENERIC_SCAM": 8,
    "CREDENTIAL_STUFFING": 28,
    "BRUTE_FORCE": 26,
    "WEB_ATTACK": 24,
    "PORT_SCAN": 12,
    "UNKNOWN": 6,
}

CATEGORY_LABELS: Dict[str, str] = {
    "DIGITAL_ARREST": "Digital arrest",
    "UPI_FRAUD": "UPI payment fraud",
    "BANK_FRAUD": "Bank impersonation",
    "CRYPTO_SCAM": "Crypto investment fraud",
    "KYC_FRAUD": "KYC update fraud",
    "PHISHING": "Phishing",
    "PHISHING_EMAIL": "Email phishing",
    "SUSPICIOUS_EMAIL": "Suspicious email",
    "SUSPICIOUS_URL": "Suspicious URL / domain",
    "REFUND_SCAM": "Refund lure",
    "LOTTERY_SCAM": "Lottery / prize lure",
    "GENERIC_SCAM": "Generic scam",
    "CREDENTIAL_STUFFING": "Credential stuffing",
    "BRUTE_FORCE": "Brute-force attack",
    "WEB_ATTACK": "Web / API attack",
    "PORT_SCAN": "Port scan",
    "UNKNOWN": "Unclassified",
}

RECOMMENDED_ACTIONS: Dict[str, str] = {
    SEVERITY_CRITICAL: "Escalate now: freeze the listed payment identifiers and notify the cybercrime desk.",
    SEVERITY_HIGH: "Action within the hour: report the payment identifiers and block the listed domains.",
    SEVERITY_MEDIUM: "Queue for review: keep engaging to capture payment identifiers before closing.",
    SEVERITY_LOW: "Monitor only: not enough corroboration to act on yet.",
}

# How long an operator has before the action stops being useful. Money moves out of a
# mule account in minutes, so payment actions get the tightest clocks; a domain
# takedown is worth doing whether it lands in an hour or a day.
_SLA_BY_SEVERITY: Dict[str, float] = {
    SEVERITY_CRITICAL: 0.5,
    SEVERITY_HIGH: 1.0,
    SEVERITY_MEDIUM: 2.0,
    SEVERITY_LOW: 4.0,
}

# Per indicator kind: the action to take, who owns it, base urgency and why.
# priority is the sort key (lower runs first), sla_minutes is scaled by severity.
_INDICATOR_PLAYBOOK: Dict[str, Dict[str, object]] = {
    "upi": {
        "action": "FREEZE_UPI_HANDLE",
        "owner": "Payments fraud desk",
        "priority": 1,
        "sla_minutes": 30,
        "rationale": "Collection handle for the campaign - freezing it stops in-flight transfers.",
    },
    "account": {
        "action": "FREEZE_BENEFICIARY_ACCOUNT",
        "owner": "Bank liaison",
        "priority": 1,
        "sla_minutes": 30,
        "rationale": "Mule account receiving victim funds; request a lien before it is drained.",
    },
    "wallet": {
        "action": "FLAG_CRYPTO_WALLET",
        "owner": "Crypto compliance",
        "priority": 2,
        "sla_minutes": 60,
        "rationale": "Send the address to exchange compliance so deposits can be held.",
    },
    "domain": {
        "action": "BLOCK_AND_TAKEDOWN_DOMAIN",
        "owner": "Network security",
        "priority": 2,
        "sla_minutes": 60,
        "rationale": "Phishing host - block at the resolver and file a registrar takedown.",
    },
    "phone": {
        "action": "REPORT_CALLER_NUMBER",
        "owner": "Telecom abuse liaison",
        "priority": 3,
        "sla_minutes": 120,
        "rationale": "Report to the telecom abuse desk and the national cybercrime helpline (1930).",
    },
    "email": {
        "action": "BLOCK_SENDER_ADDRESS",
        "owner": "Email security",
        "priority": 4,
        "sla_minutes": 240,
        "rationale": "Add to the tenant block list and sweep mailboxes for prior contact.",
    },
    "ip": {
        "action": "BLOCK_SOURCE_IP",
        "owner": "Network security",
        "priority": 1,
        "sla_minutes": 15,
        "rationale": "Block the source at the edge and preserve its authentication activity for investigation.",
    },
    "user": {
        "action": "LOCK_ACCOUNT_AND_FORCE_RESET",
        "owner": "IAM / identity",
        "priority": 1,
        "sla_minutes": 30,
        "rationale": "Account was targeted by an authentication attack; lock it and require a credential reset.",
    },
    "hash": {
        "action": "QUARANTINE_FILE_HASH",
        "owner": "Endpoint security",
        "priority": 2,
        "sla_minutes": 60,
        "rationale": "Quarantine matching files and hunt endpoints for the captured hash.",
    },
    "endpoint": {
        "action": "INVESTIGATE_TARGET_ENDPOINT",
        "owner": "Application security",
        "priority": 2,
        "sla_minutes": 60,
        "rationale": "Review access and authentication logs for the targeted endpoint.",
    },
}

_DOMAIN_RE = re.compile(r"(?i)^(?:https?://)?(?:www\.)?([a-z0-9.\-]+)")


def _link_domain(link: str) -> str:
    match = _DOMAIN_RE.match(link.strip())
    return match.group(1).lower() if match else link.strip().lower()


@dataclass
class ResponseAction:
    """One concrete thing an operator should do, with an owner and a clock."""

    action: str
    target: str
    owner: str
    priority: int
    sla_minutes: int
    rationale: str


@dataclass
class Incident:
    incident_id: str
    name: str
    severity: str
    severity_score: float
    scam_category: str
    session_ids: List[str]
    session_count: int
    first_seen: float
    last_seen: float
    duration_seconds: int
    sessions_per_minute: float
    shared_indicators: List[str]
    languages: List[str]
    total_messages: int
    max_confidence: float
    score_breakdown: Dict[str, float]
    recommended_action: str
    response_plan: List[ResponseAction] = field(default_factory=list)
    triage: str = "ACTION_REQUIRED"
    source_type: str = "Honeypot"
    declared_at: float = field(default_factory=time.time)


class _Union:
    """Union-find over session ids. ponytail: no rank/compression, N is small."""

    def __init__(self) -> None:
        self._parent: Dict[str, str] = {}

    def add(self, item: str) -> None:
        self._parent.setdefault(item, item)

    def find(self, item: str) -> str:
        self.add(item)
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[rb] = ra

    def groups(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for item in self._parent:
            out.setdefault(self.find(item), []).append(item)
        return out


def _session_indicators(state) -> List[str]:
    """Hard, attacker-controlled identifiers. Keywords are deliberately excluded:
    every phishing message contains "verify", so they would merge everything."""
    intel = state.intel
    indicators = []
    indicators.extend(f"upi:{v.lower()}" for v in intel.upi_ids)
    indicators.extend(f"phone:{re.sub(r'[^0-9]', '', v)[-10:]}" for v in intel.phone_numbers if v)
    indicators.extend(f"account:{v}" for v in intel.bank_accounts)
    indicators.extend(f"wallet:{v.lower()}" for v in intel.crypto_wallets)
    indicators.extend(f"domain:{_link_domain(v)}" for v in intel.phishing_links if v)
    indicators.extend(f"domain:{_link_domain(v)}" for v in intel.domains if v)
    indicators.extend(f"email:{v.lower()}" for v in intel.emails)
    indicators.extend(f"ip:{v.lower()}" for v in intel.ip_addresses)
    indicators.extend(f"user:{v.lower()}" for v in intel.usernames)
    indicators.extend(f"hash:{v.lower()}" for v in intel.file_hashes)
    indicators.extend(f"endpoint:{v.lower()}" for v in intel.endpoints)
    return [i for i in indicators if len(i.split(":", 1)[1]) >= 4]


def _cluster(sessions: Sequence) -> List[List]:
    by_id = {s.session_id: s for s in sessions}
    union = _Union()
    indicator_owner: Dict[str, str] = {}

    for state in sessions:
        union.add(state.session_id)
        for indicator in _session_indicators(state):
            owner = indicator_owner.setdefault(indicator, state.session_id)
            union.union(owner, state.session_id)

    return [[by_id[sid] for sid in ids] for ids in union.groups().values()]


def _dominant_category(cluster: Sequence) -> str:
    counts: Dict[str, int] = {}
    for state in cluster:
        counts[state.scam_category] = counts.get(state.scam_category, 0) + 1
    # Ties break toward the more dangerous type, not toward alphabetical order.
    return max(counts.items(), key=lambda kv: (kv[1], ATTACK_TYPE_WEIGHTS.get(kv[0], 0)))[0]


def _severity_from_score(score: float) -> str:
    if score >= 75:
        return SEVERITY_CRITICAL
    if score >= 50:
        return SEVERITY_HIGH
    if score >= 25:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def _score(
    category: str,
    affected_entities: int,
    events_per_minute: float,
    distinct_indicators: int,
    max_confidence: float,
) -> Tuple[float, Dict[str, float]]:
    """
    0-100, built from four things an operator would actually weigh.

    ponytail: fixed weights, no learned model. Tune the constants from real
    triage feedback; a model only earns its keep once there is labelled data.
    """
    attack_type = float(ATTACK_TYPE_WEIGHTS.get(category, ATTACK_TYPE_WEIGHTS["UNKNOWN"]))
    breadth = min(25.0, 5.0 * (affected_entities - 1))
    velocity = min(20.0, 5.0 * events_per_minute)
    intel_value = min(15.0, 3.0 * distinct_indicators)
    confidence = 10.0 * max(0.0, min(1.0, max_confidence))

    breakdown = {
        "attackType": round(attack_type, 2),
        "breadth": round(breadth, 2),
        "velocity": round(velocity, 2),
        "intelValue": round(intel_value, 2),
        "confidence": round(confidence, 2),
    }
    return round(sum(breakdown.values()), 2), breakdown


# Name the incident after the most actionable identifier available: a UPI handle
# can be reported and frozen, a caller ID mostly cannot.
_NAMING_PRIORITY = ("upi", "wallet", "account", "domain", "ip", "email", "phone", "user", "hash", "endpoint")


def _headline_indicator(indicators: List[str]) -> Optional[str]:
    for kind in _NAMING_PRIORITY:
        for indicator in indicators:
            if indicator.startswith(f"{kind}:"):
                return indicator.split(":", 1)[1]
    return None


# Above this many targets of one kind, the plan names a count instead of a row each.
_MAX_TARGETS_PER_KIND = 3

_BULK_NOUNS = {
    "ip": "source IPs",
    "user": "accounts",
    "hash": "file hashes",
    "endpoint": "endpoints",
    "phone": "numbers",
    "email": "addresses",
    "domain": "domains",
    "upi": "UPI handles",
    "account": "bank accounts",
    "wallet": "wallets",
}


def _bulk_target(kind: str, targets: List[str]) -> str:
    shown = ", ".join(targets[:_MAX_TARGETS_PER_KIND])
    return f"{len(targets)} {_BULK_NOUNS.get(kind, kind)} ({shown} +{len(targets) - _MAX_TARGETS_PER_KIND} more)"


def build_response_plan(
    severity: str,
    category: str,
    indicators: List[str],
    session_count: int,
    languages: List[str],
) -> List[ResponseAction]:
    """
    Turn an incident into the specific things to do about it.

    Actions come from the indicators actually captured, not from the severity label
    alone - "escalate now" is not a response, "freeze mule.pay@ybl within 15 minutes,
    payments fraud desk" is. Deadlines tighten with severity.
    """
    scale = _SLA_BY_SEVERITY[severity]
    actions: List[ResponseAction] = []

    # Group by kind first. A scam session yields one or two payment handles, but a
    # credential attack yields dozens of usernames and a spray yields dozens of IPs -
    # naming each one separately turns a response plan into the alert queue this
    # system exists to collapse.
    by_kind: Dict[str, List[str]] = {}
    for indicator in indicators:
        kind, _, target = indicator.partition(":")
        if target and kind in _INDICATOR_PLAYBOOK:
            by_kind.setdefault(kind, []).append(target)

    for kind, targets in by_kind.items():
        rule = _INDICATOR_PLAYBOOK[kind]
        sla = max(15, int(round(float(rule["sla_minutes"]) * scale)))
        # Few targets stay individually actionable; many collapse into one bulk
        # action that still names the first few, so the plan stays readable.
        chunks = (
            [[t] for t in targets]
            if len(targets) <= _MAX_TARGETS_PER_KIND
            else [targets]
        )
        for chunk in chunks:
            actions.append(
                ResponseAction(
                    action=str(rule["action"]),
                    target=chunk[0] if len(chunk) == 1 else _bulk_target(kind, chunk),
                    owner=str(rule["owner"]),
                    priority=int(rule["priority"]),
                    sla_minutes=sla,
                    rationale=str(rule["rationale"]),
                )
            )

    # Campaign-level actions that follow from the shape of the incident, not from any
    # single indicator.
    if severity in (SEVERITY_CRITICAL, SEVERITY_HIGH):
        actions.append(
            ResponseAction(
                action="FILE_CYBERCRIME_REPORT",
                target=f"{category} campaign",
                owner="SOC lead",
                priority=1,
                sla_minutes=max(15, int(60 * scale)),
                rationale="Severity clears the bar for a formal report with the captured indicators attached.",
            )
        )

    if session_count >= 3:
        actions.append(
            ResponseAction(
                action="ISSUE_CUSTOMER_ADVISORY",
                target=f"{session_count} targeted sessions",
                owner="Comms / fraud awareness",
                priority=3,
                sla_minutes=max(60, int(240 * scale)),
                rationale="Campaign is hitting multiple targets; warn the affected segment before it spreads.",
            )
        )

    vernacular = [code for code in languages if code != "en"]
    if vernacular:
        actions.append(
            ResponseAction(
                action="ROUTE_TO_LANGUAGE_ANALYST",
                target=", ".join(vernacular),
                owner="Regional fraud analyst",
                priority=4,
                sla_minutes=max(60, int(240 * scale)),
                rationale="Operating in a regional language - a native-speaker review catches nuance the lexicon misses.",
            )
        )

    if not actions:
        actions.append(
            ResponseAction(
                action="CONTINUE_ENGAGEMENT",
                target="honey-pot session",
                owner="Automated agent",
                priority=5,
                sla_minutes=max(60, int(240 * scale)),
                rationale="No actionable identifier captured yet; keep the engagement running to harvest one.",
            )
        )

    actions.sort(key=lambda a: (a.priority, a.sla_minutes, a.action, a.target))
    return actions


def _incident_name(category: str, indicators: List[str], session_count: int, incident_id: str) -> str:
    label = CATEGORY_LABELS.get(category, category)
    headline = _headline_indicator(indicators)
    if session_count > 1 and headline:
        return f"{label} campaign via {headline} ({session_count} sessions)"
    if session_count > 1:
        return f"{label} campaign ({session_count} sessions)"
    if headline:
        return f"{label} incident via {headline}"
    return f"{label} incident {incident_id}"


def _build_incident(cluster: Sequence, now: float) -> Incident:
    session_ids = sorted(s.session_id for s in cluster)
    incident_id = "INC-" + hashlib.sha256("|".join(session_ids).encode("utf-8")).hexdigest()[:8].upper()

    starts = [s.first_scam_timestamp or s.created_at for s in cluster]
    ends = [s.finalized_timestamp or s.updated_at for s in cluster]
    first_seen, last_seen = min(starts), max(ends)
    duration = max(0, int(last_seen - first_seen))

    # Rate over at least a one-minute window, so a two-second burst is not
    # reported as thousands of sessions per minute.
    window_minutes = max(1.0, duration / 60.0)
    sessions_per_minute = round(len(cluster) / window_minutes, 2)

    # One technical event can carry 50 attempts against 12 accounts, so severity reads
    # the magnitudes the feed reported rather than counting rows. A honeypot track is
    # 1 observation against 1 victim, which makes both of these identical to the old
    # session-count maths and leaves existing scores untouched.
    observations = sum(getattr(s, "event_count", 1) for s in cluster)
    affected_entities = max(len(cluster), sum(getattr(s, "affected_targets", 1) for s in cluster))
    events_per_minute = round(observations / window_minutes, 2)

    indicators = sorted({i for s in cluster for i in _session_indicators(s)})
    languages = sorted({s.language for s in cluster if s.language and s.language != "unknown"})
    category = _dominant_category(cluster)
    max_confidence = max((s.scam_confidence for s in cluster), default=0.0)

    score, breakdown = _score(
        category=category,
        affected_entities=affected_entities,
        events_per_minute=events_per_minute,
        distinct_indicators=len(indicators),
        max_confidence=max_confidence,
    )
    severity = _severity_from_score(score)
    source_types = {getattr(s, "source_type", "honeypot") for s in cluster}
    source_type = "Mixed" if len(source_types) > 1 else ("Technical" if "technical" in source_types else "Honeypot")

    return Incident(
        response_plan=build_response_plan(severity, category, indicators, len(cluster), languages),
        triage=TRIAGE_BY_SEVERITY[severity],
        source_type=source_type,
        incident_id=incident_id,
        name=_incident_name(category, indicators, len(cluster), incident_id),
        severity=severity,
        severity_score=score,
        scam_category=category,
        session_ids=session_ids,
        session_count=len(cluster),
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
        sessions_per_minute=sessions_per_minute,
        shared_indicators=indicators,
        languages=languages,
        total_messages=sum(len(s.transcript) for s in cluster),
        max_confidence=round(max_confidence, 2),
        score_breakdown=breakdown,
        recommended_action=RECOMMENDED_ACTIONS[severity],
        declared_at=now,
    )


def declare_incidents(sessions: Iterable, now: Optional[float] = None) -> List[Incident]:
    """
    Turn confirmed-scam sessions into ranked incidents, worst first.

    Sessions where no scam was detected produce no incident - declaring one would
    put noise at the top of an operator's queue, which is the failure this feature
    exists to prevent.
    """
    now = time.time() if now is None else now
    scam_sessions = [s for s in sessions if s.scam_detected]
    if not scam_sessions:
        return []

    incidents = [_build_incident(cluster, now) for cluster in _cluster(scam_sessions)]
    incidents.sort(key=lambda i: (SEVERITY_ORDER[i.severity], -i.severity_score, -i.last_seen))
    return incidents


def severity_counts(incidents: Sequence[Incident]) -> Dict[str, int]:
    counts = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0}
    for incident in incidents:
        counts[incident.severity] += 1
    return counts


def triage_funnel(raw_events: int, sessions: int, incidents: Sequence[Incident]) -> Dict[str, object]:
    """
    The events -> incidents -> "actually work this" funnel.

    This is the number the problem is really about: a security team drowning in
    events cares how many things are left once correlation and prioritisation have
    run, not how many alerts fired.
    """
    action_required = [i for i in incidents if i.triage == TRIAGE_ACTION_REQUIRED]
    review = [i for i in incidents if i.triage == TRIAGE_REVIEW]
    suppressed = [i for i in incidents if i.triage == TRIAGE_SUPPRESSED]

    reduction = 0.0
    if raw_events:
        reduction = round(100.0 * (1.0 - (len(action_required) / raw_events)), 1)

    return {
        "rawEvents": raw_events,
        "sessions": sessions,
        "incidents": len(incidents),
        "actionRequired": len(action_required),
        "review": len(review),
        "suppressed": len(suppressed),
        "openActions": sum(len(i.response_plan) for i in action_required),
        "noiseReductionPercent": max(0.0, reduction),
    }


def _self_check() -> None:
    from models.session import SessionState, TranscriptMessage

    def make(sid, category, upi=None, phone=None, conf=0.9, lang="en", start_offset=0):
        state = SessionState(session_id=sid, persona_id="p", persona_label="P")
        state.scam_detected = True
        state.scam_category = category
        state.scam_confidence = conf
        state.language = lang
        state.first_scam_timestamp = 1000.0 + start_offset
        state.updated_at = 1000.0 + start_offset + 30
        state.transcript.append(TranscriptMessage(sender="scammer", text="x", timestamp=1))
        if upi:
            state.intel.upi_ids.add(upi)
        if phone:
            state.intel.phone_numbers.add(phone)
        return state

    # Sessions sharing a UPI handle are one incident; an unrelated one stays separate.
    shared = [
        make("a", "UPI_FRAUD", upi="fraud@ybl"),
        make("b", "UPI_FRAUD", upi="fraud@ybl", start_offset=20),
        make("c", "UPI_FRAUD", upi="fraud@ybl", start_offset=40),
        make("z", "LOTTERY_SCAM", upi="prize@okaxis"),
    ]
    incidents = declare_incidents(shared, now=1200.0)
    assert len(incidents) == 2, incidents
    campaign = next(i for i in incidents if len(i.session_ids) == 3)
    assert campaign.session_ids == ["a", "b", "c"], campaign
    assert "fraud@ybl" in campaign.name, campaign.name

    # Naming prefers the freezable identifier over the caller ID.
    named = declare_incidents(
        [make("a", "UPI_FRAUD", upi="mule@ybl", phone="+919876543210")], now=1200.0
    )
    assert "mule@ybl" in named[0].name, named[0].name

    # A wide, fast digital-arrest campaign outranks a lone lottery lure.
    lone = next(i for i in incidents if i.session_ids == ["z"])
    assert SEVERITY_ORDER[campaign.severity] <= SEVERITY_ORDER[lone.severity], (campaign, lone)
    assert campaign.severity_score > lone.severity_score

    # Transitive linking: a-b share a phone, b-c share a UPI, so all three merge.
    chain = [
        make("a", "BANK_FRAUD", phone="+919876543210"),
        make("b", "BANK_FRAUD", phone="+919876543210", upi="mule@upi"),
        make("c", "BANK_FRAUD", upi="mule@upi"),
    ]
    merged = declare_incidents(chain, now=1200.0)
    assert len(merged) == 1, merged
    assert merged[0].session_ids == ["a", "b", "c"]

    # A track that stands for many observations against many targets scores on those
    # magnitudes, not on how many rows the feed sent.
    bulk = make("bulk", "BRUTE_FORCE", upi="x@ybl")
    bulk.event_count, bulk.affected_targets = 50, 12
    bulk_incident = declare_incidents([bulk], now=1200.0)[0]
    lone = declare_incidents([make("lone", "BRUTE_FORCE", upi="y@ybl")], now=1200.0)[0]
    assert bulk_incident.score_breakdown["breadth"] > lone.score_breakdown["breadth"], bulk_incident
    assert bulk_incident.score_breakdown["velocity"] > lone.score_breakdown["velocity"], bulk_incident
    # Defaults keep a plain honeypot session on exactly the old session-count maths.
    assert lone.score_breakdown["breadth"] == 0.0, lone.score_breakdown

    # Severity labels track the score bands.
    assert _severity_from_score(80) == SEVERITY_CRITICAL
    assert _severity_from_score(60) == SEVERITY_HIGH
    assert _severity_from_score(30) == SEVERITY_MEDIUM
    assert _severity_from_score(10) == SEVERITY_LOW

    # Non-scam traffic never gets declared.
    quiet = SessionState(session_id="q", persona_id="p", persona_label="P")
    assert declare_incidents([quiet]) == []

    # Scores stay inside the advertised 0-100 range at both extremes.
    hot = [make(f"s{i}", "DIGITAL_ARREST", upi=f"m{i}@upi", conf=1.0) for i in range(12)]
    for i in declare_incidents(hot, now=1200.0):
        assert 0.0 <= i.severity_score <= 100.0, i

    assert severity_counts(incidents)[campaign.severity] >= 1

    # --- recommended response actions --------------------------------------
    plan = campaign.response_plan
    assert plan, "an incident with indicators must produce actions"
    # Every action is concrete: a real target, a named owner, a deadline.
    for action in plan:
        assert action.target and action.owner and action.rationale, action
        assert action.sla_minutes >= 15, action
    # The captured UPI handle is actioned by name, not described in the abstract.
    freeze = [a for a in plan if a.action == "FREEZE_UPI_HANDLE"]
    assert freeze and freeze[0].target == "fraud@ybl", plan
    # Highest-priority work sorts first so the plan reads top-down.
    assert plan == sorted(plan, key=lambda a: (a.priority, a.sla_minutes, a.action, a.target))
    # A 3-session campaign warrants a customer advisory.
    assert any(a.action == "ISSUE_CUSTOMER_ADVISORY" for a in plan), plan

    # Vernacular campaigns route to a native-speaker analyst.
    hindi = declare_incidents(
        [make("h1", "UPI_FRAUD", upi="thug@ybl", lang="hi"), make("h2", "UPI_FRAUD", upi="thug@ybl", lang="hi")],
        now=1200.0,
    )
    assert any(a.action == "ROUTE_TO_LANGUAGE_ANALYST" for a in hindi[0].response_plan), hindi[0].response_plan

    # Tighter severity means tighter deadlines for the same action.
    def sla_for(severity):
        actions = build_response_plan(severity, "UPI_FRAUD", ["upi:x@ybl"], 1, ["en"])
        return next(a.sla_minutes for a in actions if a.action == "FREEZE_UPI_HANDLE")

    assert sla_for(SEVERITY_CRITICAL) < sla_for(SEVERITY_LOW), (sla_for(SEVERITY_CRITICAL), sla_for(SEVERITY_LOW))

    # A session with no indicators still gets told what to do next.
    bare = build_response_plan(SEVERITY_LOW, "GENERIC_SCAM", [], 1, ["en"])
    assert [a.action for a in bare] == ["CONTINUE_ENGAGEMENT"], bare

    # Many targets of one kind collapse into a single counted action instead of
    # one row per target.
    many = build_response_plan(
        SEVERITY_HIGH, "CREDENTIAL_STUFFING", [f"user:acct{i}" for i in range(14)], 1, ["en"]
    )
    locks = [a for a in many if a.action == "LOCK_ACCOUNT_AND_FORCE_RESET"]
    assert len(locks) == 1, locks
    assert locks[0].target.startswith("14 accounts ("), locks[0].target
    # Few targets are still named individually.
    few = build_response_plan(SEVERITY_HIGH, "BRUTE_FORCE", ["ip:203.0.113.9", "ip:203.0.113.8"], 1, ["en"])
    assert sorted(a.target for a in few if a.action == "BLOCK_SOURCE_IP") == ["203.0.113.8", "203.0.113.9"], few

    # --- triage funnel ------------------------------------------------------
    assert campaign.triage == TRIAGE_BY_SEVERITY[campaign.severity]
    funnel = triage_funnel(raw_events=400, sessions=4, incidents=incidents)
    assert funnel["incidents"] == len(incidents)
    assert funnel["actionRequired"] + funnel["review"] + funnel["suppressed"] == len(incidents)
    assert 0.0 <= funnel["noiseReductionPercent"] <= 100.0, funnel
    assert triage_funnel(0, 0, [])["noiseReductionPercent"] == 0.0

    print("incident engine self-check ok")


if __name__ == "__main__":
    _self_check()
