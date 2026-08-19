"""
SOC orchestration layer.

The four SOC capabilities live in separate modules on purpose - detection,
correlation/prioritisation (incident_engine), behavioural analytics
(behavioral_analytics), enrichment + automated investigation (threat_intel,
investigation). This module is the single place that runs them together and shapes
the result the way a SOC analyst reads it:

  - a **case queue**: every declared incident as a case with a status, an owner, an
    investigation verdict/confidence and an SLA clock;
  - **SOC KPIs**: detection latency (MTTD proxy), containment window (MTTR proxy),
    open vs. contained cases, analyst queue depth, and automation rate - the share
    of raw volume the pipeline handled without ever paging a human;
  - the **top risky entities** from UEBA and the triage funnel, in one payload.

`soc_overview` is what the `/soc` console and `GET /dashboard/api/soc/overview`
render. Everything is derived on read from live session state - no separate SOC
store to fall out of sync, same as the incident engine.
"""

import time
from typing import Dict, List, Optional, Sequence

from services.behavioral_analytics import analyze_entities, risk_band_counts
from services.incident_engine import declare_incidents, severity_counts, triage_funnel
from services.investigation import investigate_incident

# Case lifecycle. Derived from the incident's triage band and whether every session
# behind it has been finalised (contained) - there is no manual state to persist yet.
CASE_NEW = "NEW"
CASE_INVESTIGATING = "INVESTIGATING"
CASE_ACTION_REQUIRED = "ACTION_REQUIRED"
CASE_CONTAINED = "CONTAINED"


def _case_status(incident, sessions_by_id) -> str:
    all_final = all(
        (sessions_by_id.get(sid).finalized if sessions_by_id.get(sid) else True)
        for sid in incident.session_ids
    )
    if incident.triage == "ACTION_REQUIRED":
        return CASE_CONTAINED if all_final else CASE_ACTION_REQUIRED
    if incident.triage == "REVIEW":
        return CASE_INVESTIGATING
    return CASE_NEW


def _primary_owner(incident) -> str:
    """Who this case lands on first: the owner of its highest-priority action."""
    if incident.response_plan:
        top = min(incident.response_plan, key=lambda a: (a.priority, a.sla_minutes))
        return top.owner
    return "SOC lead"


def _tightest_sla(incident) -> Optional[int]:
    if not incident.response_plan:
        return None
    return min(a.sla_minutes for a in incident.response_plan)


def _detection_latency_seconds(state) -> Optional[int]:
    """MTTD proxy: time from the case first being observed to a scam being flagged.
    For the technical feed both stamps are the event time, so latency is ~0 - the
    point of the proxy is the honeypot path, where engagement precedes confirmation."""
    if not state.scam_detected or state.first_scam_timestamp is None:
        return None
    return max(0, int(state.first_scam_timestamp - state.created_at))


def soc_overview(sessions: Sequence, raw_events: int, now: Optional[float] = None) -> Dict[str, object]:
    now = time.time() if now is None else now
    sessions = list(sessions)
    sessions_by_id = {s.session_id: s for s in sessions}

    incidents = declare_incidents(sessions, now=now)
    profiles = analyze_entities(sessions, now=now)

    cases: List[Dict[str, object]] = []
    contained = 0
    open_cases = 0
    containment_windows: List[int] = []
    detection_latencies: List[int] = []

    for incident in incidents:
        investigation = investigate_incident(incident, sessions, profiles=profiles)
        status = _case_status(incident, sessions_by_id)
        if status == CASE_CONTAINED:
            contained += 1
            containment_windows.append(incident.duration_seconds)
        elif status in (CASE_ACTION_REQUIRED, CASE_INVESTIGATING):
            open_cases += 1

        cases.append({
            "incidentId": incident.incident_id,
            "name": incident.name,
            "severity": incident.severity,
            "severityScore": incident.severity_score,
            "sourceType": incident.source_type,
            "triage": incident.triage,
            "status": status,
            "owner": _primary_owner(incident),
            "slaMinutes": _tightest_sla(incident),
            "sessionCount": incident.session_count,
            "verdict": investigation.verdict,
            "investigationConfidence": investigation.confidence,
            "feedHitCount": investigation.feed_hit_count,
            "maliciousIndicatorCount": investigation.malicious_indicator_count,
            "topEntity": (
                investigation.entity_profiles[0].to_payload()
                if investigation.entity_profiles else None
            ),
            "openActions": len(incident.response_plan),
            "correlatedOn": incident.shared_indicators,
            "firstSeen": int(incident.first_seen),
            "lastSeen": int(incident.last_seen),
        })

    for state in sessions:
        latency = _detection_latency_seconds(state)
        if latency is not None:
            detection_latencies.append(latency)

    funnel = triage_funnel(raw_events or len(sessions), len(sessions), incidents)
    action_required = funnel["actionRequired"]

    # Automation rate: of everything correlated, the share that did NOT need a human.
    total_incidents = len(incidents)
    auto_handled = total_incidents - action_required
    automation_rate = round(100.0 * auto_handled / total_incidents, 1) if total_incidents else 0.0

    kpis = {
        "openCases": open_cases,
        "containedCases": contained,
        "actionRequired": action_required,
        "totalCases": total_incidents,
        "analystQueueDepth": action_required,
        "meanDetectionLatencySeconds": (
            int(sum(detection_latencies) / len(detection_latencies)) if detection_latencies else 0
        ),
        "meanContainmentSeconds": (
            int(sum(containment_windows) / len(containment_windows)) if containment_windows else 0
        ),
        "automationRatePercent": automation_rate,
        "noiseReductionPercent": funnel["noiseReductionPercent"],
        "confirmedThreats": sum(1 for c in cases if c["verdict"] == "TRUE_POSITIVE"),
        "trackedEntities": len(profiles),
    }

    top_entities = [p.to_payload() for p in profiles[:12]]

    return {
        "generatedAt": int(now),
        "kpis": kpis,
        "triageFunnel": funnel,
        "severityCounts": severity_counts(incidents),
        "entityRiskCounts": risk_band_counts(profiles),
        "cases": cases,
        "topEntities": top_entities,
    }


def soc_case(incident_id: str, sessions: Sequence, now: Optional[float] = None) -> Optional[Dict[str, object]]:
    """The full case file for one incident: incident + investigation + response plan."""
    from services.reporting import action_payload

    now = time.time() if now is None else now
    sessions = list(sessions)
    incidents = declare_incidents(sessions, now=now)
    incident = next((i for i in incidents if i.incident_id == incident_id), None)
    if incident is None:
        return None

    investigation = investigate_incident(incident, sessions)
    sessions_by_id = {s.session_id: s for s in sessions}
    return {
        "incidentId": incident.incident_id,
        "name": incident.name,
        "severity": incident.severity,
        "severityScore": incident.severity_score,
        "sourceType": incident.source_type,
        "triage": incident.triage,
        "status": _case_status(incident, sessions_by_id),
        "owner": _primary_owner(incident),
        "scamCategory": incident.scam_category,
        "sessionIds": incident.session_ids,
        "sessionCount": incident.session_count,
        "correlatedOn": incident.shared_indicators,
        "languages": incident.languages,
        "scoreBreakdown": incident.score_breakdown,
        "firstSeen": int(incident.first_seen),
        "lastSeen": int(incident.last_seen),
        "durationSeconds": incident.duration_seconds,
        "responsePlan": [action_payload(a) for a in incident.response_plan],
        "investigation": investigation.to_payload(),
    }


def _self_check() -> None:
    from models.session import SessionState, TranscriptMessage

    def chat(sid, upi, domain=None, offset=0, final=False):
        s = SessionState(session_id=sid, persona_id="p", persona_label="P")
        s.scam_detected = True
        s.scam_category = "UPI_FRAUD"
        s.scam_confidence = 0.9
        s.created_at = 1000.0 + offset
        s.first_scam_timestamp = 1000.0 + offset + 5
        s.updated_at = 1000.0 + offset + 40
        s.intel.upi_ids.add(upi)
        if domain:
            s.intel.phishing_links.add(domain)
        s.transcript.append(TranscriptMessage(sender="scammer", text="pay now", timestamp=1))
        if final:
            s.finalized = True
            s.finalized_timestamp = 1000.0 + offset + 40
        return s

    def tech(sid, ip, users, count, domain=None, offset=0):
        s = SessionState(
            session_id=sid, persona_id="technical-feed", persona_label=ip,
            source_type="technical", event_count=count, affected_targets=len(users),
        )
        s.scam_detected = True
        s.scam_category = "CREDENTIAL_STUFFING"
        s.scam_confidence = 0.9
        s.created_at = 1000.0 + offset
        s.first_scam_timestamp = 1000.0 + offset
        s.finalized = True
        s.finalized_timestamp = 1000.0 + offset + 30
        s.updated_at = 1000.0 + offset + 30
        s.intel.ip_addresses.add(ip)
        for u in users:
            s.intel.usernames.add(u)
        if domain:
            s.intel.domains.add(domain)
        return s

    c = chat("c1", "mule@ybl", domain="http://sbi-verify.tk/login", final=True)
    t = tech("t1", "203.0.113.9", [f"user{i}" for i in range(6)], count=40, domain="sbi-verify.tk")
    lottery = chat("l1", "prize@okaxis", offset=500)

    overview = soc_overview([c, t, lottery], raw_events=20, now=1200.0)
    assert overview["kpis"]["totalCases"] >= 2, overview["kpis"]
    assert 0.0 <= overview["kpis"]["automationRatePercent"] <= 100.0
    assert overview["cases"], overview
    assert overview["topEntities"], overview
    # The cross-source case is a confirmed true positive.
    mixed = next(c2 for c2 in overview["cases"] if c2["sourceType"] == "Mixed")
    assert mixed["verdict"] == "TRUE_POSITIVE", mixed
    assert mixed["owner"], mixed
    assert mixed["slaMinutes"] and mixed["slaMinutes"] >= 15, mixed

    # Case file for the mixed incident resolves and carries the investigation.
    case = soc_case(mixed["incidentId"], [c, t, lottery], now=1200.0)
    assert case and case["investigation"]["verdict"] == "TRUE_POSITIVE", case
    assert case["responsePlan"], case
    assert soc_case("INC-NONE", [c, t, lottery]) is None

    print("soc self-check ok")


if __name__ == "__main__":
    _self_check()
