"""
Our own report format.

The previous schema existed to satisfy one external grader's contract. This one is
shaped around the three questions a security team actually asks of a threat feed:

  what did we see        -> detection + indicators
  does it matter         -> incident, severity, triage
  what do we do about it -> responsePlan

`schemaVersion` is here so downstream consumers can pin; bump it on a breaking change.
"""

import time
from typing import Dict, List, Optional, Sequence

from agent.multilingual import LANGUAGE_NAMES
from models.session import SessionState
from services.incident_engine import Incident, declare_incidents, triage_funnel

SCHEMA_VERSION = "honeypot-report/1.0"


def engagement_duration_seconds(state: SessionState, now: Optional[float] = None) -> int:
    if state.first_scam_timestamp is None:
        return 0
    end = state.finalized_timestamp or state.updated_at
    return max(0, int(end - state.first_scam_timestamp))


def action_payload(action) -> Dict[str, object]:
    return {
        "action": action.action,
        "target": action.target,
        "owner": action.owner,
        "priority": action.priority,
        "slaMinutes": action.sla_minutes,
        "rationale": action.rationale,
    }


def incident_report(incident: Incident) -> Dict[str, object]:
    return {
        "incidentId": incident.incident_id,
        "name": incident.name,
        "severity": incident.severity,
        "severityScore": incident.severity_score,
        "triage": incident.triage,
        "scamCategory": incident.scam_category,
        "sessionIds": incident.session_ids,
        "sessionCount": incident.session_count,
        "firstSeen": int(incident.first_seen),
        "lastSeen": int(incident.last_seen),
        "durationSeconds": incident.duration_seconds,
        "sessionsPerMinute": incident.sessions_per_minute,
        "correlatedOn": incident.shared_indicators,
        "languages": [LANGUAGE_NAMES.get(code, code) for code in incident.languages],
        "totalMessages": incident.total_messages,
        "maxConfidence": incident.max_confidence,
        "scoreBreakdown": incident.score_breakdown,
        "summaryAction": incident.recommended_action,
        "responsePlan": [action_payload(a) for a in incident.response_plan],
    }


def session_report(state: SessionState, incident: Optional[Incident] = None) -> Dict[str, object]:
    total_messages = state.final_total_messages_exchanged or len(state.transcript)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": int(time.time()),
        "sessionId": state.session_id,
        "status": "closed" if state.finalized else "active",
        "detection": {
            "scamDetected": state.scam_detected,
            "category": state.scam_category,
            "confidence": round(min(1.0, max(0.0, state.scam_confidence)), 2),
            "riskScore": state.rolling_scam_score,
            "lastRuleScore": state.last_rule_risk_score,
            "lastBehaviorScore": state.last_behavior_risk_score,
            "strategyState": state.strategy_state,
            "triggers": state.scam_triggers,
        },
        "language": {
            "code": state.language,
            "name": state.language_name,
            "confidence": state.language_confidence,
            "observed": [LANGUAGE_NAMES.get(c, c) for c in state.languages_seen],
            "vernacularScore": state.vernacular_score,
        },
        "engagement": {
            "persona": state.persona_label,
            "personaId": state.persona_id,
            "agentTurns": state.agent_turns,
            "scammerMessages": state.scammer_messages,
            "totalMessages": total_messages,
            "durationSeconds": engagement_duration_seconds(state),
            "replyProvider": state.reply_provider,
        },
        "indicators": state.intel.to_indicator_payload(),
        "extendedIndicators": state.intel.to_extended_payload(),
        "incident": (
            {
                "incidentId": incident.incident_id,
                "name": incident.name,
                "severity": incident.severity,
                "severityScore": incident.severity_score,
                "triage": incident.triage,
                "responsePlan": [action_payload(a) for a in incident.response_plan],
            }
            if incident
            else None
        ),
        "analystNotes": state.agent_notes,
    }


def threat_report(sessions: Sequence[SessionState], raw_events: int) -> Dict[str, object]:
    """The whole picture: every declared incident, ranked, with the triage funnel."""
    incidents = declare_incidents(sessions)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": int(time.time()),
        "triageFunnel": triage_funnel(raw_events, len(sessions), incidents),
        "incidents": [incident_report(i) for i in incidents],
    }


def incident_index(sessions: Sequence[SessionState]) -> Dict[str, Incident]:
    index: Dict[str, Incident] = {}
    for incident in declare_incidents(sessions):
        for session_id in incident.session_ids:
            index[session_id] = incident
    return index


def _self_check() -> None:
    from models.session import TranscriptMessage

    state = SessionState(session_id="s1", persona_id="retired_teacher", persona_label="Arthur")
    state.scam_detected = True
    state.scam_category = "UPI_FRAUD"
    state.scam_confidence = 0.9
    state.language, state.language_name, state.languages_seen = "hi", "Hindi", ["hi"]
    state.first_scam_timestamp = time.time() - 90
    state.intel.upi_ids.add("mule@ybl")
    state.transcript.append(TranscriptMessage(sender="scammer", text="pay now", timestamp=1))

    incident = declare_incidents([state])[0]
    report = session_report(state, incident)

    assert report["schemaVersion"] == SCHEMA_VERSION
    assert report["detection"]["category"] == "UPI_FRAUD"
    assert report["language"]["name"] == "Hindi"
    assert report["indicators"]["upiIds"] == ["mule@ybl"]
    assert report["incident"]["responsePlan"], report["incident"]
    assert report["status"] == "active"
    # No trace of the old grader's contract.
    assert "extractedIntelligence" not in report and "scamType" not in report

    whole = threat_report([state], raw_events=50)
    assert whole["incidents"][0]["responsePlan"], whole
    assert whole["triageFunnel"]["rawEvents"] == 50
    assert whole["incidents"][0]["correlatedOn"] == ["upi:mule@ybl"]

    # A session with no incident still reports cleanly.
    quiet = SessionState(session_id="q", persona_id="p", persona_label="P")
    assert session_report(quiet)["incident"] is None

    print("reporting self-check ok")


if __name__ == "__main__":
    _self_check()
