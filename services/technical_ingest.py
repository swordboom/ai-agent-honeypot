"""Technical feed -> SessionState without entering the honeypot engagement path."""

from models.session import SessionState
from services.technical_detector import classify


def ingest(event, session_manager) -> SessionState:
    detection = classify(
        event_type=event.eventType,
        count=event.count,
        distinct_targets=len(set(event.targetIdentifiers)),
        succeeded=event.succeededAfterFailures,
    )

    def factory(session_id: str) -> SessionState:
        return SessionState(
            session_id=session_id,
            persona_id="technical-feed",
            persona_label=event.sourceIdentifier,
            source_type="technical",
            event_type=event.eventType,
            source_identifier=event.sourceIdentifier,
            event_count=max(1, int(event.count)),
            affected_targets=max(1, len(set(event.targetIdentifiers))),
            created_at=event.timestamp,
            updated_at=event.timestamp,
        )

    state = session_manager.get_or_create(event.eventId, factory)

    def apply(intel) -> None:
        indicators = event.indicators
        intel.ip_addresses.update(indicators.get("ip", []))
        intel.usernames.update(indicators.get("user", []))
        intel.file_hashes.update(indicators.get("hash", []))
        intel.endpoints.update(indicators.get("endpoint", []))
        intel.domains.update(indicators.get("domain", []))
        intel.emails.update(indicators.get("email", []))

    session_manager.update_intel(state, apply)
    session_manager.update_detection(
        state,
        is_scam=detection.is_threat,
        confidence=event.confidence if detection.is_threat else 0.0,
        category=detection.category,
        triggers=list(detection.triggers),
        suspicious_keywords=[],
        rolling_score=float(event.count) if detection.is_threat else 0.0,
        rule_score=float(event.count) if detection.is_threat else 0.0,
        behavior_score=0.0,
        strategy_state="Technical detection",
    )
    # Preserve the feed timestamp for deterministic correlation and immediately
    # close this non-conversational track without creating an agent note/reply.
    session_manager.finalize_technical(state, event.timestamp)
    return state
