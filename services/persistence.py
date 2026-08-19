"""
JSON snapshot persistence for the in-memory session store.

Saves the full session state to a single .json file on disk so that
history survives a process restart.  The file is written atomically
(write-to-tmp → os.replace) so a crash mid-write never produces a
corrupt snapshot.

Usage:
    from services.persistence import save_snapshot, load_snapshot

    # on startup
    event_count = load_snapshot(session_manager, "/path/to/sessions.json")

    # periodically / on shutdown
    save_snapshot(session_manager, "/path/to/sessions.json", raw_event_count())
"""

import json
import logging
import os
import time
from typing import Tuple

from models.session import Intelligence, SessionState, TranscriptMessage
from services.session_manager import SessionManager

logger = logging.getLogger(__name__)

SNAPSHOT_VERSION = 1

# All set-valued fields on Intelligence, in declaration order.
_INTEL_SET_FIELDS = [
    "bank_accounts", "upi_ids", "phishing_links", "phone_numbers",
    "suspicious_keywords", "reference_ids", "case_ids", "policy_numbers",
    "order_numbers", "amounts", "emails", "crypto_wallets", "domains",
    "ifsc_codes", "ip_addresses", "usernames", "file_hashes", "endpoints",
]


# ---------- serialisers ----------

def _intel_to_dict(intel: Intelligence) -> dict:
    return {f: sorted(getattr(intel, f)) for f in _INTEL_SET_FIELDS}


def _dict_to_intel(d: dict) -> Intelligence:
    intel = Intelligence()
    for f in _INTEL_SET_FIELDS:
        if f in d:
            getattr(intel, f).update(d[f])
    return intel


def _state_to_dict(state: SessionState) -> dict:
    return {
        "session_id": state.session_id,
        "persona_id": state.persona_id,
        "persona_label": state.persona_label,
        "source_type": state.source_type,
        "event_type": state.event_type,
        "source_identifier": state.source_identifier,
        "event_count": state.event_count,
        "affected_targets": state.affected_targets,
        "scam_detected": state.scam_detected,
        "scam_confidence": state.scam_confidence,
        "scam_category": state.scam_category,
        "scam_triggers": state.scam_triggers,
        "rolling_scam_score": state.rolling_scam_score,
        "last_rule_risk_score": state.last_rule_risk_score,
        "last_behavior_risk_score": state.last_behavior_risk_score,
        "strategy_state": state.strategy_state,
        "language": state.language,
        "language_name": state.language_name,
        "language_confidence": state.language_confidence,
        "languages_seen": state.languages_seen,
        "vernacular_score": state.vernacular_score,
        "agent_turns": state.agent_turns,
        "scammer_messages": state.scammer_messages,
        "created_at": state.created_at,
        "updated_at": state.updated_at,
        "first_scam_timestamp": state.first_scam_timestamp,
        "finalized_timestamp": state.finalized_timestamp,
        "agent_notes": state.agent_notes,
        "finalized": state.finalized,
        "closed": state.closed,
        "final_total_messages_exchanged": state.final_total_messages_exchanged,
        "reply_provider": state.reply_provider,
        "last_llm_extraction_at": state.last_llm_extraction_at,
        "intel": _intel_to_dict(state.intel),
        "transcript": [
            {
                "sender": m.sender,
                "text": m.text,
                "timestamp": m.timestamp,
                "provider": m.provider,
            }
            for m in state.transcript
        ],
    }


def _dict_to_state(d: dict) -> SessionState:
    return SessionState(
        session_id=d["session_id"],
        persona_id=d.get("persona_id", ""),
        persona_label=d.get("persona_label", ""),
        source_type=d.get("source_type", "honeypot"),
        event_type=d.get("event_type", ""),
        source_identifier=d.get("source_identifier", ""),
        event_count=d.get("event_count", 1),
        affected_targets=d.get("affected_targets", 1),
        scam_detected=d.get("scam_detected", False),
        scam_confidence=d.get("scam_confidence", 0.0),
        scam_category=d.get("scam_category", "UNKNOWN"),
        scam_triggers=d.get("scam_triggers", []),
        rolling_scam_score=d.get("rolling_scam_score", 0.0),
        last_rule_risk_score=d.get("last_rule_risk_score", 0.0),
        last_behavior_risk_score=d.get("last_behavior_risk_score", 0.0),
        strategy_state=d.get("strategy_state", "Neutral"),
        language=d.get("language", "en"),
        language_name=d.get("language_name", "English"),
        language_confidence=d.get("language_confidence", 0.0),
        languages_seen=d.get("languages_seen", []),
        vernacular_score=d.get("vernacular_score", 0.0),
        agent_turns=d.get("agent_turns", 0),
        scammer_messages=d.get("scammer_messages", 0),
        created_at=d.get("created_at", time.time()),
        updated_at=d.get("updated_at", time.time()),
        first_scam_timestamp=d.get("first_scam_timestamp"),
        finalized_timestamp=d.get("finalized_timestamp"),
        agent_notes=d.get("agent_notes", ""),
        finalized=d.get("finalized", False),
        closed=d.get("closed", False),
        final_total_messages_exchanged=d.get("final_total_messages_exchanged"),
        reply_provider=d.get("reply_provider", "rules"),
        last_llm_extraction_at=d.get("last_llm_extraction_at"),
        intel=_dict_to_intel(d.get("intel", {})),
        transcript=[
            TranscriptMessage(
                sender=m["sender"],
                text=m["text"],
                timestamp=m["timestamp"],
                provider=m.get("provider"),
            )
            for m in d.get("transcript", [])
        ],
    )


# ---------- public API ----------

def save_snapshot(session_manager: SessionManager, path: str, event_count: int = 0) -> None:
    """Atomically write all live sessions to *path* as JSON."""
    sessions = session_manager.list_sessions()
    data = {
        "version": SNAPSHOT_VERSION,
        "saved_at": time.time(),
        "event_count": event_count,
        "sessions": [_state_to_dict(s) for s in sessions],
    }
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, path)
        logger.info("Snapshot saved: %d sessions → %s", len(sessions), path)
    except Exception as exc:
        logger.warning("Snapshot save failed: %s", exc)
        try:
            os.remove(tmp)
        except OSError:
            pass


def load_snapshot(session_manager: SessionManager, path: str) -> Tuple[int, int]:
    """
    Load sessions from *path* into *session_manager*.

    Returns (sessions_restored, event_count_from_snapshot).
    Silently returns (0, 0) if the file does not exist or is corrupt.
    """
    if not os.path.exists(path):
        return 0, 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        states = [_dict_to_state(d) for d in data.get("sessions", [])]
        loaded = session_manager.bulk_load(states)
        event_count = int(data.get("event_count", 0))
        logger.info("Snapshot loaded: %d/%d sessions from %s", loaded, len(states), path)
        return loaded, event_count
    except Exception as exc:
        logger.warning("Snapshot load failed (%s) — starting fresh", exc)
        return 0, 0
