import threading
import time
from typing import Dict, Iterable, List, Optional

from models.api import Message
from models.session import SessionState, TranscriptMessage


class SessionManager:
    def __init__(self, session_ttl_seconds: int, cleanup_interval_seconds: int):
        self._sessions: Dict[str, SessionState] = {}
        self._lock = threading.Lock()
        self._ttl_seconds = max(60, int(session_ttl_seconds))
        self._cleanup_interval_seconds = max(5, int(cleanup_interval_seconds))
        self._last_cleanup_at = 0.0

    def maybe_cleanup(self) -> int:
        now = time.time()
        if (now - self._last_cleanup_at) < self._cleanup_interval_seconds:
            return 0

        with self._lock:
            self._last_cleanup_at = now
            expired = []
            for session_id, state in self._sessions.items():
                if (now - state.updated_at) > self._ttl_seconds:
                    expired.append(session_id)
            for session_id in expired:
                del self._sessions[session_id]
            return len(expired)

    def clear(self) -> int:
        with self._lock:
            count = len(self._sessions)
            self._sessions.clear()
            return count

    def get(self, session_id: str) -> Optional[SessionState]:
        with self._lock:
            return self._sessions.get(session_id)

    def get_or_create(self, session_id: str, state_factory) -> SessionState:
        with self._lock:
            existing = self._sessions.get(session_id)
            if existing:
                return existing
            state = state_factory(session_id)
            self._sessions[session_id] = state
            return state

    def list_sessions(self) -> List[SessionState]:
        with self._lock:
            return list(self._sessions.values())

    def seed_history_if_needed(self, state: SessionState, history: Iterable[Message]) -> None:
        with self._lock:
            if state.transcript:
                return
            for msg in history:
                self._append_transcript_unlocked(state, msg.sender, msg.text, msg.timestamp, provider=None)

    def append_transcript(
        self,
        state: SessionState,
        sender: str,
        text: str,
        timestamp,
        provider: Optional[str] = None,
    ) -> None:
        with self._lock:
            self._append_transcript_unlocked(state, sender, text, timestamp, provider)

    def _append_transcript_unlocked(
        self,
        state: SessionState,
        sender: str,
        text: str,
        timestamp,
        provider: Optional[str],
    ) -> None:
        if not text:
            return
        entry = TranscriptMessage(
            sender=sender,
            text=text,
            timestamp=timestamp if timestamp is not None else int(time.time() * 1000),
            provider=provider,
        )
        if state.transcript:
            last = state.transcript[-1]
            if (
                last.sender == entry.sender
                and last.text == entry.text
                and str(last.timestamp) == str(entry.timestamp)
            ):
                return
        state.transcript.append(entry)
        state.updated_at = time.time()

    def update_detection(
        self,
        state: SessionState,
        is_scam: bool,
        confidence: float,
        category: str,
        triggers: List[str],
        suspicious_keywords: List[str],
        rolling_score: float,
        rule_score: float,
        behavior_score: float,
        strategy_state: str,
    ) -> None:
        with self._lock:
            if is_scam and not state.scam_detected:
                state.first_scam_timestamp = time.time()
            if is_scam:
                state.scam_detected = True
            state.scam_confidence = max(state.scam_confidence, confidence)
            state.scam_category = category if category and category != "UNKNOWN" else state.scam_category
            state.scam_triggers = sorted(set(state.scam_triggers).union(triggers))
            state.intel.suspicious_keywords.update(suspicious_keywords)
            state.rolling_scam_score = round(max(state.rolling_scam_score, rolling_score), 2)
            state.last_rule_risk_score = round(rule_score, 2)
            state.last_behavior_risk_score = round(behavior_score, 2)
            state.strategy_state = strategy_state
            state.updated_at = time.time()

    def update_language(
        self,
        state: SessionState,
        code: str,
        name: str,
        confidence: float,
        vernacular_score: float,
    ) -> None:
        with self._lock:
            if code and code != "unknown":
                # Keep the strongest non-English read: scammers open in English and
                # switch to vernacular once the target engages.
                stronger = confidence > state.language_confidence
                upgrade_from_english = state.language in {"en", "unknown"} and code != "en"
                if stronger or upgrade_from_english:
                    state.language = code
                    state.language_name = name
                    state.language_confidence = round(confidence, 2)
                if code not in state.languages_seen:
                    state.languages_seen.append(code)
            state.vernacular_score = round(max(state.vernacular_score, vernacular_score), 2)
            state.updated_at = time.time()

    def increment_scammer_message(self, state: SessionState) -> None:
        with self._lock:
            state.scammer_messages += 1
            state.updated_at = time.time()

    def increment_agent_turn(self, state: SessionState) -> None:
        with self._lock:
            state.agent_turns += 1
            state.updated_at = time.time()

    def set_reply_provider(self, state: SessionState, provider: str) -> None:
        with self._lock:
            state.reply_provider = provider
            state.updated_at = time.time()

    def set_strategy_state(self, state: SessionState, strategy_state: str) -> None:
        with self._lock:
            state.strategy_state = strategy_state
            state.updated_at = time.time()

    def mark_finalized(self, state: SessionState) -> None:
        with self._lock:
            if not state.finalized:
                state.finalized = True
                state.finalized_timestamp = time.time()
            state.updated_at = time.time()

    def close_session(self, state: SessionState) -> None:
        with self._lock:
            state.closed = True
            state.updated_at = time.time()

    def update_agent_notes(self, state: SessionState, notes: str) -> None:
        with self._lock:
            state.agent_notes = notes
            state.updated_at = time.time()

    def update_intel(self, state: SessionState, mutator) -> None:
        """
        Thread-safe mutation hook for state.intel (sets are not thread-safe).
        """
        with self._lock:
            mutator(state.intel)
            state.updated_at = time.time()

    def finalize_and_close(self, state: SessionState, notes: str, total_messages: Optional[int] = None) -> None:
        with self._lock:
            if not state.finalized:
                state.finalized = True
                state.finalized_timestamp = time.time()
            state.agent_notes = notes
            state.closed = True
            if total_messages is not None and state.final_total_messages_exchanged is None:
                state.final_total_messages_exchanged = int(total_messages)
            state.updated_at = time.time()

    def update_llm_extraction_time(self, state: SessionState) -> None:
        with self._lock:
            state.last_llm_extraction_at = time.time()
            state.updated_at = time.time()

