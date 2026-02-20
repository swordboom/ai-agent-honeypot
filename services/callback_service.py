import hashlib
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional, Union

import requests

from models.session import SessionState
from services.session_manager import SessionManager

logger = logging.getLogger(__name__)


class CallbackService:
    def __init__(
        self,
        *,
        callback_url: str,
        timeout_seconds: int,
        max_attempts: int,
        backoff_base_seconds: int,
        max_workers: int,
        enable_updates: bool,
        max_updates: int,
        session_manager: SessionManager,
    ):
        self._callback_url = callback_url
        self._timeout_seconds = max(1, int(timeout_seconds))
        self._max_attempts = max(1, int(max_attempts))
        self._backoff_base_seconds = max(1, int(backoff_base_seconds))
        self._enable_updates = bool(enable_updates)
        self._max_updates = max(0, int(max_updates))
        self._sessions = session_manager
        self._executor = ThreadPoolExecutor(max_workers=max(1, int(max_workers)))

    def build_payload(self, state: SessionState, total_messages: int) -> Dict[str, Union[str, bool, int, Dict]]:
        return {
            "sessionId": state.session_id,
            "scamDetected": state.scam_detected,
            "totalMessagesExchanged": total_messages,
            "extractedIntelligence": state.intel.to_callback_payload(),
            "agentNotes": state.agent_notes,
        }

    def payload_signature(self, payload: Dict) -> str:
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def should_send(self, state: SessionState, signature: str) -> bool:
        if not state.scam_detected:
            return False
        if not state.finalized:
            return False
        if signature == state.callback_payload_signature:
            return False
        if state.callback_sent and not self._enable_updates:
            return False
        if state.callback_sent and self._enable_updates and state.callback_updates >= self._max_updates:
            return False
        return True

    def send_async(self, state: SessionState, total_messages: int) -> None:
        payload = self.build_payload(state, total_messages)
        signature = self.payload_signature(payload)
        if not self.should_send(state, signature):
            return

        update_mode = state.callback_sent
        self._executor.submit(self._send_with_retry, state.session_id, payload, signature, update_mode)

    def _send_with_retry(self, session_id: str, payload: Dict, signature: str, update_mode: bool) -> None:
        last_error = None
        for attempt in range(1, self._max_attempts + 1):
            state = self._sessions.get(session_id)
            if not state:
                return

            self._sessions.update_callback_state(state, attempts_inc=True, last_error=None)

            try:
                resp = requests.post(
                    self._callback_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=self._timeout_seconds,
                )
                status = int(resp.status_code)
                self._sessions.update_callback_state(state, last_status=status)
                if 200 <= status < 300:
                    self._sessions.update_callback_state(
                        state,
                        sent=True,
                        payload_signature=signature,
                        last_sent_at=time.time(),
                        updates_inc=update_mode,
                        last_error=None,
                    )
                    logger.info("Callback sent for session %s status=%s", session_id, status)
                    return

                last_error = f"non-2xx:{status}"
                self._sessions.update_callback_state(state, last_error=last_error)
            except Exception as exc:
                last_error = str(exc)
                self._sessions.update_callback_state(state, last_error=last_error)

            sleep_for = self._backoff_base_seconds * (2 ** (attempt - 1))
            time.sleep(min(30, sleep_for))

        state = self._sessions.get(session_id)
        if state and last_error:
            self._sessions.update_callback_state(state, last_error=last_error)
