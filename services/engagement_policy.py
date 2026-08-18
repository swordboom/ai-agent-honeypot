import time
import os

from models.session import SessionState


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# Close a session on turn/message thresholds rather than waiting out the duration
# clock, so short bursts do not leave sessions hanging open forever.
FAST_SESSION_CLOSE = _env_bool("FAST_SESSION_CLOSE", True)


def should_finalize(state: SessionState) -> bool:
    if state.finalized or not state.scam_detected:
        return False

    actionable_categories = state.intel.actionable_category_count()
    has_high_value = state.intel.has_high_value()
    has_payment_id = bool(state.intel.upi_ids or state.intel.crypto_wallets)
    elapsed_seconds = 0
    if state.first_scam_timestamp is not None:
        elapsed_seconds = int(time.time() - state.first_scam_timestamp)
    total_messages = state.scammer_messages + state.agent_turns

    # Hard stop to avoid never-ending sessions.
    if state.agent_turns >= 12:
        return True

    # Fast path for short bursts that hit the turn limit well before 60s.
    if FAST_SESSION_CLOSE:
        if state.agent_turns >= 8 and total_messages >= 12 and actionable_categories >= 2:
            return True
        if state.agent_turns >= 10 and total_messages >= 16 and actionable_categories >= 1:
            return True

    # If we captured a direct payment identifier, we can wrap up sooner.
    if (
        has_payment_id
        and actionable_categories >= 2
        and state.agent_turns >= 5
        and total_messages >= 10
        and elapsed_seconds >= 60
    ):
        return True

    # Strong extraction signal (but require more depth so we don't close before getting UPI, etc).
    if actionable_categories >= 3 and state.agent_turns >= 10 and elapsed_seconds >= 60:
        return True

    # Last resort for very chatty scammers.
    if state.scammer_messages >= 12 and state.agent_turns >= 10 and elapsed_seconds >= 60:
        return True

    return False
