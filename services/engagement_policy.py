from models.session import SessionState


def should_finalize(state: SessionState) -> bool:
    if state.finalized or not state.scam_detected:
        return False

    actionable_categories = state.intel.actionable_category_count()
    has_high_value = state.intel.has_high_value()
    has_payment_id = bool(state.intel.upi_ids or state.intel.crypto_wallets)

    # Hard stop to avoid never-ending sessions.
    if state.agent_turns >= 12:
        return True

    # If we captured a direct payment identifier, we can wrap up sooner.
    if has_payment_id and actionable_categories >= 2 and state.agent_turns >= 5:
        return True

    # Strong extraction signal (but require more depth so we don't close before getting UPI, etc).
    if actionable_categories >= 3 and state.agent_turns >= 10:
        return True

    # Last resort for very chatty scammers.
    if state.scammer_messages >= 12 and state.agent_turns >= 10:
        return True

    return False
