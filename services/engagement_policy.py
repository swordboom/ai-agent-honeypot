from models.session import SessionState


def should_finalize(state: SessionState) -> bool:
    if state.finalized or not state.scam_detected:
        return False

    actionable_categories = state.intel.actionable_category_count()
    has_high_value = state.intel.has_high_value()

    # Hard stop to avoid never-ending sessions.
    if state.agent_turns >= 10:
        return True

    # Strong extraction signal: multiple actionable categories quickly collected.
    if actionable_categories >= 3 and state.agent_turns >= 3:
        return True

    # Balanced signal: one high-value indicator plus another actionable signal.
    if has_high_value and actionable_categories >= 2 and state.agent_turns >= 5:
        return True

    # Conversation-depth fallback when high-value intel exists.
    if has_high_value and state.scammer_messages >= 5 and state.agent_turns >= 6:
        return True

    return False

