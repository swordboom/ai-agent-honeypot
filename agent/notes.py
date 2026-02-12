from models.session import SessionState


def build_agent_notes(state: SessionState) -> str:
    notes = []

    kw = state.intel.suspicious_keywords
    if "urgent" in kw or "immediately" in kw:
        notes.append("Used urgency tactics")
    if "verify" in kw or "verification" in kw:
        notes.append("Pushed for verification")
    if state.intel.upi_ids:
        notes.append("Requested UPI payment")
    if state.intel.phishing_links:
        notes.append("Shared a link")
    if state.intel.phone_numbers:
        notes.append("Provided phone contact")
    if state.intel.bank_accounts:
        notes.append("Shared account details")
    if state.intel.reference_ids:
        notes.append("Provided reference IDs")
    if state.intel.amounts:
        notes.append("Mentioned specific amounts")
    if state.intel.crypto_wallets:
        notes.append("Mentioned crypto wallets")

    if not notes:
        notes.append("Likely phishing attempt with generic verification language")

    return "; ".join(notes)

