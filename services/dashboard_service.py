import re
import time
from typing import Dict, List, Tuple

from models.dashboard import (
    DashboardIntelCounts,
    DashboardMapPoint,
    DashboardSessionCard,
    DashboardSessionDetail,
    DashboardSummary,
    DashboardTranscriptEntry,
)
from services.session_manager import SessionManager


COUNTRY_PREFIXES: Dict[str, Tuple[str, str]] = {
    "91": ("IN", "India"),
    "1": ("US", "United States"),
    "44": ("GB", "United Kingdom"),
    "61": ("AU", "Australia"),
    "65": ("SG", "Singapore"),
    "880": ("BD", "Bangladesh"),
    "92": ("PK", "Pakistan"),
    "94": ("LK", "Sri Lanka"),
    "971": ("AE", "United Arab Emirates"),
}


def _get_country_from_phone(phone: str) -> Tuple[str, str]:
    digits = re.sub(r"\D", "", phone)
    if len(digits) == 10:
        return COUNTRY_PREFIXES["91"]
    for prefix in sorted(COUNTRY_PREFIXES.keys(), key=len, reverse=True):
        if digits.startswith(prefix):
            return COUNTRY_PREFIXES[prefix]
    return "UN", "Unknown"


def _session_time_wasted_seconds(first_scam_timestamp, finalized_timestamp, updated_at, now_ts: float) -> int:
    if first_scam_timestamp is None:
        return 0
    start = first_scam_timestamp or updated_at
    # For non-finalized sessions, use last activity time instead of wall clock time.
    # This prevents "time wasted" from increasing while no messages are exchanged.
    end = finalized_timestamp or updated_at
    return max(0, int(end - start))


def _final_output_payload(state, now_ts: float) -> Dict[str, object]:
    duration = _session_time_wasted_seconds(
        state.first_scam_timestamp,
        state.finalized_timestamp,
        state.updated_at,
        now_ts,
    )
    total_messages = state.final_total_messages_exchanged or len(state.transcript)
    return {
        "sessionId": state.session_id,
        "status": "completed" if state.finalized else "in_progress",
        "scamDetected": state.scam_detected,
        "scamType": state.scam_category,
        "confidenceLevel": round(min(1.0, max(0.0, state.scam_confidence)), 2),
        "extractedIntelligence": state.intel.to_callback_payload(),
        "totalMessagesExchanged": total_messages,
        "engagementDurationSeconds": duration,
        "engagementMetrics": {
            "totalMessagesExchanged": total_messages,
            "engagementDurationSeconds": duration,
        },
        "agentNotes": state.agent_notes,
    }


def _intel_counts(intel) -> DashboardIntelCounts:
    return DashboardIntelCounts(
        bankAccounts=len(intel.bank_accounts),
        upiIds=len(intel.upi_ids),
        phishingLinks=len(intel.phishing_links),
        phoneNumbers=len(intel.phone_numbers),
        emailAddresses=len(intel.emails),
        caseIds=len(intel.case_ids.union(intel.reference_ids)),
        policyNumbers=len(intel.policy_numbers),
        orderNumbers=len(intel.order_numbers),
        referenceIds=len(intel.reference_ids),
        amounts=len(intel.amounts),
        emails=len(intel.emails),
        cryptoWallets=len(intel.crypto_wallets),
        domains=len(intel.domains),
    )


class DashboardService:
    def __init__(self, session_manager: SessionManager):
        self._sessions = session_manager

    def summary(self) -> DashboardSummary:
        now_ts = time.time()
        sessions = self._sessions.list_sessions()

        active = 0
        finalized = 0
        total_wasted = 0

        all_bank = set()
        all_upi = set()
        all_links = set()
        all_phones = set()
        all_case_ids = set()
        all_policy_numbers = set()
        all_order_numbers = set()
        all_ref = set()
        all_amounts = set()
        all_emails = set()
        all_crypto = set()
        all_domains = set()

        for state in sessions:
            if state.scam_detected and not state.finalized:
                active += 1
            if state.finalized:
                finalized += 1

            total_wasted += _session_time_wasted_seconds(
                state.first_scam_timestamp,
                state.finalized_timestamp,
                state.updated_at,
                now_ts,
            )

            all_bank.update(state.intel.bank_accounts)
            all_upi.update(state.intel.upi_ids)
            all_links.update(state.intel.phishing_links)
            all_phones.update(state.intel.phone_numbers)
            all_case_ids.update(state.intel.case_ids)
            all_policy_numbers.update(state.intel.policy_numbers)
            all_order_numbers.update(state.intel.order_numbers)
            all_ref.update(state.intel.reference_ids)
            all_amounts.update(state.intel.amounts)
            all_emails.update(state.intel.emails)
            all_crypto.update(state.intel.crypto_wallets)
            all_domains.update(state.intel.domains)

        return DashboardSummary(
            activeEngagements=active,
            totalSessions=len(sessions),
            finalizedSessions=finalized,
            totalScammerTimeWastedSeconds=total_wasted,
            totalExtracted=DashboardIntelCounts(
                bankAccounts=len(all_bank),
                upiIds=len(all_upi),
                phishingLinks=len(all_links),
                phoneNumbers=len(all_phones),
                emailAddresses=len(all_emails),
                caseIds=len(all_case_ids.union(all_ref)),
                policyNumbers=len(all_policy_numbers),
                orderNumbers=len(all_order_numbers),
                referenceIds=len(all_ref),
                amounts=len(all_amounts),
                emails=len(all_emails),
                cryptoWallets=len(all_crypto),
                domains=len(all_domains),
            ),
        )

    def list_sessions(self, limit: int) -> List[DashboardSessionCard]:
        sessions = sorted(self._sessions.list_sessions(), key=lambda item: item.updated_at, reverse=True)
        cards = []
        for state in sessions[:limit]:
            cards.append(
                DashboardSessionCard(
                    sessionId=state.session_id,
                    persona=state.persona_label,
                    scamDetected=state.scam_detected,
                    scamCategory=state.scam_category,
                    scamConfidence=state.scam_confidence,
                    rollingScamScore=state.rolling_scam_score,
                    strategyState=state.strategy_state,
                    engagementComplete=state.finalized,
                    replyProvider=state.reply_provider,
                    messageCount=len(state.transcript),
                    lastUpdated=int(state.updated_at),
                    intelCounts=_intel_counts(state.intel),
                )
            )
        return cards

    def session_detail(self, session_id: str) -> DashboardSessionDetail:
        state = self._sessions.get(session_id)
        if not state:
            raise KeyError("Session not found")

        now_ts = time.time()
        return DashboardSessionDetail(
            sessionId=state.session_id,
            personaId=state.persona_id,
            persona=state.persona_label,
            scamDetected=state.scam_detected,
            scamCategory=state.scam_category,
            scamConfidence=state.scam_confidence,
            rollingScamScore=state.rolling_scam_score,
            strategyState=state.strategy_state,
            scamTriggers=state.scam_triggers,
            engagementComplete=state.finalized,
            replyProvider=state.reply_provider,
            callbackSent=state.callback_sent,
            callbackAttempts=state.callback_attempts,
            callbackLastStatus=state.callback_last_status,
            callbackLastError=state.callback_last_error,
            totalMessages=len(state.transcript),
            timeWastedSeconds=_session_time_wasted_seconds(
                state.first_scam_timestamp,
                state.finalized_timestamp,
                state.updated_at,
                now_ts,
            ),
            finalOutput=_final_output_payload(state, now_ts),
            extractedIntelligence=state.intel.to_callback_payload(),
            extendedIntelligence=state.intel.to_extended_payload(),
            transcript=[
                DashboardTranscriptEntry(
                    sender=t.sender,
                    text=t.text,
                    timestamp=t.timestamp,
                    provider=t.provider,
                )
                for t in state.transcript
            ],
        )

    def map_points(self) -> List[DashboardMapPoint]:
        counts: Dict[str, Dict[str, object]] = {}
        for state in self._sessions.list_sessions():
            for phone in state.intel.phone_numbers:
                cc, name = _get_country_from_phone(phone)
                if cc not in counts:
                    counts[cc] = {"countryCode": cc, "countryName": name, "count": 0}
                counts[cc]["count"] = int(counts[cc]["count"]) + 1

        result = [DashboardMapPoint(**row) for row in counts.values()]
        result.sort(key=lambda item: item.count, reverse=True)
        return result
