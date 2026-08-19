import re
import time
from typing import Dict, List, Tuple

from agent.llm_clients import model_health_snapshot
from agent.multilingual import LANGUAGE_NAMES
from models.dashboard import (
    DashboardCountEntry,
    DashboardIncident,
    DashboardIntelCounts,
    DashboardMapPoint,
    DashboardSessionCard,
    DashboardSessionDetail,
    DashboardSummary,
    DashboardTimelinePoint,
    DashboardTranscriptEntry,
)
from services.incident_engine import Incident, declare_incidents, severity_counts, triage_funnel
from services.reporting import action_payload, session_report
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

TIMELINE_BUCKET_SECONDS = 300
TIMELINE_BUCKETS = 12


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
        ipAddresses=len(intel.ip_addresses),
        usernames=len(intel.usernames),
    )


def _to_entries(counts: Dict[str, int]) -> List[DashboardCountEntry]:
    return [
        DashboardCountEntry(label=label, value=value)
        for label, value in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def _incident_model(incident: Incident) -> DashboardIncident:
    return DashboardIncident(
        incidentId=incident.incident_id,
        name=incident.name,
        severity=incident.severity,
        severityScore=incident.severity_score,
        sourceType=incident.source_type,
        scamCategory=incident.scam_category,
        sessionIds=incident.session_ids,
        sessionCount=incident.session_count,
        firstSeen=int(incident.first_seen),
        lastSeen=int(incident.last_seen),
        durationSeconds=incident.duration_seconds,
        sessionsPerMinute=incident.sessions_per_minute,
        sharedIndicators=incident.shared_indicators,
        languages=incident.languages,
        totalMessages=incident.total_messages,
        maxConfidence=incident.max_confidence,
        scoreBreakdown=incident.score_breakdown,
        recommendedAction=incident.recommended_action,
        triage=incident.triage,
        responsePlan=[action_payload(a) for a in incident.response_plan],
    )


class DashboardService:
    def __init__(self, session_manager: SessionManager):
        self._sessions = session_manager

    # --- incidents (Feature 3) -------------------------------------------------

    def incidents(self) -> List[DashboardIncident]:
        return [_incident_model(i) for i in declare_incidents(self._sessions.list_sessions())]

    def _incident_index(self) -> Dict[str, Incident]:
        """session_id -> the incident it belongs to."""
        index: Dict[str, Incident] = {}
        for incident in declare_incidents(self._sessions.list_sessions()):
            for session_id in incident.session_ids:
                index[session_id] = incident
        return index

    # --- summary ---------------------------------------------------------------

    def summary(self, raw_events: int = 0) -> DashboardSummary:
        now_ts = time.time()
        sessions = self._sessions.list_sessions()

        active = 0
        finalized = 0
        scam_sessions = 0
        total_wasted = 0
        total_messages = 0

        categories: Dict[str, int] = {}
        languages: Dict[str, int] = {}
        providers: Dict[str, int] = {}

        all_bank, all_upi, all_links, all_phones = set(), set(), set(), set()
        all_case_ids, all_policy_numbers, all_order_numbers, all_ref = set(), set(), set(), set()
        all_amounts, all_emails, all_crypto, all_domains = set(), set(), set(), set()
        all_ips, all_usernames = set(), set()

        for state in sessions:
            if state.scam_detected and not state.finalized:
                active += 1
            if state.finalized:
                finalized += 1
            if state.scam_detected:
                scam_sessions += 1
                categories[state.scam_category] = categories.get(state.scam_category, 0) + 1

            language_label = LANGUAGE_NAMES.get(state.language, state.language or "Unknown")
            languages[language_label] = languages.get(language_label, 0) + 1
            providers[state.reply_provider or "rules"] = providers.get(state.reply_provider or "rules", 0) + 1

            total_messages += len(state.transcript)
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
            all_ips.update(state.intel.ip_addresses)
            all_usernames.update(state.intel.usernames)

        incidents = declare_incidents(sessions, now=now_ts)
        counts = severity_counts(incidents)

        return DashboardSummary(
            activeEngagements=active,
            totalSessions=len(sessions),
            finalizedSessions=finalized,
            scamSessions=scam_sessions,
            totalScammerTimeWastedSeconds=total_wasted,
            totalMessages=total_messages,
            severityCounts=counts,
            openIncidents=sum(1 for i in incidents if i.session_count and not self._all_finalized(i)),
            topSeverity=incidents[0].severity if incidents else "LOW",
            triageFunnel=triage_funnel(raw_events or total_messages, len(sessions), incidents),
            categoryBreakdown=_to_entries(categories),
            languageBreakdown=_to_entries(languages),
            providerBreakdown=_to_entries(providers),
            timeline=self._timeline(sessions, now_ts),
            llmModelHealth=model_health_snapshot(),
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
                ipAddresses=len(all_ips),
                usernames=len(all_usernames),
            ),
        )

    def _all_finalized(self, incident: Incident) -> bool:
        return all(
            (self._sessions.get(sid).finalized if self._sessions.get(sid) else True)
            for sid in incident.session_ids
        )

    def _timeline(self, sessions, now_ts: float) -> List[DashboardTimelinePoint]:
        """Sessions and messages per 5-minute bucket over the last hour."""
        newest_bucket = int(now_ts // TIMELINE_BUCKET_SECONDS) * TIMELINE_BUCKET_SECONDS
        buckets = [newest_bucket - (i * TIMELINE_BUCKET_SECONDS) for i in range(TIMELINE_BUCKETS - 1, -1, -1)]
        session_counts = {b: 0 for b in buckets}
        message_counts = {b: 0 for b in buckets}
        oldest = buckets[0]

        for state in sessions:
            started = state.first_scam_timestamp or state.created_at
            bucket = int(started // TIMELINE_BUCKET_SECONDS) * TIMELINE_BUCKET_SECONDS
            if bucket in session_counts:
                session_counts[bucket] += 1
            elif started < oldest:
                session_counts[oldest] += 1

            for msg in state.transcript:
                ts = _message_seconds(msg.timestamp, state.updated_at)
                mbucket = int(ts // TIMELINE_BUCKET_SECONDS) * TIMELINE_BUCKET_SECONDS
                if mbucket in message_counts:
                    message_counts[mbucket] += 1
                elif ts < oldest:
                    message_counts[oldest] += 1

        return [
            DashboardTimelinePoint(bucketStart=b, sessions=session_counts[b], messages=message_counts[b])
            for b in buckets
        ]

    # --- sessions --------------------------------------------------------------

    def list_sessions(self, limit: int) -> List[DashboardSessionCard]:
        sessions = sorted(self._sessions.list_sessions(), key=lambda item: item.updated_at, reverse=True)
        index = self._incident_index()
        cards = []
        for state in sessions[:limit]:
            incident = index.get(state.session_id)
            cards.append(
                DashboardSessionCard(
                    sessionId=state.session_id,
                    persona=state.persona_label,
                    sourceType=state.source_type,
                    scamDetected=state.scam_detected,
                    scamCategory=state.scam_category,
                    scamConfidence=state.scam_confidence,
                    rollingScamScore=state.rolling_scam_score,
                    strategyState=state.strategy_state,
                    engagementComplete=state.finalized,
                    replyProvider=state.reply_provider,
                    messageCount=len(state.transcript),
                    lastUpdated=int(state.updated_at),
                    language=state.language,
                    languageName=state.language_name,
                    incidentId=incident.incident_id if incident else None,
                    incidentSeverity=incident.severity if incident else None,
                    intelCounts=_intel_counts(state.intel),
                )
            )
        return cards

    def session_detail(self, session_id: str) -> DashboardSessionDetail:
        state = self._sessions.get(session_id)
        if not state:
            raise KeyError("Session not found")

        now_ts = time.time()
        incident = self._incident_index().get(session_id)
        return DashboardSessionDetail(
            sessionId=state.session_id,
            personaId=state.persona_id,
            persona=state.persona_label,
            sourceType=state.source_type,
            scamDetected=state.scam_detected,
            scamCategory=state.scam_category,
            scamConfidence=state.scam_confidence,
            rollingScamScore=state.rolling_scam_score,
            strategyState=state.strategy_state,
            scamTriggers=state.scam_triggers,
            engagementComplete=state.finalized,
            replyProvider=state.reply_provider,
            totalMessages=len(state.transcript),
            timeWastedSeconds=_session_time_wasted_seconds(
                state.first_scam_timestamp,
                state.finalized_timestamp,
                state.updated_at,
                now_ts,
            ),
            language=state.language,
            languageName=state.language_name,
            languageConfidence=state.language_confidence,
            languagesSeen=[LANGUAGE_NAMES.get(c, c) for c in state.languages_seen],
            vernacularScore=state.vernacular_score,
            incidentId=incident.incident_id if incident else None,
            incidentName=incident.name if incident else None,
            incidentSeverity=incident.severity if incident else None,
            incidentTriage=incident.triage if incident else None,
            responsePlan=[action_payload(a) for a in incident.response_plan] if incident else [],
            report=session_report(state, incident),
            extractedIntelligence=state.intel.to_indicator_payload(),
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


def _message_seconds(timestamp, fallback: float) -> float:
    """Transcript timestamps arrive as ms ints, second ints, or strings."""
    try:
        value = float(timestamp)
    except (TypeError, ValueError):
        return fallback
    # Anything past year 2286 in seconds is really milliseconds.
    return value / 1000.0 if value > 1e11 else value
