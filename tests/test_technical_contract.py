"""
Phase 1 specification - EXPECTED TO FAIL until technical threat ingestion lands.

This file is written before the implementation on purpose. Every failure below is a
Phase 1 checklist item, in dependency order, and the last one is the whole point:
a honeypot conversation and a technical security event collapsing into ONE incident.

Design decision already made (do not re-litigate in code):
    Cross-source correlation joins on a SHARED INDICATOR STRING - a domain or an
    email address that both sources saw. There is no DNS resolution step and no
    `resolvedIp` field. Union-find joins identical strings; if the two sources never
    utter the same string, they are two incidents, and that is correct.

Run just this file:
    python -m unittest tests.test_technical_contract
"""

import importlib
import os
import time
import unittest

# config prefers HONEY_POT_API_KEY over API_KEY, so both must be pinned or a
# lingering HONEY_POT_API_KEY in the host environment silently wins and every
# authenticated call fails with 401.
os.environ["HONEY_POT_API_KEY"] = "test-api-key"
os.environ["API_KEY"] = "test-api-key"
os.environ["OPENROUTER_API_KEY"] = ""
os.environ["GROQ_API_KEY"] = ""
os.environ["ENABLE_LLM_EXTRACTION"] = "false"

import main  # noqa: E402
from models.session import SessionState, TranscriptMessage  # noqa: E402
from services.incident_engine import declare_incidents  # noqa: E402

API_KEY = "test-api-key"
BASE_TS = 1_700_000_000.0


def _need(module_path: str, attr: str = None):
    """Import a not-yet-written module and fail readably instead of erroring out."""
    try:
        module = importlib.import_module(module_path)
    except ImportError as exc:
        raise AssertionError(f"NOT IMPLEMENTED (Phase 1): {module_path} - {exc}")
    if attr is None:
        return module
    if not hasattr(module, attr):
        raise AssertionError(f"NOT IMPLEMENTED (Phase 1): {module_path}.{attr}")
    return getattr(module, attr)


def _auth_event(event_id, ip, users, failures, offset=0, succeeded=False, domain=None):
    """The TechnicalEvent shape this design commits to."""
    TechnicalEvent = _need("models.technical", "TechnicalEvent")
    indicators = {"ip": [ip], "user": list(users)}
    if domain:
        indicators["domain"] = [domain]
    return TechnicalEvent(
        eventId=event_id,
        timestamp=BASE_TS + offset,
        eventType="AUTH_FAILURE_BURST",
        sourceIdentifier=ip,
        targetIdentifiers=list(users),
        indicators=indicators,
        count=failures,
        confidence=0.9,
        detectionSource="auth-log-simulator",
        succeededAfterFailures=succeeded,
    )


class TechnicalIngestContract(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        main.session_manager.clear()

    # --- step 2: the data model stays backward compatible ---------------------

    def test_existing_session_state_defaults_to_the_honeypot_source(self):
        state = SessionState(session_id="s", persona_id="p", persona_label="P")
        self.assertEqual(
            getattr(state, "source_type", None),
            "honeypot",
            "SessionState.source_type must default to 'honeypot' so every existing "
            "session and test keeps working untouched",
        )

    def test_intelligence_carries_technical_indicator_sets(self):
        from models.session import Intelligence

        intel = Intelligence()
        for field in ("ip_addresses", "usernames", "file_hashes", "endpoints"):
            self.assertTrue(hasattr(intel, field), f"Intelligence.{field} missing")

    # --- step 4: vocabulary, not logic ----------------------------------------

    def test_usernames_do_not_collide_with_bank_accounts(self):
        """`account:` already means 'bank account'. A login name must not reuse it,
        or a mule account and a username silently merge into one incident."""
        from services.incident_engine import _session_indicators

        state = SessionState(session_id="s", persona_id="p", persona_label="P")
        state.intel.bank_accounts.add("50100234567890")
        if not hasattr(state.intel, "usernames"):
            raise AssertionError("NOT IMPLEMENTED (Phase 1): Intelligence.usernames")
        state.intel.usernames.add("admin.finance")

        kinds = {i.split(":", 1)[0] for i in _session_indicators(state)}
        self.assertIn("user", kinds, "usernames must be emitted under the `user:` prefix")
        self.assertEqual(
            [i for i in _session_indicators(state) if i.startswith("account:")],
            ["account:50100234567890"],
            "`account:` must remain bank-accounts-only",
        )

    # --- steps 5-7: ingest ----------------------------------------------------

    async def test_ingest_accepts_a_mixed_batch_through_the_existing_endpoint(self):
        """One door. No /api/ingest/technical, or the funnel accounting forks."""
        from models.api import Message, MessageEvent

        batch = main.IngestBatch(
            events=[
                MessageEvent(
                    sessionId="mixed-chat",
                    message=Message(sender="scammer", text="Share OTP to unblock your account", timestamp=1),
                ),
                _auth_event("mixed-tech", "203.0.113.9", ["a.sharma"], failures=40),
            ]
        )
        result = await main.ingest_batch(batch, x_api_key=API_KEY)
        self.assertEqual(result["accepted"], 2, result)
        self.assertEqual(result["failed"], [])

    async def test_technical_ingest_never_enters_the_engagement_path(self):
        """A firewall event does not deserve a persona reply, and 500 of them must
        not become 500 LLM calls. Also: it finalizes at once, so it does not sit in
        `activeEngagements` until the 6h TTL."""
        batch = main.IngestBatch(events=[_auth_event("tech-only", "203.0.113.9", ["a.sharma"], failures=40)])
        await main.ingest_batch(batch, x_api_key=API_KEY)

        tracks = [s for s in main.session_manager.list_sessions() if getattr(s, "source_type", "") == "technical"]
        self.assertEqual(len(tracks), 1, "technical event must produce exactly one track")
        track = tracks[0]
        self.assertEqual(track.transcript, [], "no conversation was had")
        self.assertEqual(track.agent_turns, 0, "no reply was generated")
        self.assertTrue(track.finalized, "technical tracks finalize on ingest")

    # --- step 5: detection ----------------------------------------------------

    def test_brute_force_threshold_and_benign_control(self):
        classify = _need("services.technical_detector", "classify")

        burst = classify(event_type="AUTH_FAILURE_BURST", count=40, distinct_targets=12, succeeded=True)
        self.assertTrue(burst.is_threat)
        self.assertEqual(burst.category, "CREDENTIAL_STUFFING")

        quiet = classify(event_type="AUTH_FAILURE_BURST", count=3, distinct_targets=1, succeeded=False)
        self.assertFalse(quiet.is_threat, "three failed logins by one user is a Monday, not an incident")

    async def test_benign_failed_logins_declare_no_incident(self):
        batch = main.IngestBatch(events=[_auth_event("benign", "198.51.100.4", ["r.iyer"], failures=3)])
        await main.ingest_batch(batch, x_api_key=API_KEY)
        self.assertEqual(declare_incidents(main.session_manager.list_sessions()), [])

    # --- correlation ----------------------------------------------------------

    async def test_password_spray_from_many_ips_is_one_incident(self):
        """Reverse fan-out: 30 sources, one target. Union-find should collapse them
        on the shared `user:` key with no new correlation logic."""
        events = [
            _auth_event(f"spray-{i}", f"203.0.113.{i}", ["a.sharma"], failures=20, offset=i * 2)
            for i in range(1, 31)
        ]
        await main.ingest_batch(main.IngestBatch(events=events), x_api_key=API_KEY)

        incidents = declare_incidents(main.session_manager.list_sessions())
        self.assertEqual(len(incidents), 1, [i.name for i in incidents])
        self.assertGreaterEqual(incidents[0].session_count, 30)

    async def test_unrelated_technical_events_stay_separate(self):
        events = [
            _auth_event("sep-1", "203.0.113.9", ["a.sharma"], failures=40),
            _auth_event("sep-2", "198.51.100.7", ["v.rao"], failures=40, offset=5),
        ]
        await main.ingest_batch(main.IngestBatch(events=events), x_api_key=API_KEY)
        self.assertEqual(len(declare_incidents(main.session_manager.list_sessions())), 2)

    # --- severity must describe the attack, not the feed ----------------------

    async def test_severity_is_independent_of_how_the_feed_batches(self):
        """The same 50 attempts against the same 12 accounts, delivered as one event or
        as five, is the same attack. Scoring breadth off row count made severity a
        property of the sender's batching policy."""
        users = [f"user{i}" for i in range(12)]

        main.session_manager.clear()
        await main.ingest_batch(
            main.IngestBatch(events=[_auth_event("one-shot", "203.0.113.9", users, 50, succeeded=True)]),
            x_api_key=API_KEY,
        )
        one_shot = declare_incidents(main.session_manager.list_sessions())[0]

        main.session_manager.clear()
        await main.ingest_batch(
            main.IngestBatch(
                events=[
                    _auth_event(f"batched-{i}", "203.0.113.9", users, 10, offset=i, succeeded=True)
                    for i in range(5)
                ]
            ),
            x_api_key=API_KEY,
        )
        batched = declare_incidents(main.session_manager.list_sessions())[0]

        self.assertEqual(one_shot.severity, batched.severity)
        self.assertEqual(one_shot.score_breakdown["breadth"], batched.score_breakdown["breadth"])
        self.assertEqual(one_shot.score_breakdown["velocity"], batched.score_breakdown["velocity"])

    async def test_a_bigger_attack_outranks_a_smaller_one_in_the_same_batch_shape(self):
        """Both arrive as a single event, so only the reported magnitudes differ."""
        main.session_manager.clear()
        await main.ingest_batch(
            main.IngestBatch(
                events=[
                    _auth_event("big", "203.0.113.9", [f"user{i}" for i in range(12)], 50, succeeded=True),
                    # 25 failures clears the brute-force bar; 12 accounts and a success do not apply.
                    _auth_event("small", "198.51.100.7", ["r.iyer", "s.mehta"], 25),
                ]
            ),
            x_api_key=API_KEY,
        )
        by_id = {i.session_ids[0]: i for i in declare_incidents(main.session_manager.list_sessions())}
        self.assertGreater(by_id["big"].severity_score, by_id["small"].severity_score)

    # --- the one that matters -------------------------------------------------

    async def test_honeypot_and_technical_events_become_one_incident(self):
        """
        Scammer hands the honeypot a phishing domain. The auth feed reports a
        credential attack whose events carry that same domain. One incident, both
        halves of the response plan.
        """
        from models.api import Message, MessageEvent

        phishing_domain = "secure-kyc-verify.tk"

        await main.handle_message(
            MessageEvent(
                sessionId="cross-chat",
                message=Message(
                    sender="scammer",
                    text=f"Urgent: verify your KYC at http://{phishing_domain}/login or account will be blocked",
                    timestamp=1,
                ),
            ),
            x_api_key=API_KEY,
        )
        await main.ingest_batch(
            main.IngestBatch(
                events=[
                    _auth_event("cross-tech", "203.0.113.9", ["a.sharma", "v.rao"], 40, domain=phishing_domain)
                ]
            ),
            x_api_key=API_KEY,
        )

        incidents = declare_incidents(main.session_manager.list_sessions())
        self.assertEqual(len(incidents), 1, f"expected one correlated incident, got {[i.name for i in incidents]}")
        incident = incidents[0]

        self.assertIn("cross-chat", incident.session_ids)
        self.assertIn("cross-tech", incident.session_ids)
        self.assertIn(f"domain:{phishing_domain}", incident.shared_indicators)
        self.assertIn("ip:203.0.113.9", incident.shared_indicators)
        self.assertEqual(getattr(incident, "source_type", None), "Mixed")

        actions = {a.action for a in incident.response_plan}
        self.assertIn("BLOCK_AND_TAKEDOWN_DOMAIN", actions)
        self.assertIn("BLOCK_SOURCE_IP", actions)
        self.assertIn("LOCK_ACCOUNT_AND_FORCE_RESET", actions)

    # --- step 8: the simulator is shared, not duplicated into JS --------------

    def test_simulator_exposes_the_four_scenarios(self):
        build = _need("simulator.technical_events", "build")
        for name in ("credential_stuffing", "password_spray", "benign_failures", "cross_source"):
            events = build(name)
            self.assertTrue(events, f"scenario {name} produced no events")

    # --- step 9: reporting stays backward compatible --------------------------

    def test_report_schema_is_additive(self):
        from services import reporting

        self.assertEqual(reporting.SCHEMA_VERSION, "honeypot-report/1.1")

        state = SessionState(session_id="s1", persona_id="retired_teacher", persona_label="Arthur")
        state.scam_detected = True
        state.scam_category = "UPI_FRAUD"
        state.first_scam_timestamp = time.time() - 60
        state.intel.upi_ids.add("mule@ybl")
        state.transcript.append(TranscriptMessage(sender="scammer", text="pay", timestamp=1))

        report = reporting.session_report(state, declare_incidents([state])[0])
        # Every 1.0 key survives.
        for key in ("detection", "language", "engagement", "indicators", "extendedIndicators", "incident"):
            self.assertIn(key, report)
        self.assertEqual(report["sourceType"], "honeypot")


if __name__ == "__main__":
    unittest.main()
