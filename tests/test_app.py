import json
import os
import time
import unittest

from fastapi import HTTPException


# Ensure tests are deterministic and never hit real external services.
# config prefers HONEY_POT_API_KEY over API_KEY, so both must be pinned or a
# lingering HONEY_POT_API_KEY in the host environment silently wins and every
# authenticated call fails with 401.
os.environ["HONEY_POT_API_KEY"] = "test-api-key"
os.environ["API_KEY"] = "test-api-key"
os.environ["OPENROUTER_API_KEY"] = ""
os.environ["ENABLE_LLM_EXTRACTION"] = "false"

import main  # noqa: E402
from agent.intelligence_extractor import extract_intelligence  # noqa: E402
from agent.multilingual import detect_language, scan  # noqa: E402
from agent.personas import assign_persona  # noqa: E402
from agent.reply_agent import generate_agent_reply  # noqa: E402
from agent.scam_detector import ScamDetector  # noqa: E402
from models.api import Message, MessageEvent, Metadata  # noqa: E402
from models.session import Intelligence, SessionState, TranscriptMessage  # noqa: E402
from services.engagement_policy import should_finalize  # noqa: E402
from services.incident_engine import declare_incidents  # noqa: E402
from services.reporting import session_report, threat_report  # noqa: E402


class _DummyLLM:
    """Stands in for OpenRouterClient; records the prompt it was handed."""

    def __init__(self, reply):
        self.api_key = "x"
        self._reply = reply
        self.last_messages = None

    def chat(self, messages, *args, **kwargs):
        self.last_messages = messages
        return self._reply


class HoneypotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        main.session_manager.clear()

    def test_persona_assignment_is_deterministic(self):
        a = assign_persona("session-1").id
        b = assign_persona("session-1").id
        self.assertEqual(a, b)
        ids = {assign_persona(f"session-{i}").id for i in range(20)}
        self.assertGreaterEqual(len(ids), 2)

    def test_intelligence_extraction_upi_not_email(self):
        intel = Intelligence()
        extract_intelligence(
            [
                "Contact support@sbi.com. Pay to scammer.fraud@fakebank ASAP.",
                "Verification link: https://secure-sbi.com/verify?acc=123",
            ],
            intel,
        )
        self.assertIn("support@sbi.com", intel.emails)
        self.assertIn("scammer.fraud@fakebank", intel.upi_ids)
        self.assertNotIn("support@sbi", intel.upi_ids)
        self.assertTrue(any("https://secure-sbi.com/verify" in x for x in intel.phishing_links))

    def test_intelligence_extraction_phone_not_bank(self):
        intel = Intelligence()
        extract_intelligence(
            ["Call +91-9876543210. Account: 1234567890123456 IFSC: SBIN0001234"],
            intel,
        )
        self.assertIn("+919876543210", intel.phone_numbers)
        self.assertIn("1234567890123456", intel.bank_accounts)
        self.assertNotIn("9876543210", intel.bank_accounts)
        self.assertIn("SBIN0001234", intel.ifsc_codes)

    def test_long_account_numbers_are_not_mistaken_for_phone_numbers(self):
        """A 14-digit mule account was being extracted as a phone, so the plan chased a
        number that does not exist and never froze the account."""
        intel = Intelligence()
        extract_intelligence(
            ["Case ID SBI-88911. Call 9812345670 to confirm. Or deposit to 50100234567890, IFSC SBIN0001234."],
            intel,
        )
        self.assertEqual(sorted(intel.phone_numbers), ["+919812345670"])
        self.assertEqual(sorted(intel.bank_accounts), ["50100234567890"])
        self.assertEqual(sorted(intel.ifsc_codes), ["SBIN0001234"])
        # An IFSC is not a case reference; it has its own field.
        self.assertEqual(sorted(intel.case_ids), ["SBI-88911"])

        # A bare 15-digit run stays an account even though it starts with 91.
        other = Intelligence()
        extract_intelligence(["Pay the penalty to 918823456789012 or face arrest. Call +91-9876543210."], other)
        self.assertEqual(sorted(other.phone_numbers), ["+919876543210"])
        self.assertEqual(sorted(other.bank_accounts), ["918823456789012"])

    def test_rule_based_replies_never_reference_things_the_scammer_never_sent(self):
        """`missing_intel_targets` lists what was NEVER captured, so asking the scammer
        to "resend the link" when no link was ever sent is a persona-breaking tell."""
        from agent.reply_agent import generate_rule_based_reply

        state = SessionState(session_id="coherence", persona_id="retired_teacher", persona_label="Arthur")
        state.scam_detected = True
        state.scam_category = "BANK_FRAUD"

        # A scammer who never sends a link, a UPI id, or a URL.
        messages = [
            "Your SBI KYC has expired. Your account will be blocked today. Verify immediately.",
            "Case ID SBI-88911. Call 9812345670 to confirm.",
            "You must complete this before 6pm or the account is frozen.",
            "This is your final reminder from the bank.",
            "Do not ignore this message.",
            "Confirm now to avoid penalty.",
        ]
        presupposing = ("resend the link", "the link again", "send it again", "still cannot open the link")

        for text in messages:
            state.transcript.append(TranscriptMessage(sender="scammer", text=text, timestamp=1))
            reply = generate_rule_based_reply(state)
            lowered = reply.lower()
            for phrase in presupposing:
                self.assertNotIn(phrase, lowered, f"turn {state.agent_turns}: {reply!r}")
            state.transcript.append(TranscriptMessage(sender="user", text=reply, timestamp=2, provider="rules"))
            state.agent_turns += 1

    def test_opening_line_matches_the_detected_category(self):
        """One hardcoded opener asked "which bank is this about?" about parcel seizures
        and lottery wins - the first reply is the one most likely to blow the persona."""
        from agent.reply_agent import generate_rule_based_reply

        def opener(category):
            state = SessionState(session_id=f"open-{category}", persona_id="retired_teacher", persona_label="A")
            state.scam_detected = True
            state.scam_category = category
            state.transcript.append(TranscriptMessage(sender="scammer", text="hello", timestamp=1))
            return generate_rule_based_reply(state).lower()

        self.assertIn("bank", opener("BANK_FRAUD"))
        self.assertIn("lottery", opener("LOTTERY_SCAM"))
        self.assertIn("department", opener("DIGITAL_ARREST"))
        self.assertIn("refund", opener("REFUND_SCAM"))
        self.assertIn("invested", opener("CRYPTO_SCAM"))

        # Nothing that is not about a bank should ask which bank it is.
        for category in ("LOTTERY_SCAM", "DIGITAL_ARREST", "REFUND_SCAM", "CRYPTO_SCAM", "UPI_FRAUD"):
            self.assertNotIn("which bank", opener(category), category)

    def test_crypto_investment_lure_is_detected(self):
        """A wallet address was extracted but the message scored 1/10, so no incident was
        declared and FLAG_CRYPTO_WALLET never fired."""
        detector = ScamDetector()
        lure = detector.detect(
            "Bitcoin doubling scheme closing today. Send 0.01 BTC to "
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq for guaranteed 2x."
        )
        self.assertTrue(lure.is_scam)
        self.assertEqual(lure.category, "CRYPTO_SCAM")
        self.assertIn("wallet", lure.triggers)

        # Merely mentioning bitcoin is not a scam.
        self.assertFalse(detector.detect("I bought some bitcoin last year and it did well.").is_scam)

    def test_agent_reply_uses_openrouter_then_falls_back_to_rules(self):
        state = SessionState(session_id="s1", persona_id="retired_teacher", persona_label="Arthur")
        state.scam_detected = True
        state.transcript.append(TranscriptMessage(sender="scammer", text="Share your UPI ID.", timestamp=1))

        reply, provider = generate_agent_reply(
            state,
            Metadata(channel="SMS", language="English", locale="IN"),
            llm=_DummyLLM("ok"),
            max_history=12,
        )
        self.assertEqual(provider, "openrouter")
        self.assertTrue(reply)

        # No key / every free model exhausted -> deterministic reply, never silence.
        reply, provider = generate_agent_reply(state, None, llm=_DummyLLM(None), max_history=12)
        self.assertEqual(provider, "rules")
        self.assertTrue(reply)

        reply, provider = generate_agent_reply(state, None, llm=None, max_history=12)
        self.assertEqual(provider, "rules")
        self.assertTrue(reply)

    def test_openrouter_client_falls_through_model_chain(self):
        from agent.llm_clients import OpenRouterClient

        calls = []

        class _Response:
            def __init__(self, status_code, payload=None, text=""):
                self.status_code = status_code
                self._payload = payload
                self.text = text

            def json(self):
                return self._payload

        def fake_post(url, headers=None, json=None, timeout=None):
            calls.append(json["model"])
            if json["model"] == "bad/model:free":
                return _Response(429, text="rate limited")
            return _Response(200, {"choices": [{"message": {"content": "hi"}}]})

        import agent.llm_clients as llm_clients

        original = llm_clients.requests.post
        llm_clients.requests.post = fake_post
        try:
            client = OpenRouterClient(
                api_key="k",
                models=("bad/model:free", "good/model:free"),
                timeout_seconds=1,
            )
            self.assertEqual(client.chat([{"role": "user", "content": "x"}], 0.5, 20), "hi")
            self.assertEqual(calls, ["bad/model:free", "good/model:free"])
        finally:
            llm_clients.requests.post = original

    def test_daily_quota_stops_walking_the_whole_model_chain(self):
        """OpenRouter's free tier caps requests per DAY per account, so once it trips
        every slug 429s. Walking all nine costs nine round-trips per reply for nothing."""
        import agent.llm_clients as llm_clients

        class _Response:
            def __init__(self, status_code, text="", headers=None):
                self.status_code, self.text, self.headers = status_code, text, headers or {}

            def json(self):
                return {"choices": [{"message": {"content": "hi"}}]}

        calls = []
        daily = '{"error":{"message":"Rate limit exceeded: free-models-per-day"}}'

        original_post, original_health = llm_clients.requests.post, llm_clients._health
        llm_clients._health = llm_clients._ModelHealth()
        llm_clients.requests.post = lambda url, headers=None, json=None, timeout=None: (
            calls.append(json["model"]) or _Response(429, daily)
        )
        try:
            client = llm_clients.OpenRouterClient(
                api_key="k", models=tuple(f"m{i}/x:free" for i in range(9)), timeout_seconds=1
            )
            self.assertIsNone(client.chat([{"role": "user", "content": "x"}], 0.5, 20))
            self.assertEqual(len(calls), 1, "must stop at the first daily-cap 429")

            # Subsequent replies do not touch the network at all until it resets.
            self.assertIsNone(client.chat([{"role": "user", "content": "x"}], 0.5, 20))
            self.assertEqual(len(calls), 1, calls)
            self.assertGreater(llm_clients.model_health_snapshot()["chainBlockedSeconds"], 0)
        finally:
            llm_clients.requests.post, llm_clients._health = original_post, original_health

    # --- Feature 11: multi-language ------------------------------------------

    def test_vernacular_scam_scores_like_its_english_twin(self):
        detector = ScamDetector()
        english = detector.detect("Your account will be blocked, send OTP immediately")
        romanized = detector.detect("aapka account band ho jayega, turant otp bhejo")
        native = detector.detect("आपका खाता बंद हो जाएगा, तुरंत ओटीपी भेजें")

        for result in (english, romanized, native):
            self.assertTrue(result.is_scam, result)

        self.assertEqual(romanized.language, "hi")
        self.assertEqual(native.language, "hi")
        self.assertEqual(english.language, "en")
        self.assertGreater(romanized.vernacular_score, 0)
        self.assertGreaterEqual(native.score, english.score - 4)

    def test_language_detection_across_indian_languages(self):
        cases = {
            "hi": "आपका खाता बंद हो जाएगा",
            "bn": "আপনার অ্যাকাউন্ট বন্ধ হয়ে যাবে",
            "ta": "உங்கள் கணக்கு முடக்கப்படும்",
            "te": "మీ ఖాతా బ్లాక్ అవుతుంది",
            "mr": "तुमचे खाते बंद होईल, ताबडतोब पाठवा",
            "en": "Your account will be blocked",
        }
        for expected, text in cases.items():
            self.assertEqual(detect_language(text).code, expected, text)

    def test_english_business_text_is_not_flagged_as_vernacular(self):
        self.assertEqual(scan("Please send the quarterly report by Friday").score, 0)

    async def test_session_records_scammer_language_and_prompts_in_it(self):
        event = MessageEvent(
            sessionId="hindi-session",
            message=Message(sender="scammer", text="aapka account band ho jayega, turant otp bhejo", timestamp=1),
            conversationHistory=[],
            metadata=Metadata(channel="SMS", language="Hindi", locale="IN"),
        )
        await main.handle_message(event, x_api_key="test-api-key")

        state = main.session_manager.get("hindi-session")
        self.assertEqual(state.language, "hi")
        self.assertEqual(state.language_name, "Hindi")
        self.assertIn("hi", state.languages_seen)

        # The reply prompt must instruct the model to answer in Hindi.
        dummy = _DummyLLM("theek hai")
        generate_agent_reply(state, None, llm=dummy, max_history=12)
        self.assertIn("Hindi", dummy.last_messages[0]["content"])

        # And the no-LLM path must not answer a Hindi scammer in English.
        fallback, provider = generate_agent_reply(state, None, llm=None, max_history=12)
        self.assertEqual(provider, "rules")
        self.assertTrue(any("ऀ" <= ch <= "ॿ" for ch in fallback), fallback)

    # --- Feature 3: incidents -------------------------------------------------

    def test_related_sessions_declare_one_incident_with_severity(self):
        def make(sid, upi):
            state = SessionState(session_id=sid, persona_id="p", persona_label="P")
            state.scam_detected = True
            state.scam_category = "UPI_FRAUD"
            state.scam_confidence = 0.9
            state.first_scam_timestamp = time.time() - 60
            state.updated_at = time.time()
            state.intel.upi_ids.add(upi)
            state.transcript.append(TranscriptMessage(sender="scammer", text="pay", timestamp=1))
            return state

        incidents = declare_incidents([make("a", "mule@ybl"), make("b", "mule@ybl"), make("c", "other@ybl")])

        self.assertEqual(len(incidents), 2)
        campaign = next(i for i in incidents if i.session_count == 2)
        self.assertEqual(campaign.session_ids, ["a", "b"])
        self.assertIn(campaign.severity, {"CRITICAL", "HIGH", "MEDIUM", "LOW"})
        self.assertTrue(campaign.incident_id.startswith("INC-"))
        self.assertTrue(campaign.recommended_action)
        # Ranked worst-first so an operator can work top down.
        self.assertGreaterEqual(incidents[0].severity_score, incidents[-1].severity_score)

    def test_sanitize_reply_rejects_leaked_model_reasoning(self):
        """Reasoning models burn the 120-token budget planning and return the plan.
        Sending that to a scammer is worse than saying "as an AI"."""
        from agent.llm_clients import sanitize_reply

        # Real captures from nvidia/nemotron-* on this project's own prompt.
        for leak in (
            "We need to respond as a potential scam victim, polite, slightly confused, ask for clarification",
            "The user wants a reply as a potential scam victim, staying in role, concise, human",
            "<think>Arthur should sound worried</think>",
        ):
            self.assertEqual(sanitize_reply(leak), "", leak)

        # In-character replies survive, in English and romanized Hindi.
        self.assertTrue(sanitize_reply("Oh dear, I am worried. Let me check with my bank branch."))
        self.assertTrue(sanitize_reply("Kya aap bank se baat kar rahe hain? Mujhe samajh nahi aa raha."))
        # A think block around a real answer keeps the answer.
        self.assertEqual(sanitize_reply("<think>plan</think> Which bank is this?"), "Which bank is this?")

    # --- Phase 0 guard --------------------------------------------------------
    #
    # The contract for adding a second threat source. Every number below is what
    # today's honeypot produces for a fixed campaign; adding technical indicator
    # kinds, categories or playbook rows must not move any of them. If this test
    # fails, the extension changed honeypot behaviour - that is the bug, not this
    # test being too strict.
    #
    # Deliberately absolute: fixed timestamps and an explicit `now`, so the score
    # does not drift with the wall clock.

    GUARD_BASE_TS = 1_700_000_000.0

    def _guard_campaign(self):
        def make(sid, offset, upi=None, phone=None, link=None):
            state = SessionState(session_id=sid, persona_id="retired_teacher", persona_label="Arthur (65)")
            state.scam_detected = True
            state.scam_category = "UPI_FRAUD"
            state.scam_confidence = 0.9
            state.language, state.language_name = "hi", "Hindi"
            state.first_scam_timestamp = self.GUARD_BASE_TS + offset
            state.created_at = self.GUARD_BASE_TS + offset
            state.updated_at = self.GUARD_BASE_TS + offset + 30
            state.transcript.append(TranscriptMessage(sender="scammer", text="pay now", timestamp=1))
            state.transcript.append(TranscriptMessage(sender="user", text="ok", timestamp=2))
            if upi:
                state.intel.upi_ids.add(upi)
            if phone:
                state.intel.phone_numbers.add(phone)
            if link:
                state.intel.phishing_links.add(link)
            return state

        return [
            make("guard-a", 0, upi="mule.pay@ybl"),
            make("guard-b", 20, upi="mule.pay@ybl", phone="+919876543210"),
            make("guard-c", 40, upi="mule.pay@ybl", link="http://secure-kyc-verify.tk/login"),
        ]

    def test_guard_honeypot_severity_is_unchanged(self):
        incidents = declare_incidents(self._guard_campaign(), now=self.GUARD_BASE_TS + 120)
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]

        self.assertEqual(incident.severity_score, 67.85)
        self.assertEqual(
            incident.score_breakdown,
            {"attackType": 27.0, "breadth": 10.0, "velocity": 12.85, "intelValue": 9.0, "confidence": 9.0},
        )
        self.assertEqual(incident.severity, "HIGH")
        self.assertEqual(incident.triage, "ACTION_REQUIRED")
        self.assertEqual(incident.sessions_per_minute, 2.57)
        self.assertEqual(incident.duration_seconds, 70)

    def test_guard_honeypot_correlation_and_naming_are_unchanged(self):
        incident = declare_incidents(self._guard_campaign(), now=self.GUARD_BASE_TS + 120)[0]

        self.assertEqual(incident.session_ids, ["guard-a", "guard-b", "guard-c"])
        self.assertEqual(
            incident.shared_indicators,
            ["domain:secure-kyc-verify.tk", "phone:9876543210", "upi:mule.pay@ybl"],
        )
        # Names the freezable identifier, not the caller ID.
        self.assertEqual(incident.name, "UPI payment fraud campaign via mule.pay@ybl (3 sessions)")
        # Derived from the sorted session ids, so it is stable across restarts.
        self.assertEqual(incident.incident_id, "INC-110D3888")

    def test_guard_honeypot_response_plan_is_unchanged(self):
        incident = declare_incidents(self._guard_campaign(), now=self.GUARD_BASE_TS + 120)[0]

        self.assertEqual(
            [(a.action, a.target, a.priority, a.sla_minutes) for a in incident.response_plan],
            [
                ("FREEZE_UPI_HANDLE", "mule.pay@ybl", 1, 30),
                ("FILE_CYBERCRIME_REPORT", "UPI_FRAUD campaign", 1, 60),
                ("BLOCK_AND_TAKEDOWN_DOMAIN", "secure-kyc-verify.tk", 2, 60),
                ("REPORT_CALLER_NUMBER", "9876543210", 3, 120),
                ("ISSUE_CUSTOMER_ADVISORY", "3 targeted sessions", 3, 240),
                ("ROUTE_TO_LANGUAGE_ANALYST", "hi", 4, 240),
            ],
        )

    async def test_dashboard_summary_and_incidents_are_open(self):
        summary = await main.dashboard_summary()
        payload = summary.model_dump()
        self.assertIn("totalSessions", payload)
        self.assertIn("severityCounts", payload)
        self.assertIn("languageBreakdown", payload)
        self.assertEqual(len(payload["timeline"]), 12)

        self.assertEqual(await main.dashboard_incidents(), [])

    async def test_api_requires_api_key(self):
        event = MessageEvent(
            sessionId="demo",
            message=Message(sender="scammer", text="Your bank account will be blocked. Verify now.", timestamp=1),
            conversationHistory=[],
            metadata=Metadata(channel="SMS", language="English", locale="IN"),
        )
        with self.assertRaises(HTTPException) as ctx:
            await main.handle_message(event, x_api_key=None)
        self.assertEqual(ctx.exception.status_code, 401)

    async def test_api_message_flow_creates_session_and_detects_scam(self):
        event = MessageEvent(
            sessionId="demo-2",
            message=Message(sender="scammer", text="URGENT: Share OTP and UPI to unblock.", timestamp=1),
            conversationHistory=[],
            metadata=Metadata(channel="SMS", language="English", locale="IN"),
        )
        resp = await main.handle_message(event, x_api_key="test-api-key")
        self.assertEqual(resp["status"], "success")
        self.assertIn("reply", resp)

        state = main.session_manager.get("demo-2")
        self.assertIsNotNone(state)
        self.assertTrue(state.scam_detected)
        self.assertTrue(state.persona_id)

    async def test_inactivity_auto_finalize(self):
        stale_state = SessionState(
            session_id="stale-session",
            persona_id="retired_teacher",
            persona_label="Arthur (65-year-old retired teacher)",
        )
        stale_state.scam_detected = True
        stale_state.agent_turns = 2
        stale_state.scammer_messages = 2
        stale_state.first_scam_timestamp = time.time() - 200
        stale_state.updated_at = time.time() - (main.INACTIVITY_FINALIZE_SECONDS + 5)
        stale_state.transcript.extend(
            [
                TranscriptMessage(sender="scammer", text="Share OTP now.", timestamp=1),
                TranscriptMessage(sender="user", text="Please explain once more.", timestamp=2, provider="rules"),
            ]
        )
        main.session_manager.get_or_create("stale-session", lambda _sid: stale_state)

        trigger_event = MessageEvent(
            sessionId="trigger-session",
            message=Message(sender="scammer", text="Hello there.", timestamp=3),
            conversationHistory=[],
            metadata=Metadata(channel="SMS", language="English", locale="IN"),
        )
        await main.handle_message(trigger_event, x_api_key="test-api-key")

        updated = main.session_manager.get("stale-session")
        self.assertIsNotNone(updated)
        self.assertTrue(updated.finalized)
        self.assertTrue(updated.closed)

    def test_strict_eval_finalization_for_fast_sessions(self):
        state = SessionState(
            session_id="fast-finalize",
            persona_id="retired_teacher",
            persona_label="Arthur",
        )
        state.scam_detected = True
        state.agent_turns = 8
        state.scammer_messages = 8
        state.first_scam_timestamp = time.time() - 8
        state.intel.phone_numbers.add("+919876543210")
        state.intel.phishing_links.add("https://fake.example/verify")

        self.assertTrue(should_finalize(state))

    async def test_api_allows_requests_when_api_key_not_configured(self):
        original = main.API_KEY
        main.API_KEY = ""
        try:
            event = MessageEvent(
                sessionId="no-auth-session",
                message=Message(sender="scammer", text="hello", timestamp=1),
                conversationHistory=[],
                metadata=Metadata(channel="SMS", language="English", locale="IN"),
            )
            resp = await main.handle_message(event, x_api_key=None)
            self.assertEqual(resp["status"], "success")
        finally:
            main.API_KEY = original

    # --- our own report format (the old grader's schema is gone) --------------

    def test_session_report_uses_our_schema_not_the_old_graders(self):
        state = SessionState(session_id="rep-1", persona_id="retired_teacher", persona_label="Arthur")
        state.scam_detected = True
        state.finalized = True
        state.scam_category = "BANK_FRAUD"
        state.scam_confidence = 0.87
        state.language, state.language_name = "hi", "Hindi"
        state.first_scam_timestamp = time.time() - 90
        state.finalized_timestamp = time.time()
        state.intel.phone_numbers.add("+919876543210")
        state.intel.upi_ids.add("mule@ybl")
        state.intel.emails.add("fraud@example.com")

        incident = declare_incidents([state])[0]
        report = session_report(state, incident)

        self.assertEqual(report["sessionId"], "rep-1")
        self.assertEqual(report["status"], "closed")
        self.assertEqual(report["detection"]["category"], "BANK_FRAUD")
        self.assertEqual(report["language"]["name"], "Hindi")
        self.assertIn("mule@ybl", report["indicators"]["upiIds"])
        self.assertTrue(report["incident"]["responsePlan"])

        # The external grader's field names must not survive anywhere in the payload.
        blob = json.dumps(report)
        for legacy in ("extractedIntelligence", "scamType", "confidenceLevel", "agentNotes",
                       "totalMessagesExchanged", "engagementMetrics"):
            self.assertNotIn(legacy, blob, legacy)

    def test_threat_report_ranks_incidents_and_reports_the_funnel(self):
        def make(sid, upi):
            state = SessionState(session_id=sid, persona_id="p", persona_label="P")
            state.scam_detected = True
            state.scam_category = "UPI_FRAUD"
            state.scam_confidence = 0.95
            state.first_scam_timestamp = time.time() - 30
            state.intel.upi_ids.add(upi)
            state.transcript.append(TranscriptMessage(sender="scammer", text="pay", timestamp=1))
            return state

        sessions = [make("a", "m@ybl"), make("b", "m@ybl"), make("c", "m@ybl"), make("z", "solo@ybl")]
        report = threat_report(sessions, raw_events=500)

        funnel = report["triageFunnel"]
        self.assertEqual(funnel["rawEvents"], 500)
        self.assertEqual(funnel["sessions"], 4)
        self.assertEqual(funnel["incidents"], len(report["incidents"]))
        self.assertGreater(funnel["noiseReductionPercent"], 90.0)

        # Worst first, and every incident carries actionable next steps.
        scores = [i["severityScore"] for i in report["incidents"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        for incident in report["incidents"]:
            self.assertTrue(incident["responsePlan"])
            self.assertIn(incident["triage"], {"ACTION_REQUIRED", "REVIEW", "SUPPRESSED"})

    async def test_bulk_ingest_correlates_a_campaign_in_one_call(self):
        def event(sid, text):
            return MessageEvent(
                sessionId=sid,
                message=Message(sender="scammer", text=text, timestamp=1),
                conversationHistory=[],
                metadata=Metadata(channel="SMS", locale="IN"),
            )

        batch = main.IngestBatch(
            events=[
                event("bulk-1", "Your account is blocked. Pay to mule.pay@ybl to restore KYC now."),
                event("bulk-2", "Urgent KYC: transfer to mule.pay@ybl immediately or account suspended."),
                event("bulk-3", "Win a prize! Claim at http://prize.example/claim"),
            ]
        )
        result = await main.ingest_batch(batch, x_api_key="test-api-key")

        self.assertEqual(result["accepted"], 3)
        self.assertEqual(result["failed"], [])

        # The two sessions sharing the mule handle collapse into one incident.
        campaigns = [i for i in result["incidents"] if i["sessionCount"] > 1]
        self.assertEqual(len(campaigns), 1, result["incidents"])
        self.assertEqual(sorted(campaigns[0]["sessionIds"]), ["bulk-1", "bulk-2"])
        self.assertTrue(any(a["target"] == "mule.pay@ybl" for a in campaigns[0]["responsePlan"]))
        self.assertGreaterEqual(result["triageFunnel"]["rawEvents"], 3)

    async def test_report_endpoints_require_the_api_key(self):
        with self.assertRaises(HTTPException) as ctx:
            await main.threat_report_endpoint(x_api_key="wrong")
        self.assertEqual(ctx.exception.status_code, 401)

        report = await main.threat_report_endpoint(x_api_key="test-api-key")
        self.assertIn("triageFunnel", report)

        with self.assertRaises(HTTPException) as ctx:
            await main.session_report_endpoint("nope", x_api_key="test-api-key")
        self.assertEqual(ctx.exception.status_code, 404)
