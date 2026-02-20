import os
import time
import unittest

from fastapi import HTTPException


# Ensure tests are deterministic and never hit real external services.
os.environ["API_KEY"] = "test-api-key"
os.environ["HONEY_POT_DASHBOARD_KEY"] = "test-dashboard-key"
os.environ["OPENAI_API_KEY"] = ""
os.environ["GEMINI_API_KEY"] = ""
os.environ["ENABLE_LLM_EXTRACTION"] = "false"
os.environ["HONEY_POT_CALLBACK_URL"] = "http://example.invalid/callback"

import main  # noqa: E402
from agent.intelligence_extractor import extract_intelligence  # noqa: E402
from agent.personas import assign_persona  # noqa: E402
from agent.reply_agent import generate_agent_reply  # noqa: E402
from models.api import Message, MessageEvent, Metadata  # noqa: E402
from models.session import Intelligence, SessionState, TranscriptMessage  # noqa: E402
from services.engagement_policy import should_finalize  # noqa: E402


class _DummyLLM:
    def __init__(self, reply: str | None):
        self.api_key = "x"
        self._reply = reply

    def chat(self, *args, **kwargs):
        return self._reply


class HoneypotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        main.session_manager.clear()
        # Never send real callbacks in tests.
        main.callback_service.send_async = lambda *args, **kwargs: None

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

    def test_agent_reply_failover_openai_gemini_rules(self):
        state = SessionState(session_id="s1", persona_id="retired_teacher", persona_label="Arthur")
        state.scam_detected = True
        state.transcript.append(TranscriptMessage(sender="scammer", text="Share your UPI ID.", timestamp=1))

        # OpenAI wins if it returns a reply.
        reply, provider = generate_agent_reply(
            state,
            Metadata(channel="SMS", language="English", locale="IN"),
            openai=_DummyLLM("ok"),
            gemini=_DummyLLM("nope"),
            max_history=12,
        )
        self.assertEqual(provider, "openai")
        self.assertTrue(reply)

        # Gemini if OpenAI fails.
        reply, provider = generate_agent_reply(
            state,
            None,
            openai=_DummyLLM(None),
            gemini=_DummyLLM("gemini ok"),
            max_history=12,
        )
        self.assertEqual(provider, "gemini")
        self.assertTrue(reply)

        # Rules if both fail.
        reply, provider = generate_agent_reply(
            state,
            None,
            openai=_DummyLLM(None),
            gemini=_DummyLLM(None),
            max_history=12,
        )
        self.assertEqual(provider, "rules")
        self.assertTrue(reply)

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

    async def test_dashboard_auth(self):
        with self.assertRaises(HTTPException) as ctx:
            await main.dashboard_summary(x_dashboard_key="wrong")
        self.assertEqual(ctx.exception.status_code, 401)

        summary = await main.dashboard_summary(x_dashboard_key="test-dashboard-key")
        self.assertIn("totalSessions", summary.model_dump())

    async def test_inactivity_auto_finalize(self):
        callback_calls = []
        main.callback_service.send_async = lambda *args, **kwargs: callback_calls.append((args, kwargs))

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
        self.assertGreaterEqual(len(callback_calls), 1)

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

    def test_callback_payload_contains_required_fields_and_enriched_intelligence(self):
        state = SessionState(session_id="cb-1", persona_id="retired_teacher", persona_label="Arthur")
        state.scam_detected = True
        state.finalized = True
        state.scam_category = "BANK_FRAUD"
        state.scam_confidence = 0.87
        state.first_scam_timestamp = time.time() - 90
        state.finalized_timestamp = time.time()
        state.intel.phone_numbers.add("+919876543210")
        state.intel.emails.add("fraud@example.com")
        state.intel.case_ids.add("CASE12345")

        payload = main.callback_service.build_payload(state, total_messages=8)
        self.assertEqual(payload["sessionId"], "cb-1")
        self.assertTrue(payload["scamDetected"])
        self.assertEqual(payload["totalMessagesExchanged"], 8)
        self.assertIn("emailAddresses", payload["extractedIntelligence"])
        self.assertIn("caseIds", payload["extractedIntelligence"])
