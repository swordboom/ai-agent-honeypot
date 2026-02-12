import os
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
