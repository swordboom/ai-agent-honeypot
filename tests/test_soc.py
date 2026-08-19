"""
SOC layer contract: threat-intel enrichment, UEBA behavioural analytics,
automated investigation, and the SOC orchestration/KPIs, plus the wired endpoints.

The SOC layer is *derived on read* over live session state and never mutates the
incident engine, so these tests also guard that the four capabilities compose into
one coherent case without a second store.
"""

import asyncio
import os
import unittest

# config prefers HONEY_POT_API_KEY over API_KEY; pin both so a lingering host var
# cannot flip these to 401 (see tests/test_app.py).
os.environ["HONEY_POT_API_KEY"] = "test-api-key"
os.environ["API_KEY"] = "test-api-key"
os.environ["OPENROUTER_API_KEY"] = ""
os.environ["ENABLE_LLM_EXTRACTION"] = "false"

import main  # noqa: E402
from models.session import SessionState, TranscriptMessage  # noqa: E402
from services.behavioral_analytics import analyze_entities  # noqa: E402
from services.incident_engine import declare_incidents  # noqa: E402
from services.investigation import investigate_incident  # noqa: E402
from services.soc import soc_overview, soc_case  # noqa: E402
from services.threat_intel import enrich_indicator  # noqa: E402


def _chat(sid, upi, link=None, conf=0.9, offset=0, final=False):
    s = SessionState(session_id=sid, persona_id="p", persona_label="P")
    s.scam_detected = True
    s.scam_category = "UPI_FRAUD"
    s.scam_confidence = conf
    s.created_at = 1000.0 + offset
    s.first_scam_timestamp = 1000.0 + offset + 5
    s.updated_at = 1000.0 + offset + 40
    s.intel.upi_ids.add(upi)
    if link:
        s.intel.phishing_links.add(link)
    s.transcript.append(TranscriptMessage(sender="scammer", text="pay now", timestamp=1))
    if final:
        s.finalized = True
        s.finalized_timestamp = 1000.0 + offset + 40
    return s


def _tech(sid, ip, users, count, domain=None, offset=0, success=False):
    s = SessionState(
        session_id=sid, persona_id="technical-feed", persona_label=ip,
        source_type="technical", event_count=count, affected_targets=len(users),
    )
    s.scam_detected = True
    s.scam_category = "CREDENTIAL_STUFFING"
    s.scam_confidence = 0.9
    s.created_at = 1000.0 + offset
    s.first_scam_timestamp = 1000.0 + offset
    s.finalized = True
    s.finalized_timestamp = 1000.0 + offset + 30
    s.updated_at = 1000.0 + offset + 30
    s.intel.ip_addresses.add(ip)
    for u in users:
        s.intel.usernames.add(u)
    if domain:
        s.intel.domains.add(domain)
    if success:
        s.scam_triggers = ["success", "failure_burst"]
    return s


class ThreatIntelEnrichment(unittest.TestCase):
    def test_known_bad_domain_is_malicious(self):
        e = enrich_indicator("domain", "sbi-verify.tk")
        self.assertEqual(e.verdict, "MALICIOUS")
        self.assertIn("known-bad-domain", e.feed_matches)

    def test_brand_lookalike_detected(self):
        e = enrich_indicator("domain", "hdfc-login.example.com")
        self.assertEqual(e.attributes["brandImpersonated"], "hdfc")

    def test_legit_bank_domain_is_clean(self):
        e = enrich_indicator("domain", "icicibank.com")
        self.assertIsNone(e.attributes["brandImpersonated"])
        self.assertIn(e.verdict, ("BENIGN", "UNKNOWN"))

    def test_private_ip_flagged_as_bogon(self):
        e = enrich_indicator("ip", "192.168.1.10")
        self.assertIn("bogon", e.feed_matches)

    def test_public_ip_not_bogon(self):
        e = enrich_indicator("ip", "203.0.113.9")
        self.assertEqual(e.attributes["classification"], "public")


class BehaviouralAnalytics(unittest.TestCase):
    def test_fan_out_flags_spray_source(self):
        spray = _tech("t1", "203.0.113.9", [f"user{i}" for i in range(8)], count=50, success=True)
        profiles = analyze_entities([spray], now=1200.0)
        ip = next(p for p in profiles if p.kind == "ip")
        self.assertEqual(ip.fan_out, 8)
        self.assertIn(ip.risk_band, ("HIGH", "CRITICAL"))

    def test_cross_source_entity_scores_corroboration(self):
        c = _chat("c1", "mule@ybl", link="http://sbi-verify.tk")
        t = _tech("t1", "5.5.5.5", ["a.sharma"], count=40, domain="sbi-verify.tk")
        profs = analyze_entities([c, t], now=1200.0)
        dom = next(p for p in profs if p.kind == "domain")
        self.assertEqual(len(dom.sources), 2)

    def test_quiet_traffic_produces_no_entities(self):
        quiet = SessionState(session_id="q", persona_id="p", persona_label="P")
        self.assertEqual(analyze_entities([quiet]), [])


class AutomatedInvestigation(unittest.TestCase):
    def test_cross_source_feed_hit_is_true_positive(self):
        c = _chat("c1", "mule@ybl", link="http://sbi-verify.tk/login")
        t = _tech("t1", "203.0.113.9", [f"user{i}" for i in range(6)], count=40, domain="sbi-verify.tk")
        sessions = [c, t]
        incident = declare_incidents(sessions, now=1200.0)[0]
        inv = investigate_incident(incident, sessions)
        self.assertEqual(inv.verdict, "TRUE_POSITIVE")
        self.assertGreaterEqual(inv.feed_hit_count, 1)
        self.assertTrue(inv.timeline)
        self.assertTrue(inv.next_steps)

    def test_weak_lone_session_is_not_confirmed(self):
        weak = SessionState(session_id="w", persona_id="p", persona_label="P")
        weak.scam_detected = True
        weak.scam_category = "GENERIC_SCAM"
        weak.scam_confidence = 0.3
        weak.first_scam_timestamp = 1000.0
        weak.updated_at = 1030.0
        weak.intel.phone_numbers.add("+919812345678")
        inc = declare_incidents([weak], now=1200.0)[0]
        inv = investigate_incident(inc, [weak])
        self.assertNotEqual(inv.verdict, "TRUE_POSITIVE")


class SocOrchestration(unittest.TestCase):
    def test_overview_shapes_cases_and_kpis(self):
        c = _chat("c1", "mule@ybl", link="http://sbi-verify.tk", final=True)
        t = _tech("t1", "203.0.113.9", [f"user{i}" for i in range(6)], count=40, domain="sbi-verify.tk")
        overview = soc_overview([c, t], raw_events=20, now=1200.0)
        self.assertIn("kpis", overview)
        self.assertTrue(overview["cases"])
        mixed = next(x for x in overview["cases"] if x["sourceType"] == "Mixed")
        self.assertEqual(mixed["verdict"], "TRUE_POSITIVE")
        self.assertTrue(mixed["owner"])
        self.assertGreaterEqual(mixed["slaMinutes"], 15)
        k = overview["kpis"]
        self.assertLessEqual(k["automationRatePercent"], 100.0)
        self.assertGreaterEqual(k["automationRatePercent"], 0.0)
        self.assertEqual(k["confirmedThreats"], 1)

    def test_case_file_resolves_and_carries_investigation(self):
        c = _chat("c1", "mule@ybl", link="http://sbi-verify.tk")
        t = _tech("t1", "203.0.113.9", [f"user{i}" for i in range(6)], count=40, domain="sbi-verify.tk")
        incident = declare_incidents([c, t], now=1200.0)[0]
        case = soc_case(incident.incident_id, [c, t], now=1200.0)
        self.assertIsNotNone(case)
        self.assertEqual(case["investigation"]["verdict"], "TRUE_POSITIVE")
        self.assertTrue(case["responsePlan"])

    def test_unknown_case_is_none(self):
        self.assertIsNone(soc_case("INC-NOPE", []))


class SocEndpoints(unittest.TestCase):
    """The endpoints are open (read-only telemetry), like the dashboard APIs."""

    def setUp(self):
        main.session_manager.clear()
        # Seed a cross-source campaign through the real ingest path.
        c = _chat("c1", "mule@ybl", link="http://sbi-verify.tk")
        t = _tech("t1", "203.0.113.9", [f"user{i}" for i in range(6)], count=40, domain="sbi-verify.tk")
        main.session_manager.bulk_load([c, t])

    def test_overview_endpoint(self):
        data = asyncio.run(main.soc_overview_endpoint())
        self.assertIn("kpis", data)
        self.assertTrue(data["cases"])

    def test_entities_endpoint(self):
        data = asyncio.run(main.soc_entities_endpoint(limit=50))
        self.assertTrue(any(p["kind"] == "ip" for p in data))

    def test_case_endpoint_and_404(self):
        overview = asyncio.run(main.soc_overview_endpoint())
        cid = overview["cases"][0]["incidentId"]
        case = asyncio.run(main.soc_case_endpoint(cid))
        self.assertEqual(case["incidentId"], cid)
        with self.assertRaises(Exception):
            asyncio.run(main.soc_case_endpoint("INC-NOPE"))

    def test_enrich_endpoint(self):
        data = asyncio.run(main.soc_enrich_endpoint(main.EnrichRequest(kind="domain", value="sbi-verify.tk")))
        self.assertEqual(data["verdict"], "MALICIOUS")


if __name__ == "__main__":
    unittest.main()
