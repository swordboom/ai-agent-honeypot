import logging
import os
import threading
import time
from typing import Dict, List, Optional, Union

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent.behavior_analyzer import BehaviorAnalyzer
from agent.intelligence_extractor import extract_intelligence
from agent.llm_clients import OpenRouterClient, list_free_models, model_health_snapshot
from agent.multilingual import detect_language
from agent.notes import build_agent_notes
from agent.personas import assign_persona
from agent.reply_agent import (
    generate_agent_reply,
    generate_probe_reply,
    generate_rule_based_reply,
)
from agent.scam_detector import ScamDetector
from agent.structured_extractor import extract_structured_intelligence, should_run_llm_extraction
from config import Settings
from models.api import MessageEvent
from models.technical import TechnicalEvent
from models.dashboard import (
    DashboardIncident,
    DashboardMapPoint,
    DashboardSessionCard,
    DashboardSessionDetail,
    DashboardSummary,
)
from models.session import Intelligence, SessionState, TranscriptMessage
from services.dashboard_service import DashboardService
from services.reporting import incident_index, session_report, threat_report
from services.engagement_policy import should_finalize
from services.llm_load_control import LLMCallGate
from services.session_manager import SessionManager
from services.soc import soc_overview, soc_case
from services.behavioral_analytics import analyze_entities
from services.threat_intel import enrich_indicator
from services.strategy_state import infer_strategy_state
from services.technical_ingest import ingest as ingest_technical_event
from services.url_scanner import ingest_url_scan
from services.email_scanner import ingest_email_scan
from services.persistence import load_snapshot, save_snapshot

APP_NAME = "Agentic Honey-Pot"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(APP_DIR, "static")
SNAPSHOT_PATH = os.path.join(APP_DIR, "sessions_snapshot.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(APP_NAME)

settings = Settings.from_env()

# Expose settings-derived values as module globals for easy local overrides/tests.
API_KEY = settings.api_key
EXTENDED_RESPONSE = settings.extended_response

OPENROUTER_API_KEY = settings.openrouter_api_key
OPENROUTER_MODELS = settings.openrouter_models
AGENT_MAX_HISTORY_MESSAGES = settings.agent_max_history_messages
LLM_TIMEOUT_SECONDS = settings.llm_timeout_seconds
REQUEST_TIMEOUT_BUDGET_SECONDS = max(5, settings.request_timeout_budget_seconds)

ENABLE_LLM_EXTRACTION = settings.enable_llm_extraction
LLM_EXTRACTION_MIN_INTERVAL_SECONDS = settings.llm_extraction_min_interval_seconds
ENABLE_LLM_BEHAVIOR_ANALYSIS = settings.enable_llm_behavior_analysis
HIGH_LOAD_MODE = settings.high_load_mode
INACTIVITY_FINALIZE_SECONDS = max(0, settings.inactivity_finalize_seconds)

session_manager = SessionManager(
    session_ttl_seconds=settings.session_ttl_seconds,
    cleanup_interval_seconds=settings.session_cleanup_interval_seconds,
)
scam_detector = ScamDetector()
behavior_analyzer = BehaviorAnalyzer()
dashboard_service = DashboardService(session_manager)
llm_call_gate = LLMCallGate(
    enabled=HIGH_LOAD_MODE,
    global_rpm_limit=settings.llm_global_rpm_limit,
    reply_rpm_limit=settings.llm_reply_rpm_limit,
    behavior_rpm_limit=settings.llm_behavior_rpm_limit,
    extraction_rpm_limit=settings.llm_extraction_rpm_limit,
    behavior_sample_every_n_scam_messages=settings.llm_behavior_sample_every_n_scam_messages,
)

app = FastAPI(title=APP_NAME)

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# ---------- persistence ----------

_snapshot_stop = threading.Event()


def _snapshot_loop() -> None:
    """Background thread: saves a session snapshot every 60 seconds."""
    while not _snapshot_stop.wait(60):
        save_snapshot(session_manager, SNAPSHOT_PATH, raw_event_count())


@app.on_event("startup")
async def _on_startup() -> None:
    sessions_loaded, prior_event_count = load_snapshot(session_manager, SNAPSHOT_PATH)
    if prior_event_count:
        _event_counter["count"] = prior_event_count
    if sessions_loaded:
        logger.info("History restored: %d sessions, %d prior events", sessions_loaded, prior_event_count)
    t = threading.Thread(target=_snapshot_loop, daemon=True, name="snapshot-saver")
    t.start()


@app.on_event("shutdown")
async def _on_shutdown() -> None:
    _snapshot_stop.set()
    save_snapshot(session_manager, SNAPSHOT_PATH, raw_event_count())


class DebugTextRequest(BaseModel):
    text: str


class URLScanRequest(BaseModel):
    url: str


class EmailScanRequest(BaseModel):
    rawEmail: str


class IngestBatch(BaseModel):
    """A batch of raw events from an upstream feed."""

    events: List[Union[MessageEvent, TechnicalEvent]]


# Raw events seen since start. The triage funnel is only meaningful against the
# volume that came in - "3 incidents" means nothing without "out of 900 events".
# ponytail: a plain counter, not a metrics backend; swap in Prometheus if it ever
# needs to survive a restart.
_event_counter = {"count": 0}


def _count_event(n: int = 1) -> None:
    _event_counter["count"] += n


def raw_event_count() -> int:
    return _event_counter["count"]


def _require_api_key(x_api_key: Optional[str]) -> None:
    # If API key is not configured, run in open mode.
    if not API_KEY:
        return
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _llm_client() -> Optional[OpenRouterClient]:
    if not OPENROUTER_API_KEY:
        return None
    return OpenRouterClient(
        api_key=OPENROUTER_API_KEY,
        models=OPENROUTER_MODELS,
        timeout_seconds=LLM_TIMEOUT_SECONDS,
    )


def _collect_scammer_texts(event: MessageEvent) -> List[str]:
    texts = [m.text for m in event.conversationHistory if m.sender == "scammer" and m.text]
    if event.message.sender == "scammer" and event.message.text:
        texts.append(event.message.text)
    return texts


def _engagement_duration_seconds(state: SessionState) -> int:
    if state.first_scam_timestamp is None:
        return 0
    end = state.finalized_timestamp or time.time()
    return max(0, int(end - state.first_scam_timestamp))


def _rolling_score(previous: float, rule_score: float, behavior_score: float) -> float:
    # Progressive session-level scoring: decayed carry + new message contribution.
    contribution = (0.65 * max(0.0, rule_score)) + (0.35 * max(0.0, behavior_score))
    return round(min(100.0, (previous * 0.92) + contribution), 2)


def _resolve_scam_category(rule_category: str, behavior_hint: Optional[str]) -> str:
    if behavior_hint and behavior_hint != "GENERIC_SCAM":
        return behavior_hint
    if rule_category and rule_category != "GENERIC_SCAM":
        return rule_category
    return behavior_hint or rule_category or "GENERIC_SCAM"


def _session_factory(session_id: str) -> SessionState:
    persona = assign_persona(session_id)
    return SessionState(
        session_id=session_id,
        persona_id=persona.id,
        persona_label=f"{persona.display_name} ({persona.age_profile})",
    )


def _auto_finalize_inactive_sessions(skip_session_id: Optional[str] = None) -> int:
    if INACTIVITY_FINALIZE_SECONDS <= 0:
        return 0

    now = time.time()
    finalized_count = 0
    for stale in session_manager.list_sessions():
        if skip_session_id and stale.session_id == skip_session_id:
            continue
        if stale.finalized or stale.closed:
            continue
        if not stale.scam_detected:
            continue
        if stale.agent_turns < 1:
            continue
        if (now - stale.updated_at) < INACTIVITY_FINALIZE_SECONDS:
            continue

        total_messages = stale.final_total_messages_exchanged or len(stale.transcript)
        session_manager.finalize_and_close(
            stale,
            build_agent_notes(stale),
            total_messages=total_messages,
        )
        finalized_count += 1

    return finalized_count


def _closed_reply(state: SessionState) -> str:
    if state.persona_id == "busy_shop_owner":
        return "I will go to the bank branch now. I cannot message more right now."
    if state.persona_id == "retired_teacher":
        return "I will visit the bank and check. I will reply later."
    return "I will check this with the bank. Please wait."


def _has_time_budget(deadline_ts: float, reserve_seconds: float) -> bool:
    return time.time() + reserve_seconds < deadline_ts


@app.get("/health")
async def healthcheck() -> Dict[str, str]:
    return {"status": "ok"}


def _static_page(filename: str, label: str) -> FileResponse:
    file_path = os.path.join(STATIC_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"{label} not found")
    # These tiny shell pages intentionally stay fresh: each points at a
    # versioned dashboard/console script and must not leave an old renderer
    # running after a reload during local development.
    return FileResponse(file_path, headers={"Cache-Control": "no-store, max-age=0"})


@app.get("/")
async def index() -> FileResponse:
    return _static_page("sentinel.html", "Cyber Sentinel UI")


@app.get("/dashboard")
async def dashboard_page() -> FileResponse:
    return _static_page("dashboard.html", "Dashboard UI")


@app.get("/console")
async def console_page() -> FileResponse:
    """Operator console: feed events in and watch correlation happen live."""
    return _static_page("console.html", "Console UI")


@app.get("/sentinel")
async def sentinel_page() -> FileResponse:
    """Cyber Sentinel — redesigned threat operations interface."""
    return _static_page("sentinel.html", "Cyber Sentinel UI")


@app.get("/soc")
async def soc_page() -> FileResponse:
    """SOC console: case queue, automated investigations, and UEBA entity risk."""
    return _static_page("soc.html", "SOC Console UI")


# Dashboard APIs are read-only telemetry over an in-memory store and carry no
# secrets, so they are open. The scam-ingest endpoint keeps its x-api-key.
@app.get("/dashboard/api/summary", response_model=DashboardSummary)
async def dashboard_summary() -> DashboardSummary:
    _auto_finalize_inactive_sessions()
    return dashboard_service.summary(raw_events=raw_event_count())


@app.get("/dashboard/api/sessions", response_model=List[DashboardSessionCard])
async def dashboard_sessions(
    limit: int = Query(default=50, ge=1, le=200),
) -> List[DashboardSessionCard]:
    _auto_finalize_inactive_sessions()
    return dashboard_service.list_sessions(limit=limit)


@app.get("/dashboard/api/sessions/{session_id}", response_model=DashboardSessionDetail)
async def dashboard_session_detail(session_id: str) -> DashboardSessionDetail:
    _auto_finalize_inactive_sessions()
    try:
        return dashboard_service.session_detail(session_id=session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")


@app.get("/dashboard/api/incidents", response_model=List[DashboardIncident])
async def dashboard_incidents() -> List[DashboardIncident]:
    """Feature 3: correlated alerts declared as ranked, severity-labelled incidents."""
    _auto_finalize_inactive_sessions()
    return dashboard_service.incidents()


@app.get("/dashboard/api/map", response_model=List[DashboardMapPoint])
async def dashboard_map() -> List[DashboardMapPoint]:
    _auto_finalize_inactive_sessions()
    return dashboard_service.map_points()


@app.get("/dashboard/api/models")
async def dashboard_models():
    """Configured free-model chain plus what OpenRouter currently advertises as free."""
    live = list_free_models()
    return {
        "configured": list(OPENROUTER_MODELS),
        "configuredAvailable": [m for m in OPENROUTER_MODELS if m in live] if live else [],
        "liveFreeModels": live,
        "health": model_health_snapshot(),
        "apiKeyConfigured": bool(OPENROUTER_API_KEY),
    }


# ---------- SOC console (read-only telemetry, open like the dashboard) ----------


class EnrichRequest(BaseModel):
    kind: str
    value: str


@app.get("/dashboard/api/soc/overview")
async def soc_overview_endpoint():
    """Full SOC posture: KPIs, case queue, UEBA entity risk, triage funnel."""
    _auto_finalize_inactive_sessions()
    return soc_overview(session_manager.list_sessions(), raw_events=raw_event_count())


@app.get("/dashboard/api/soc/case/{incident_id}")
async def soc_case_endpoint(incident_id: str):
    """One case file: incident + automated investigation + response plan."""
    _auto_finalize_inactive_sessions()
    case = soc_case(incident_id, session_manager.list_sessions())
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.get("/dashboard/api/soc/entities")
async def soc_entities_endpoint(limit: int = Query(default=50, ge=1, le=200)):
    """Ranked behavioural-analytics (UEBA) entity profiles."""
    _auto_finalize_inactive_sessions()
    profiles = analyze_entities(session_manager.list_sessions())
    return [p.to_payload() for p in profiles[:limit]]


@app.post("/dashboard/api/soc/enrich")
async def soc_enrich_endpoint(req: EnrichRequest):
    """Ad-hoc offline threat-intel enrichment for a single indicator."""
    return enrich_indicator(req.kind, req.value).to_payload()


# Debug endpoints
@app.post("/dashboard/api/debug/detect-scam")
async def debug_detect_scam(req: DebugTextRequest):
    result = scam_detector.detect(req.text)
    behavior = behavior_analyzer.analyze(req.text, _llm_client() if ENABLE_LLM_BEHAVIOR_ANALYSIS else None)
    return {
        "isScam": result.is_scam,
        "confidence": result.confidence,
        "category": result.category,
        "score": result.score,
        "language": result.language,
        "languageName": result.language_name,
        "languageConfidence": result.language_confidence,
        "vernacularScore": result.vernacular_score,
        "vernacularTerms": result.vernacular_terms,
        "behaviorScore": behavior.score,
        "behaviorIndicators": behavior.indicators,
        "triggers": result.triggers,
        "suspiciousKeywords": result.suspicious_keywords,
    }


@app.post("/dashboard/api/debug/extract-intelligence")
async def debug_extract_intelligence(req: DebugTextRequest):
    intel = Intelligence()
    extract_intelligence([req.text], intel)
    return {
        "indicators": intel.to_indicator_payload(),
        "extended": intel.to_extended_payload(),
    }


@app.get("/dashboard/api/debug/llm-gate")
async def debug_llm_gate():
    return llm_call_gate.snapshot().to_dict()


@app.delete("/dashboard/api/debug/sessions")
async def debug_clear_sessions():
    cleared = session_manager.clear()
    return {"status": "success", "cleared": cleared}


@app.post("/api/scan/url")
async def scan_url_endpoint(req: URLScanRequest, x_api_key: Optional[str] = Header(None)):
    """Analyse a URL for phishing infrastructure signals and feed it into the correlator."""
    _require_api_key(x_api_key)
    _count_event()
    result, session_id = ingest_url_scan(req.url, session_manager)
    response: Dict = {"scan": result, "sessionId": session_id}
    if session_id:
        incident = incident_index(session_manager.list_sessions()).get(session_id)
        if incident:
            from services.reporting import session_report
            state = session_manager.get(session_id)
            if state:
                response["incidentSummary"] = session_report(state, incident).get("incident")
    return response


@app.post("/api/scan/email")
async def scan_email_endpoint(req: EmailScanRequest, x_api_key: Optional[str] = Header(None)):
    """Analyse a raw email for phishing signals and feed sender domain into the correlator."""
    _require_api_key(x_api_key)
    _count_event()
    result, session_id = ingest_email_scan(req.rawEmail, session_manager)
    response: Dict = {"scan": result, "sessionId": session_id}
    if session_id:
        incident = incident_index(session_manager.list_sessions()).get(session_id)
        if incident:
            from services.reporting import session_report
            state = session_manager.get(session_id)
            if state:
                response["incidentSummary"] = session_report(state, incident).get("incident")
    return response


@app.post("/api/message")
async def handle_message(event: MessageEvent, x_api_key: Optional[str] = Header(None)):
    _require_api_key(x_api_key)
    _count_event()
    request_deadline = time.time() + REQUEST_TIMEOUT_BUDGET_SECONDS
    session_manager.maybe_cleanup()
    _auto_finalize_inactive_sessions(skip_session_id=event.sessionId)
    llm_client = _llm_client()

    state = session_manager.get_or_create(event.sessionId, _session_factory)

    # If we already closed the engagement, we keep replying politely but we do not keep extracting.
    if state.closed:
        session_manager.append_transcript(state, event.message.sender, event.message.text, event.message.timestamp)
        reply = _closed_reply(state)
        session_manager.append_transcript(state, "user", reply, int(time.time() * 1000), provider="rules")
        return {"status": "success", "reply": reply}

    session_manager.seed_history_if_needed(state, event.conversationHistory)
    session_manager.append_transcript(state, event.message.sender, event.message.text, event.message.timestamp)

    incoming_scammer_text = event.message.text if event.message.sender == "scammer" else ""
    incoming_scammer_index = state.scammer_messages + (1 if event.message.sender == "scammer" else 0)
    scammer_texts = _collect_scammer_texts(event)
    detection = scam_detector.detect(incoming_scammer_text)
    allow_behavior_llm = (
        ENABLE_LLM_BEHAVIOR_ANALYSIS
        and event.message.sender == "scammer"
        and _has_time_budget(request_deadline, (2 * LLM_TIMEOUT_SECONDS) + 1)
        and llm_call_gate.allow("behavior", scammer_message_index=incoming_scammer_index)
    )
    behavior = behavior_analyzer.analyze(
        incoming_scammer_text,
        llm_client if allow_behavior_llm else None,
    )

    # Feature 11: record the language before generating a reply, so the persona
    # answers in the language the scammer is actually using.
    if event.message.sender == "scammer" and incoming_scammer_text:
        session_manager.update_language(
            state,
            code=detection.language,
            name=detection.language_name,
            confidence=detection.language_confidence,
            vernacular_score=detection.vernacular_score,
        )

    rolling_score = _rolling_score(
        state.rolling_scam_score,
        detection.score if event.message.sender == "scammer" else 0.0,
        behavior.score if event.message.sender == "scammer" else 0.0,
    )
    scam_detected_now = (
        detection.is_scam
        or behavior.score >= 5.0
        or rolling_score >= 6.0
    )
    confidence = round(
        min(1.0, max(detection.confidence, behavior.confidence, rolling_score / 12.0)),
        2,
    )
    category = _resolve_scam_category(detection.category, behavior.category_hint)
    merged_triggers = sorted(set(detection.triggers).union(behavior.indicators))
    merged_keywords = sorted(set(detection.suspicious_keywords).union(behavior.indicators))

    # Include phone/link/account clues from already-collected intel to avoid under-classification.
    actionable_count = state.intel.actionable_category_count()
    strategy_state = infer_strategy_state(
        state,
        rolling_score=rolling_score,
        scam_detected=scam_detected_now,
        actionable_count=actionable_count,
    )

    session_manager.update_detection(
        state,
        is_scam=scam_detected_now,
        confidence=confidence,
        category=category,
        triggers=merged_triggers,
        suspicious_keywords=merged_keywords,
        rolling_score=rolling_score,
        rule_score=detection.score,
        behavior_score=behavior.score,
        strategy_state=strategy_state,
    )

    if event.message.sender == "scammer":
        session_manager.increment_scammer_message(state)

    # Regex extraction always.
    session_manager.update_intel(state, lambda intel: extract_intelligence(scammer_texts, intel))

    # Optional LLM structured extraction (augment regex).
    if (
        ENABLE_LLM_EXTRACTION
        and state.scam_detected
        and event.message.sender == "scammer"
        and should_run_llm_extraction(state.last_llm_extraction_at, LLM_EXTRACTION_MIN_INTERVAL_SECONDS)
        and _has_time_budget(request_deadline, (2 * LLM_TIMEOUT_SECONDS) + 1)
        and llm_call_gate.allow("extraction", scammer_message_index=incoming_scammer_index)
    ):
        indicator_payload, extended_payload = extract_structured_intelligence(
            text=event.message.text,
            llm=llm_client,
            timeout_hint_seconds=LLM_TIMEOUT_SECONDS,
        )
        session_manager.update_intel(
            state,
            lambda intel: (intel.merge_indicator_payload(indicator_payload), intel.merge_extended_payload(extended_payload)),
        )
        session_manager.update_llm_extraction_time(state)

    session_manager.set_strategy_state(state, infer_strategy_state(state))

    allow_reply_llm = state.scam_detected and llm_call_gate.allow(
        "reply",
        scammer_message_index=incoming_scammer_index,
    ) and _has_time_budget(request_deadline, (2 * LLM_TIMEOUT_SECONDS) + 1)

    if state.scam_detected and allow_reply_llm:
        reply, provider = generate_agent_reply(
            state,
            event.metadata,
            llm_client,
            max_history=AGENT_MAX_HISTORY_MESSAGES,
        )
    elif state.scam_detected:
        reply, provider = (generate_rule_based_reply(state), "rules")
    else:
        reply, provider = (generate_probe_reply(state), "rules")

    session_manager.set_reply_provider(state, provider)

    if state.scam_detected:
        session_manager.increment_agent_turn(state)

    session_manager.append_transcript(state, "user", reply, int(time.time() * 1000), provider=provider)

    total_messages = len(state.transcript)

    if should_finalize(state):
        session_manager.finalize_and_close(state, build_agent_notes(state), total_messages=total_messages)

    response = {"status": "success", "reply": reply}
    if EXTENDED_RESPONSE:
        incident = incident_index(session_manager.list_sessions()).get(state.session_id)
        response.update(
            {
                "report": session_report(state, incident),
                "llmLoadGate": llm_call_gate.snapshot().to_dict(),
            }
        )

    return response


@app.post("/api/ingest")
async def ingest_batch(batch: IngestBatch, x_api_key: Optional[str] = Header(None)):
    """
    Bulk event intake.

    A security team's problem is volume, so events arrive in batches, not one
    conversation at a time. Each event runs the full pipeline; one bad event does not
    sink the batch, and the response is the triage funnel - what the batch actually
    reduced to once correlated and prioritised.
    """
    _require_api_key(x_api_key)

    accepted, failed = 0, []
    for event in batch.events:
        try:
            if isinstance(event, TechnicalEvent):
                _count_event()
                ingest_technical_event(event, session_manager)
            else:
                await handle_message(event, x_api_key)
            accepted += 1
        except HTTPException:
            raise
        except Exception as exc:  # keep ingesting; report the casualty
            logger.warning("Ingest failed for session %s: %s", event.sessionId, exc)
            failed.append({"sessionId": event.sessionId, "error": str(exc)})

    report = threat_report(session_manager.list_sessions(), raw_event_count())
    return {
        "status": "success",
        "accepted": accepted,
        "failed": failed,
        "triageFunnel": report["triageFunnel"],
        "incidents": report["incidents"],
    }


@app.get("/api/report/threat")
async def threat_report_endpoint(x_api_key: Optional[str] = Header(None)):
    """Every declared incident, ranked, with the triage funnel. Our own schema."""
    _require_api_key(x_api_key)
    _auto_finalize_inactive_sessions()
    return threat_report(session_manager.list_sessions(), raw_event_count())


@app.get("/api/report/session/{session_id}")
async def session_report_endpoint(session_id: str, x_api_key: Optional[str] = Header(None)):
    _require_api_key(x_api_key)
    state = session_manager.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail="Session not found")
    return session_report(state, incident_index(session_manager.list_sessions()).get(session_id))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
