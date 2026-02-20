import logging
import os
import time
from typing import Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent.behavior_analyzer import BehaviorAnalyzer
from agent.intelligence_extractor import extract_intelligence
from agent.llm_clients import GeminiClient, OpenAIClient
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
from models.dashboard import (
    DashboardMapPoint,
    DashboardSessionCard,
    DashboardSessionDetail,
    DashboardSummary,
)
from models.session import Intelligence, SessionState, TranscriptMessage
from services.callback_service import CallbackService
from services.dashboard_service import DashboardService
from services.engagement_policy import should_finalize
from services.llm_load_control import LLMCallGate
from services.session_manager import SessionManager
from services.strategy_state import infer_strategy_state

APP_NAME = "Agentic Honey-Pot"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(APP_DIR, "static")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(APP_NAME)

settings = Settings.from_env()

# Expose settings-derived values as module globals for easy local overrides/tests.
API_KEY = settings.api_key
DASHBOARD_KEY = settings.dashboard_key
CALLBACK_ENDPOINT = settings.callback_url
EXTENDED_RESPONSE = settings.extended_response

OPENAI_API_KEY = settings.openai_api_key
OPENAI_MODEL = settings.openai_model
GEMINI_API_KEY = settings.gemini_api_key
GEMINI_MODEL = settings.gemini_model
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
callback_service = CallbackService(
    callback_url=CALLBACK_ENDPOINT,
    timeout_seconds=settings.callback_timeout_seconds,
    max_attempts=settings.callback_max_attempts,
    backoff_base_seconds=settings.callback_backoff_base_seconds,
    max_workers=settings.callback_max_workers,
    enable_updates=settings.enable_callback_updates,
    max_updates=settings.callback_max_updates,
    session_manager=session_manager,
)
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


class DebugTextRequest(BaseModel):
    text: str


def _require_api_key(x_api_key: Optional[str]) -> None:
    # If API key is not configured, run in open mode.
    if not API_KEY:
        return
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _require_dashboard_key(x_dashboard_key: Optional[str]) -> None:
    if not DASHBOARD_KEY:
        raise HTTPException(status_code=503, detail="Dashboard key is not configured")
    if not x_dashboard_key or x_dashboard_key != DASHBOARD_KEY:
        raise HTTPException(status_code=401, detail="Invalid dashboard key")


def _openai_client() -> Optional[OpenAIClient]:
    if not OPENAI_API_KEY:
        return None
    return OpenAIClient(api_key=OPENAI_API_KEY, model=OPENAI_MODEL, timeout_seconds=LLM_TIMEOUT_SECONDS)


def _gemini_client() -> Optional[GeminiClient]:
    if not GEMINI_API_KEY:
        return None
    return GeminiClient(api_key=GEMINI_API_KEY, model=GEMINI_MODEL, timeout_seconds=LLM_TIMEOUT_SECONDS)


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


def _build_final_output(state: SessionState, total_messages: int) -> Dict[str, object]:
    engagement_duration = _engagement_duration_seconds(state)
    confidence = round(min(1.0, max(0.0, state.scam_confidence)), 2)
    return {
        "sessionId": state.session_id,
        "status": "completed" if state.finalized else "in_progress",
        "scamDetected": state.scam_detected,
        "scamType": state.scam_category,
        "confidenceLevel": confidence,
        "extractedIntelligence": state.intel.to_callback_payload(),
        "totalMessagesExchanged": total_messages,
        "engagementDurationSeconds": engagement_duration,
        "engagementMetrics": {
            "totalMessagesExchanged": total_messages,
            "engagementDurationSeconds": engagement_duration,
        },
        "agentNotes": state.agent_notes or build_agent_notes(state),
    }


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
        callback_service.send_async(stale, total_messages=total_messages)
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


@app.get("/dashboard")
async def dashboard_page() -> FileResponse:
    file_path = os.path.join(STATIC_DIR, "dashboard.html")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Dashboard UI not found")
    return FileResponse(file_path)


@app.get("/dashboard/api/summary", response_model=DashboardSummary)
async def dashboard_summary(x_dashboard_key: Optional[str] = Header(None)) -> DashboardSummary:
    _require_dashboard_key(x_dashboard_key)
    _auto_finalize_inactive_sessions()
    return dashboard_service.summary()


@app.get("/dashboard/api/sessions", response_model=List[DashboardSessionCard])
async def dashboard_sessions(
    limit: int = Query(default=50, ge=1, le=200),
    x_dashboard_key: Optional[str] = Header(None),
) -> List[DashboardSessionCard]:
    _require_dashboard_key(x_dashboard_key)
    _auto_finalize_inactive_sessions()
    return dashboard_service.list_sessions(limit=limit)


@app.get("/dashboard/api/sessions/{session_id}", response_model=DashboardSessionDetail)
async def dashboard_session_detail(
    session_id: str,
    x_dashboard_key: Optional[str] = Header(None),
) -> DashboardSessionDetail:
    _require_dashboard_key(x_dashboard_key)
    _auto_finalize_inactive_sessions()
    try:
        return dashboard_service.session_detail(session_id=session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")


@app.get("/dashboard/api/map", response_model=List[DashboardMapPoint])
async def dashboard_map(x_dashboard_key: Optional[str] = Header(None)) -> List[DashboardMapPoint]:
    _require_dashboard_key(x_dashboard_key)
    _auto_finalize_inactive_sessions()
    return dashboard_service.map_points()


# Debug endpoints (protected by dashboard key)
@app.post("/dashboard/api/debug/detect-scam")
async def debug_detect_scam(req: DebugTextRequest, x_dashboard_key: Optional[str] = Header(None)):
    _require_dashboard_key(x_dashboard_key)
    result = scam_detector.detect(req.text)
    behavior = behavior_analyzer.analyze(
        req.text,
        _openai_client() if ENABLE_LLM_BEHAVIOR_ANALYSIS else None,
        _gemini_client() if ENABLE_LLM_BEHAVIOR_ANALYSIS else None,
    )
    return {
        "isScam": result.is_scam,
        "confidence": result.confidence,
        "category": result.category,
        "score": result.score,
        "behaviorScore": behavior.score,
        "behaviorIndicators": behavior.indicators,
        "triggers": result.triggers,
        "suspiciousKeywords": result.suspicious_keywords,
    }


@app.post("/dashboard/api/debug/extract-intelligence")
async def debug_extract_intelligence(req: DebugTextRequest, x_dashboard_key: Optional[str] = Header(None)):
    _require_dashboard_key(x_dashboard_key)
    intel = Intelligence()
    extract_intelligence([req.text], intel)
    return {
        "callback": intel.to_callback_payload(),
        "extended": intel.to_extended_payload(),
    }


@app.get("/dashboard/api/debug/llm-gate")
async def debug_llm_gate(x_dashboard_key: Optional[str] = Header(None)):
    _require_dashboard_key(x_dashboard_key)
    return llm_call_gate.snapshot().to_dict()


@app.delete("/dashboard/api/debug/sessions")
async def debug_clear_sessions(x_dashboard_key: Optional[str] = Header(None)):
    _require_dashboard_key(x_dashboard_key)
    cleared = session_manager.clear()
    return {"status": "success", "cleared": cleared}


@app.post("/dashboard/api/debug/send-callback/{session_id}")
async def debug_send_callback(session_id: str, x_dashboard_key: Optional[str] = Header(None)):
    _require_dashboard_key(x_dashboard_key)
    state = session_manager.get(session_id)
    if not state:
        raise HTTPException(status_code=404, detail="Session not found")
    session_manager.finalize_and_close(state, build_agent_notes(state), total_messages=len(state.transcript))
    callback_service.send_async(state, total_messages=len(state.transcript))
    return {"status": "success"}


@app.post("/api/message")
async def handle_message(event: MessageEvent, x_api_key: Optional[str] = Header(None)):
    _require_api_key(x_api_key)
    request_deadline = time.time() + REQUEST_TIMEOUT_BUDGET_SECONDS
    session_manager.maybe_cleanup()
    _auto_finalize_inactive_sessions(skip_session_id=event.sessionId)
    openai_client = _openai_client()
    gemini_client = _gemini_client()

    state = session_manager.get_or_create(event.sessionId, _session_factory)

    # If we already closed the engagement, we keep replying politely but we do not keep extracting.
    if state.closed:
        session_manager.append_transcript(state, event.message.sender, event.message.text, event.message.timestamp)
        reply = _closed_reply(state)
        session_manager.append_transcript(state, "user", reply, int(time.time() * 1000), provider="rules")
        if state.finalized and not state.callback_sent:
            callback_service.send_async(
                state,
                total_messages=state.final_total_messages_exchanged or len(state.transcript),
            )
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
        openai_client if allow_behavior_llm else None,
        gemini_client if allow_behavior_llm else None,
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
        callback_payload, extended_payload = extract_structured_intelligence(
            text=event.message.text,
            openai=openai_client,
            gemini=gemini_client,
            timeout_hint_seconds=LLM_TIMEOUT_SECONDS,
        )
        session_manager.update_intel(
            state,
            lambda intel: (intel.merge_callback_payload(callback_payload), intel.merge_extended_payload(extended_payload)),
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
            openai_client,
            gemini_client,
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
        callback_service.send_async(state, total_messages=state.final_total_messages_exchanged or total_messages)

    response = {"status": "success", "reply": reply}
    if EXTENDED_RESPONSE:
        final_result = _build_final_output(state, state.final_total_messages_exchanged or total_messages)
        response.update(
            {
                "scamDetected": state.scam_detected,
                "scamCategory": state.scam_category,
                "scamConfidence": state.scam_confidence,
                "rollingScamScore": state.rolling_scam_score,
                "strategyState": state.strategy_state,
                "engagementComplete": state.finalized,
                "persona": state.persona_label,
                "replyProvider": state.reply_provider,
                "extractedIntelligence": state.intel.to_callback_payload(),
                "extendedIntelligence": state.intel.to_extended_payload(),
                "totalMessagesExchanged": total_messages,
                "finalResult": final_result,
                "llmLoadGate": llm_call_gate.snapshot().to_dict(),
            }
        )

    return response


@app.post("/")
async def root_entry(event: MessageEvent, x_api_key: Optional[str] = Header(None)):
    return await handle_message(event, x_api_key)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
