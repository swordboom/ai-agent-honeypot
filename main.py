import logging
import os
import time
from typing import Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent.intelligence_extractor import extract_intelligence
from agent.llm_clients import GeminiClient, OpenAIClient
from agent.notes import build_agent_notes
from agent.personas import assign_persona
from agent.reply_agent import (
    build_tactical_hint,
    generate_agent_reply,
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
from services.session_manager import SessionManager

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

ENABLE_LLM_EXTRACTION = settings.enable_llm_extraction
LLM_EXTRACTION_MIN_INTERVAL_SECONDS = settings.llm_extraction_min_interval_seconds

session_manager = SessionManager(
    session_ttl_seconds=settings.session_ttl_seconds,
    cleanup_interval_seconds=settings.session_cleanup_interval_seconds,
)
scam_detector = ScamDetector()
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

app = FastAPI(title=APP_NAME)

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class DebugTextRequest(BaseModel):
    text: str


def _require_api_key(x_api_key: Optional[str]) -> None:
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


def _compute_total_messages(event: MessageEvent) -> int:
    # history + current + our reply
    return len(event.conversationHistory) + 2


def _session_factory(session_id: str) -> SessionState:
    persona = assign_persona(session_id)
    return SessionState(
        session_id=session_id,
        persona_id=persona.id,
        persona_label=f"{persona.display_name} ({persona.age_profile})",
    )


def _closed_reply(state: SessionState) -> str:
    if state.persona_id == "busy_shop_owner":
        return "I will go to the bank branch now. I cannot message more right now."
    if state.persona_id == "retired_teacher":
        return "I will visit the bank and check. I will reply later."
    return "I will check this with the bank. Please wait."


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
    return dashboard_service.summary()


@app.get("/dashboard/api/sessions", response_model=List[DashboardSessionCard])
async def dashboard_sessions(
    limit: int = Query(default=50, ge=1, le=200),
    x_dashboard_key: Optional[str] = Header(None),
) -> List[DashboardSessionCard]:
    _require_dashboard_key(x_dashboard_key)
    return dashboard_service.list_sessions(limit=limit)


@app.get("/dashboard/api/sessions/{session_id}", response_model=DashboardSessionDetail)
async def dashboard_session_detail(
    session_id: str,
    x_dashboard_key: Optional[str] = Header(None),
) -> DashboardSessionDetail:
    _require_dashboard_key(x_dashboard_key)
    try:
        return dashboard_service.session_detail(session_id=session_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")


@app.get("/dashboard/api/map", response_model=List[DashboardMapPoint])
async def dashboard_map(x_dashboard_key: Optional[str] = Header(None)) -> List[DashboardMapPoint]:
    _require_dashboard_key(x_dashboard_key)
    return dashboard_service.map_points()


# Debug endpoints (protected by dashboard key)
@app.post("/dashboard/api/debug/detect-scam")
async def debug_detect_scam(req: DebugTextRequest, x_dashboard_key: Optional[str] = Header(None)):
    _require_dashboard_key(x_dashboard_key)
    result = scam_detector.detect(req.text)
    return {
        "isScam": result.is_scam,
        "confidence": result.confidence,
        "category": result.category,
        "score": result.score,
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
    session_manager.maybe_cleanup()

    state = session_manager.get_or_create(event.sessionId, _session_factory)

    # If we already closed the engagement, we keep replying politely but we do not keep extracting.
    if state.closed:
        session_manager.append_transcript(state, event.message.sender, event.message.text, event.message.timestamp)
        reply = _closed_reply(state)
        session_manager.append_transcript(state, "user", reply, int(time.time() * 1000), provider="rules")
        if state.finalized and not state.callback_sent:
            callback_service.send_async(
                state,
                total_messages=state.final_total_messages_exchanged or _compute_total_messages(event),
            )
        return {"status": "success", "reply": reply}

    session_manager.seed_history_if_needed(state, event.conversationHistory)
    session_manager.append_transcript(state, event.message.sender, event.message.text, event.message.timestamp)

    scammer_texts = _collect_scammer_texts(event)
    detection = scam_detector.detect(scammer_texts)
    session_manager.update_detection(
        state,
        is_scam=detection.is_scam,
        confidence=detection.confidence,
        category=detection.category,
        triggers=detection.triggers,
        suspicious_keywords=detection.suspicious_keywords,
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
    ):
        callback_payload, extended_payload = extract_structured_intelligence(
            text=event.message.text,
            openai=_openai_client(),
            gemini=_gemini_client(),
            timeout_hint_seconds=LLM_TIMEOUT_SECONDS,
        )
        session_manager.update_intel(
            state,
            lambda intel: (intel.merge_callback_payload(callback_payload), intel.merge_extended_payload(extended_payload)),
        )
        session_manager.update_llm_extraction_time(state)

    if state.scam_detected:
        reply, provider = generate_agent_reply(
            state,
            event.metadata,
            _openai_client(),
            _gemini_client(),
            max_history=AGENT_MAX_HISTORY_MESSAGES,
        )
    else:
        reply, provider = (
            "Sorry, I am not sure I understand. Can you clarify what this is about?",
            "rules",
        )

    session_manager.set_reply_provider(state, provider)

    if state.scam_detected:
        session_manager.increment_agent_turn(state)

    session_manager.append_transcript(state, "user", reply, int(time.time() * 1000), provider=provider)

    total_messages = _compute_total_messages(event)

    if should_finalize(state):
        session_manager.finalize_and_close(state, build_agent_notes(state), total_messages=total_messages)
        callback_service.send_async(state, total_messages=state.final_total_messages_exchanged or total_messages)

    response = {"status": "success", "reply": reply}
    if EXTENDED_RESPONSE:
        response.update(
            {
                "scamDetected": state.scam_detected,
                "scamCategory": state.scam_category,
                "scamConfidence": state.scam_confidence,
                "engagementComplete": state.finalized,
                "persona": state.persona_label,
                "replyProvider": state.reply_provider,
                "extractedIntelligence": state.intel.to_callback_payload(),
                "extendedIntelligence": state.intel.to_extended_payload(),
                "totalMessagesExchanged": total_messages,
            }
        )

    return response


@app.post("/")
async def root_entry(event: MessageEvent, x_api_key: Optional[str] = Header(None)):
    return await handle_message(event, x_api_key)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
