# Agentic Honey-Pot API

This project provides an API-first scam honeypot with:
- scam intent detection
- multi-persona autonomous engagement
- intelligence extraction
- mandatory GUVI final callback
- protected live operator dashboard

## Endpoints

### Core evaluator endpoints
- `GET /health`
- `POST /api/message`
- `POST /` (alias of `/api/message`)

### Dashboard endpoints
- `GET /dashboard`
- `GET /dashboard/api/summary`
- `GET /dashboard/api/sessions?limit=50`
- `GET /dashboard/api/sessions/{session_id}`
- `GET /dashboard/api/map`

Dashboard API endpoints require header `x-dashboard-key`.

## Environment Variables

### Required
- `HONEY_POT_API_KEY` or `API_KEY`
- `HONEY_POT_DASHBOARD_KEY` (for dashboard APIs)

### LLM (recommended)
- `OPENAI_API_KEY`
- `OPENAI_MODEL` (default: `gpt-4o-mini`)
- `GEMINI_API_KEY`
- `GEMINI_MODEL` (default: `gemini-1.5-flash`)

### Optional
- `AGENT_MAX_HISTORY_MESSAGES` (default: `12`)
- `LLM_TIMEOUT_SECONDS` (default: `10`)
- `ENABLE_LLM_EXTRACTION` (default: `true`)
- `LLM_EXTRACTION_MIN_INTERVAL_SECONDS` (default: `15`)
- `SESSION_TTL_SECONDS` (default: `21600`)
- `SESSION_CLEANUP_INTERVAL_SECONDS` (default: `60`)
- `HONEY_POT_CALLBACK_URL` (default GUVI callback URL)
- `CALLBACK_TIMEOUT_SECONDS` (default: `5`)
- `CALLBACK_MAX_ATTEMPTS` (default: `3`)
- `CALLBACK_BACKOFF_BASE_SECONDS` (default: `1`)
- `CALLBACK_MAX_WORKERS` (default: `4`)
- `ENABLE_CALLBACK_UPDATES` (default: `true`)
- `CALLBACK_MAX_UPDATES` (default: `2`)
- `HONEY_POT_EXTENDED_RESPONSE` (`true` to include extra debug fields in `/api/message` response)

## Local Run

This app auto-loads `.env` if present. Use `.env.example` as a template.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python main.py
```

## Local Smoke Test

```powershell
$headers = @{
  "x-api-key" = "your-api-key"
  "Content-Type" = "application/json"
}

$body = @{
  sessionId = "demo-session-1"
  message = @{
    sender = "scammer"
    text = "Your bank account will be blocked today. Verify immediately."
    timestamp = 1770005528731
  }
  conversationHistory = @()
  metadata = @{
    channel = "SMS"
    language = "English"
    locale = "IN"
  }
} | ConvertTo-Json -Depth 6

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/message" -Headers $headers -Body $body
```

Dashboard URL:
- `http://127.0.0.1:8000/dashboard`

## Tests

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

## Notes

- Reply generation failover order: OpenAI -> Gemini -> rule-based fallback.
- Session and metrics are in-memory by design for hackathon speed.
- API response contract remains minimal by default: `{"status":"success","reply":"..."}`.
- Final callback payload remains evaluator-compatible.

## Render Deployment (Docker)

1. Create a Render **Web Service** from this repo and select **Docker**.
2. Add environment variables in Render:
   - `API_KEY` (required)
   - `HONEY_POT_DASHBOARD_KEY` (recommended)
   - `OPENAI_API_KEY` and/or `GEMINI_API_KEY` (optional but recommended)
3. Deploy. Render will provide a public URL for the evaluator.
