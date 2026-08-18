# Agentic Honey-Pot

**Security teams receive massive volumes of threat intelligence but struggle to identify
relevant risks.** This is an AI honey-pot that engages scammers autonomously and then does
the three things that turn that noise into work a team can actually do:

| Problem statement | Where it lives |
|---|---|
| **Automatically correlates cyber events** | `services/incident_engine.py` — union-find over shared payment IDs, phones, domains, accounts and wallets; correlation is transitive |
| **Prioritises incidents** | 0–100 severity from attack type, breadth, velocity, captured intel and confidence → `CRITICAL / HIGH / MEDIUM / LOW`, ranked worst-first |
| **Recommends response actions** | A concrete response plan per incident: what to do, to which target, by whom, by when |

Everything below is the machinery that feeds it.

## What it does with volume

`POST /api/ingest` takes batches. The response is the **triage funnel** — the number a
team actually cares about:

```
11 raw events → 11 sessions → 3 incidents → 3 need action now → 8 concrete actions
                                             72.7% of raw volume never reaches an operator
```

Benign traffic produces no incident at all. `LOW` severity is kept and searchable but
marked `SUPPRESSED`, because a queue where everything is important is a queue nobody works.

Example plan for a correlated UPI campaign:

```
p1  FREEZE_UPI_HANDLE        mule.pay@ybl          30m   Payments fraud desk
p1  FILE_CYBERCRIME_REPORT   UPI_FRAUD campaign    60m   SOC lead
p3  ISSUE_CUSTOMER_ADVISORY  3 targeted sessions  240m   Comms / fraud awareness
```

Deadlines tighten with severity; actions come from the indicators actually captured, not
from the severity label alone.

## The rest of the system
- scam intent detection
- hybrid detection pipeline (rules + optional LLM behavior + rolling session risk)
- **multi-language Indian scam detection** - English, Hindi, Bengali, Tamil, Telugu, Marathi
  in native script, romanized, or code-mixed
- **incident declaration** - correlated alerts grouped into one named attack with a
  CRITICAL / HIGH / MEDIUM / LOW severity label
- multi-persona autonomous engagement, replying in the scammer's own language
- intelligence extraction
- our own report schema (`services/reporting.py`) — no external grader's contract
- open operator dashboard with charts, plus a live operator console

## Feature 3 - incident declaration and severity

`services/incident_engine.py` turns per-message alerts into declared incidents.

- **Correlate.** Sessions sharing a hard indicator - UPI ID, phone, bank account,
  crypto wallet, link domain, email - collapse into one incident via union-find, so
  linking is transitive (A shares a phone with B, B shares a UPI with C: all one attack).
- **Score.** 0-100 from five weighted parts, all returned in `scoreBreakdown`:

  | Component | Max | Meaning |
  |---|---|---|
  | `attackType` | 30 | digital arrest 30 > UPI 27 > bank 25 > KYC 22 > phishing 20 > refund 14 > lottery 12 |
  | `breadth` | 25 | how many sessions the campaign touches |
  | `velocity` | 20 | sessions per minute - how fast it is moving |
  | `intelValue` | 15 | distinct actionable indicators captured |
  | `confidence` | 10 | peak detection confidence in the cluster |

- **Declare.** `>=75 CRITICAL`, `>=50 HIGH`, `>=25 MEDIUM`, else `LOW`, plus a human name
  (`"UPI payment fraud campaign via mule.pay@ybl (2 sessions)"`) and a recommended action.
  Incidents are returned worst-first so operators work top down.

Incidents are derived on read from live session state - the session store is already the
source of truth, so there is no second store to fall out of sync.

## Feature 11 - multi-language scam detection

`agent/multilingual.py` scores vernacular scam vocabulary on the same scale as English,
so `"aapka account band ho jayega"` is as dangerous as `"your account will be blocked"`.

- **Language detection** by Unicode script range, with Hindi/Marathi disambiguated by
  marker words (both use Devanagari), and a romanized-marker fallback for Latin-script
  vernacular. No `langdetect`/fastText dependency.
- **Scam lexicon** per language covering native script *and* romanized spellings. Every
  lexicon is scanned on every message, so code-mixed text ("KYC pending hai, turant karo")
  scores on both halves.
- **Behaviour patterns** (urgency, authority, reward bait, verification pressure) match
  vernacular equivalents, not just English.
- **The agent replies in the detected language** - the LLM is instructed to match the
  scammer's language and script, and the deterministic fallback ships per-language reply
  banks so a throttled Hindi session never suddenly answers in English.

Try it live in the dashboard's *Multi-language detector* panel, or:
`POST /dashboard/api/debug/detect-scam` with `{"text": "..."}`.

## Endpoints

### Core
- `GET /health`
- `POST /api/message` — one event, returns the persona's reply
- `POST /api/ingest` — a batch of events, returns the triage funnel and ranked incidents
- `GET /api/report/threat` — every declared incident with its response plan
- `GET /api/report/session/{id}` — full report for one session

These honour `x-api-key` when `API_KEY` is configured.

### UI
- `GET /dashboard` — operations dashboard (charts, incidents, sessions)
- `GET /console` — operator console: drive conversations, replay campaigns, watch triage

### Dashboard endpoints
- `GET /dashboard`
- `GET /dashboard/api/summary`
- `GET /dashboard/api/sessions?limit=50`
- `GET /dashboard/api/sessions/{session_id}`
- `GET /dashboard/api/incidents` - declared incidents, worst severity first
- `GET /dashboard/api/map`
- `GET /dashboard/api/models` - OpenRouter free-model chain and its health
- `POST /dashboard/api/debug/detect-scam` - `{"text": "..."}`, returns score + detected language
- `GET /dashboard/api/debug/llm-gate`

Dashboard endpoints are **open** - no key. They serve read-only telemetry from an
in-memory store and hold no secrets. `POST /api/message` still enforces `x-api-key`
when one is configured.

## Environment Variables

### Required
- `HONEY_POT_API_KEY` or `API_KEY` (optional; if set, request must include `x-api-key`)

### LLM - OpenRouter free models (recommended)
- `OPENROUTER_API_KEY` - get one at <https://openrouter.ai/keys>
- `OPENROUTER_MODELS` - optional comma-separated override of the fallback chain

All three LLM stages (reply, behaviour analysis, structured extraction) go through a
single `OpenRouterClient`. It walks the free-model chain until one answers, then sticks
to that model. A model returning 400/401/403/404 (bad or retired slug) is dropped for the
process lifetime; 429/5xx benches it for 120s. Free-tier slugs churn, so
`GET /dashboard/api/models` shows the configured chain against what OpenRouter currently
advertises as free.

Default chain (from `openrouter_free_models.txt`, chat-capable entries only - the
embedding, rerank and content-safety models in that list cannot do chat completion):

```
z-ai/glm-5.2:free, nvidia/nemotron-3-super:free, google/gemma-4-31b:free,
nvidia/nemotron-3-nano-30b-a3b:free, google/gemma-4-26b-a4b:free,
poolside/laguna-xs-2.1:free, nvidia/nemotron-nano-9b-v2:free,
cohere/north-mini-code:free, openai/gpt-oss-20b:free
```

### Optional
- `AGENT_MAX_HISTORY_MESSAGES` (default: `12`)
- `LLM_TIMEOUT_SECONDS` (default: `12`)
- `REQUEST_TIMEOUT_BUDGET_SECONDS` (default: `26`, caps optional LLM stages so a slow model never hangs a request)
- `ENABLE_LLM_BEHAVIOR_ANALYSIS` (default: `true`)
- `HIGH_LOAD_MODE` (default: `false`)
- `LLM_GLOBAL_RPM_LIMIT` (default: `26`)
- `LLM_REPLY_RPM_LIMIT` (default: `18`)
- `LLM_BEHAVIOR_RPM_LIMIT` (default: `8`)
- `LLM_EXTRACTION_RPM_LIMIT` (default: `6`)
- `LLM_BEHAVIOR_SAMPLE_EVERY_N_SCAM_MESSAGES` (default: `2`)
- `FAST_SESSION_CLOSE` (default: `true`, closes scam sessions by turn/message thresholds even when duration is short)
- `ENABLE_LLM_EXTRACTION` (default: `true`)
- `LLM_EXTRACTION_MIN_INTERVAL_SECONDS` (default: `15`)
- `INACTIVITY_FINALIZE_SECONDS` (default: `120`, set `0` to disable inactivity auto-finalize)
- `SESSION_TTL_SECONDS` (default: `21600`)
- `SESSION_CLEANUP_INTERVAL_SECONDS` (default: `60`)
- `HONEY_POT_EXTENDED_RESPONSE` (`true` to include the full session report in `/api/message` responses)

## Local Run

This app auto-loads `.env` if present. Use `.env.example` as a template.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python main.py
```

## Report schema

`schemaVersion: honeypot-report/1.0`. A session report is shaped around the three
questions, not around any external contract:

```jsonc
{
  "schemaVersion": "honeypot-report/1.0",
  "sessionId": "camp-b1",
  "status": "active",
  "detection":  { "scamDetected": true, "category": "UPI_FRAUD", "confidence": 1.0,
                  "riskScore": 21.07, "strategyState": "High Confidence Scam", "triggers": [] },
  "language":   { "code": "hi", "name": "Hindi", "confidence": 0.9, "vernacularScore": 13.0 },
  "engagement": { "persona": "...", "agentTurns": 1, "totalMessages": 2, "replyProvider": "rules" },
  "indicators": { "upiIds": ["scam.desk@ybl"], "phoneNumbers": [], "phishingLinks": [] },
  "incident":   { "incidentId": "INC-289BACA8", "severity": "HIGH", "triage": "ACTION_REQUIRED",
                  "responsePlan": [ { "action": "FREEZE_UPI_HANDLE", "target": "scam.desk@ybl",
                                      "owner": "Payments fraud desk", "priority": 1,
                                      "slaMinutes": 30, "rationale": "..." } ] },
  "analystNotes": "..."
}
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

URLs:
- Dashboard (no key needed): `http://127.0.0.1:8000/dashboard`
- Operator console: `http://127.0.0.1:8000/console`

The **console** is the fastest way to see the whole loop: send a scam message in any
supported language and watch the persona reply and the detection update, or hit one
"replay campaign" button to fire a multi-session attack through `/api/ingest` and watch
sessions collapse into one scored incident with a response plan. A *Benign noise*
scenario is included to show it stays quiet on ordinary traffic.

The dashboard shows declared incidents with severity and score breakdown, severity /
category / language charts, a 1-hour activity timeline, per-session transcripts, the
model chain state, and a live multi-language detector probe. Charts are hand-rolled SVG
with no CDN, so it works on a box with no outbound internet.

## Tests

```powershell
python -m unittest discover -s tests -p "test_*.py"

# module self-checks
python -m agent.multilingual
python -m services.incident_engine
python -m services.reporting
```

## Notes

- Reply generation: OpenRouter free-model chain -> deterministic per-language fallback.
  The fallback is a safety net for an exhausted free tier, not a primary path: without it
  a rate-limited session would return no reply and the engagement would die.
- Detection is progressive: per-message rule score + optional LLM behavior score + rolling session score.
- Conversation strategy state machine: `Neutral`, `Suspicious`, `Extraction Mode`, `High Confidence Scam`, `Intelligence Harvest Mode`.
- High-load mode can rate-limit LLM calls and degrade to rule-based behavior while keeping API responses stable.
- Inactivity auto-finalize closes stale scam sessions when no new messages arrive for the configured window.
- Session and metrics are in-memory by design for speed.
- `/api/message` stays minimal by default: `{"status":"success","reply":"..."}`.
  Set `HONEY_POT_EXTENDED_RESPONSE=true` to get the full session report inline.
- Indicators extracted: phone numbers, bank accounts + IFSC, UPI IDs, phishing links,
  email addresses, case/reference IDs, policy and order numbers, crypto wallets, amounts.

## Render Deployment (Docker)

1. Create a Render **Web Service** from this repo and select **Docker**.
2. Add environment variables in Render:
   - `API_KEY` (required)
   - `OPENROUTER_API_KEY` (recommended - without it replies use the scripted fallback)
3. Deploy. Render provides a public URL; the dashboard and console are served from it.
