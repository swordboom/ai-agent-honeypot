# Agentic Honey-Pot — AI SOC for Cyber Threat Intelligence

> **Problem statement.** *Security teams receive massive volumes of threat
> intelligence but struggle to identify relevant risks. Develop AI that automatically
> correlates cyber events, prioritises incidents and recommends response actions — an
> AI Security Operations Centre (SOC) with behavioural analytics and automated
> investigation.*

This project is that SOC. It **generates** its own high-value intelligence by luring
scammers with autonomous AI personas, **ingests** technical security events (auth
bursts, credential stuffing) through the same door, then does the four things a SOC
exists to do — correlate, prioritise, investigate, and recommend a response — and
presents the result as a worked case queue an operator can act on top-down.

Everything runs **offline and deterministic** by default (no DNS, no HTTP, no external
feed): the LLM is an optional enhancement, and the charts, detection, correlation and
enrichment all work on a box with no outbound internet.

## How it maps to the problem statement

| The statement asks for… | Where it lives | Verifiable in |
|---|---|---|
| **Correlates cyber events** | `services/incident_engine.py` — union-find over shared UPI IDs, phones, domains, accounts, wallets, IPs, usernames; transitive | `GET /api/report/threat`, `/dashboard` |
| **Prioritises incidents** | 0–100 severity from attack type, breadth, velocity, intel value, confidence → `CRITICAL/HIGH/MEDIUM/LOW`, worst-first | `scoreBreakdown` on every incident |
| **Recommends response actions** | Per-incident response plan: action, target, owner, SLA, rationale — built from the indicators actually captured | `responsePlan` on every incident |
| **Behavioural analytics (UEBA)** | `services/behavioral_analytics.py` — per-entity anomaly from fan-out/fan-in, velocity, cross-source, novelty, breach | `GET /dashboard/api/soc/entities` |
| **Automated investigation** | `services/investigation.py` — pivots indicators, enriches them, builds a timeline, writes a verdict + narrative + next steps | `GET /dashboard/api/soc/case/{id}` |
| **SOC surface** | `services/soc.py` + `/soc` console — case queue, KPIs (MTTD/MTTR proxies, automation rate) | `GET /soc`, `GET /dashboard/api/soc/overview` |

---

## How the system works (the pipeline)

There are **four ways in**, one correlation core, and a SOC layer on top. Everything
downstream is derived on read from a single in-memory session store, so there is no
second store to fall out of sync.

```
                 ┌─────────────────────── inputs ───────────────────────┐
 scammer message │  POST /api/message   → honeypot engagement + detection │
 event batch     │  POST /api/ingest    → social + technical events       │
 URL / domain    │  POST /api/scan/url  → offline phishing scoring         │
 raw email       │  POST /api/scan/email→ header / SPF / spoof analysis    │
                 └───────────────────────────┬───────────────────────────┘
                                              ▼
  language detect → scam classify → intel extract → strategy state → AI reply
                                              ▼
                              SessionState (in-memory store)
                                              ▼
        ┌──────────────────────── SOC core (derived on read) ────────────────────────┐
        │  incident_engine   correlate (union-find) → score 0-100 → declare severity  │
        │  behavioral_analytics   per-entity UEBA anomaly profiles                    │
        │  threat_intel   offline enrichment / feed match per indicator               │
        │  investigation   pivot + enrich + timeline → verdict + narrative + steps    │
        │  soc   case queue + KPIs + triage funnel                                    │
        └──────────────────────────────────────┬─────────────────────────────────────┘
                                                ▼
              /soc console · /dashboard · /console · /api/report/threat
```

**The triage funnel** is the number a drowning team actually cares about — how much
volume never reaches an operator. `POST /api/ingest` returns it directly:

```
11 raw events → 11 sessions → 3 incidents → 3 need action now → 8 concrete actions
                                            72.7% of raw volume never reaches an operator
```

Benign traffic produces **no incident at all**; `LOW` severity is kept and searchable
but marked `SUPPRESSED`, because a queue where everything is important is a queue nobody
works.

---

## Project structure

```
ai-agent-honeypot/
├── main.py                     FastAPI app: all routes, request pipeline, startup/shutdown
├── config.py                   Settings.from_env() + minimal .env loader (no dependency)
├── requirements.txt            fastapi, uvicorn, pydantic, requests
├── runtime.txt / Dockerfile    Python 3.11 pin + container build for Render
├── sessions_snapshot.json      auto-saved in-memory store (restored on startup)
│
├── agent/                      the AI honeypot + detection brain
│   ├── scam_detector.py          rule-based multilingual scam scoring
│   ├── multilingual.py           language detection + vernacular scam lexicons (6 languages)
│   ├── behavior_analyzer.py      rule + optional-LLM behavioural intent scoring
│   ├── intelligence_extractor.py regex extraction of UPI/phone/account/link/etc.
│   ├── structured_extractor.py   optional LLM structured intel extraction
│   ├── personas.py               victim personas (retired teacher, shop owner, …)
│   ├── reply_agent.py            LLM reply → deterministic per-language fallback
│   ├── llm_clients.py            OpenRouter free-model chain with health/failover
│   └── notes.py                  analyst-note generation on session close
│
├── services/                   the SOC core
│   ├── incident_engine.py        ★ correlate (union-find) + score + declare + response plan
│   ├── behavioral_analytics.py   ★ UEBA — per-entity anomaly profiles
│   ├── threat_intel.py           ★ offline threat-intel enrichment + bundled feed
│   ├── investigation.py          ★ automated investigation (timeline, verdict, narrative)
│   ├── soc.py                    ★ SOC orchestration — case queue + KPIs
│   ├── session_manager.py        thread-safe in-memory session store
│   ├── reporting.py              our own report schema (honeypot-report/1.1)
│   ├── dashboard_service.py      aggregates metrics/charts for the dashboard
│   ├── technical_ingest.py       technical event → SessionState (no engagement path)
│   ├── technical_detector.py     classifies auth bursts (stuffing / brute force)
│   ├── url_scanner.py            offline URL/domain phishing scoring
│   ├── email_scanner.py          raw RFC-2822 email header / spoof analysis
│   ├── engagement_policy.py      when to finalise a session
│   ├── strategy_state.py         conversation strategy state machine
│   ├── llm_load_control.py       per-stage RPM gating for high-load mode
│   └── persistence.py            JSON snapshot save/restore
│
├── models/                     pydantic + dataclass schemas
│   ├── api.py                     MessageEvent / Message / Metadata (wire in)
│   ├── technical.py              TechnicalEvent (technical feed wire model)
│   ├── session.py               SessionState + Intelligence (the case record)
│   └── dashboard.py             dashboard response models
│
├── simulator/
│   └── technical_events.py      synthetic technical events for demos/tests
│
├── static/                     hand-rolled UIs (no framework, no CDN)
│   ├── soc.html / soc.js         SOC console — case queue, KPIs, UEBA, investigation drawer
│   ├── dashboard.* (html/js/css) operations dashboard — charts, incidents, sessions
│   ├── console.* (html/js)       operator console — drive conversations, replay campaigns
│   └── sentinel.* (html/js/css)  "Cyber Sentinel" landing/ops view (served at / and /sentinel)
│
└── tests/
    ├── test_app.py               core pipeline, detection, reporting (29 tests)
    ├── test_technical_contract.py technical ingest + cross-source correlation (14 tests)
    └── test_soc.py               SOC layer: enrichment, UEBA, investigation, endpoints (17 tests)
```

★ = the modules that directly implement the problem statement.

---

## Running the project

### Prerequisites
- **Python 3.11** (see `runtime.txt`)
- Windows PowerShell examples below; the equivalents work on macOS/Linux.

### 1. Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure (optional)

The app auto-loads a local `.env` if present — copy `.env.example` to `.env`. **Nothing
is required to run**: with no API key the API is open, and with no OpenRouter key the
honeypot replies from its deterministic per-language fallback.

```powershell
Copy-Item .env.example .env
# then edit .env to set API_KEY (enables x-api-key) and GROQ_API_KEY (live LLM replies)
```

### 3. Run

```powershell
python main.py
```

Server starts on `http://127.0.0.1:8000` (override with `PORT`). Open one of the UIs:

| URL | What it is |
|---|---|
| `http://127.0.0.1:8000/soc` | **SOC console** — case queue, KPIs, UEBA, investigation drawer |
| `http://127.0.0.1:8000/dashboard` | Operations dashboard — charts, incidents, sessions |
| `http://127.0.0.1:8000/console` | Operator console — send scam messages, replay campaigns |

All UIs are open (read-only telemetry). Only `POST /api/*` enforces `x-api-key`, and
only when `API_KEY`/`HONEY_POT_API_KEY` is set.

### 4. See the whole loop in 30 seconds

Open `/console` and click a **replay campaign** button — it fires a multi-session attack
through `/api/ingest`. Watch the sessions collapse into one scored incident with a
response plan, then open `/soc` to see it as a case with an automated verdict. The
*Benign noise* scenario shows the system stays quiet on ordinary traffic.

Or drive it from the shell (PowerShell):

```powershell
$headers = @{ "x-api-key" = "your-api-key"; "Content-Type" = "application/json" }
$body = @{
  sessionId = "demo-1"
  message = @{ sender = "scammer"; text = "Your bank account will be blocked today. Verify KYC immediately at http://sbi-verify.tk"; timestamp = 1770005528731 }
  conversationHistory = @()
  metadata = @{ channel = "SMS"; locale = "IN" }
} | ConvertTo-Json -Depth 6
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/message" -Headers $headers -Body $body
```

### 5. Run the tests

```powershell
python -m unittest discover -s tests -p "test_*.py"    # 60 tests

# module self-checks (each runs a built-in assertion suite)
python -m agent.multilingual
python -m services.incident_engine
python -m services.reporting
python -m services.threat_intel
python -m services.behavioral_analytics
python -m services.investigation
python -m services.soc
```

> **Note for this repo's dev machine:** a persistent OS-level `HONEY_POT_API_KEY`
> environment variable takes precedence over `API_KEY` (see `config.py`). The test
> files pin **both** so the suite is hermetic; if you add a test that hits an
> authenticated endpoint, pin `HONEY_POT_API_KEY` too.

---

## The four SOC capabilities in depth

### 1. Correlation, scoring and response — `services/incident_engine.py`

Detection produces per-message alerts; that is noise until someone says "these forty
alerts are *one attack*" and ranks it.

- **Correlate.** Sessions sharing a hard indicator — UPI ID, phone, bank account,
  crypto wallet, link domain, email, IP, username — collapse into one incident via
  union-find, so linking is **transitive** (A shares a phone with B, B shares a UPI with
  C → all one attack). Keywords are excluded on purpose (every phishing message says
  "verify"), so they never merge unrelated attacks.
- **Score.** 0–100 from five weighted parts, all returned in `scoreBreakdown`:

  | Component | Max | Meaning |
  |---|---|---|
  | `attackType` | 30 | digital arrest 30 > UPI 27 > bank 25 > KYC 22 > phishing 20 > refund 14 > lottery 12 |
  | `breadth` | 25 | how many sessions/targets the campaign touches |
  | `velocity` | 20 | events per minute — how fast it is moving |
  | `intelValue` | 15 | distinct actionable indicators captured |
  | `confidence` | 10 | peak detection confidence in the cluster |

- **Declare.** `≥75 CRITICAL`, `≥50 HIGH`, `≥25 MEDIUM`, else `LOW`, plus a human name
  (`"UPI payment fraud campaign via mule.pay@ybl (2 sessions)"`).
- **Recommend.** A response plan built from the indicators actually captured, deadlines
  tightening with severity:

  ```
  p1  FREEZE_UPI_HANDLE        mule.pay@ybl          30m   Payments fraud desk
  p1  FILE_CYBERCRIME_REPORT   UPI_FRAUD campaign    60m   SOC lead
  p3  ISSUE_CUSTOMER_ADVISORY  3 targeted sessions  240m   Comms / fraud awareness
  ```

### 2. Behavioural analytics / UEBA — `services/behavioral_analytics.py`

Profiles each **entity** (IP, username, UPI, account, domain, phone) across every
session and scores anomaly 0–100 from signals a UEBA engine weighs: **fan-out** (one
source → many accounts = spray/stuffing), **fan-in** (one account ← many sources),
**velocity** above a human baseline, **cross-source** presence (same entity in the
honeypot *and* the technical feed — strong corroboration), **breadth**, an eventual auth
**success**, and **novelty**. This is a different axis from message-content scam
detection — it scores *infrastructure behaviour*, not text.

### 3. Threat-intel enrichment — `services/threat_intel.py`

Enriches any indicator against a **bundled offline feed**: known-bad domains, abused
TLDs, brand look-alike detection (Levenshtein against Indian bank brands), label
entropy, bogon/reserved IP ranges, disposable/freemail senders, lure-keyword UPI
handles. Returns a `MALICIOUS / SUSPICIOUS / UNKNOWN / BENIGN` verdict with reasons.
Swap `_KNOWN_BAD_*` for a real MISP/STIX pull behind the same signature when a network
is available.

### 4. Automated investigation — `services/investigation.py`

Takes a declared incident and *investigates* it: pivots on every shared indicator, pulls
its enrichment and the UEBA profile of each entity, lays the events on a **timeline**,
combines the independent lines of evidence (detection confidence + feed hits + entity
anomaly + cross-source agreement) into a **verdict** (`TRUE_POSITIVE / LIKELY_THREAT /
INCONCLUSIVE / LIKELY_BENIGN`) with a confidence, writes an analyst **narrative**, and
emits concrete **next investigative steps** — distinct from the *response* plan
(investigation is "find out", response is "act").

`services/soc.py` runs all four together into the **case queue** and **SOC KPIs**
(detection-latency / containment-window proxies, open vs. contained, analyst queue
depth, automation rate = share of volume handled without a human, confirmed-threat
count). See it live at **`/soc`**.

---

## The other input paths

- **Multi-language scam detection** (`agent/multilingual.py`) — English, Hindi, Bengali,
  Tamil, Telugu, Marathi in native script, romanised, or code-mixed. Language detection
  by Unicode script range (Hindi/Marathi disambiguated by marker words), per-language
  scam lexicons scanned on every message, and **the agent replies in the detected
  language**. Try it: `POST /dashboard/api/debug/detect-scam` with `{"text": "..."}`.
- **Technical feed ingestion** (`services/technical_ingest.py`) — auth-failure bursts,
  credential stuffing and brute force enter through the *same* `/api/ingest` door and
  the *same* correlation core, so a phishing domain seen in a scam chat and in an auth
  burst collapse into one **Mixed** incident.
- **URL/domain scanner** (`services/url_scanner.py`) and **email analyser**
  (`services/email_scanner.py`) — both fully offline; risky results feed the correlator.

---

## API reference

### Core (honour `x-api-key` when a key is configured)
- `GET  /health`
- `POST /api/message` — one event, returns the persona's reply
- `POST /api/ingest` — a batch of events, returns the triage funnel and ranked incidents
- `POST /api/scan/url` — `{"url": "..."}`, offline phishing scoring + correlation
- `POST /api/scan/email` — `{"rawEmail": "..."}`, header/spoof analysis + correlation
- `GET  /api/report/threat` — every declared incident with its response plan + funnel
- `GET  /api/report/session/{id}` — full report for one session

### UI
- `GET /` and `GET /sentinel` — Cyber Sentinel landing/ops view
- `GET /soc` — SOC console
- `GET /dashboard` — operations dashboard
- `GET /console` — operator console

### SOC endpoints (open, read-only telemetry)
- `GET  /dashboard/api/soc/overview` — KPIs, case queue, UEBA entity risk, triage funnel
- `GET  /dashboard/api/soc/case/{incident_id}` — one case file with its automated investigation
- `GET  /dashboard/api/soc/entities?limit=50` — ranked UEBA entity profiles
- `POST /dashboard/api/soc/enrich` — `{"kind": "...", "value": "..."}`, ad-hoc enrichment

### Dashboard endpoints (open, read-only telemetry)
- `GET  /dashboard/api/summary`
- `GET  /dashboard/api/sessions?limit=50` and `/dashboard/api/sessions/{id}`
- `GET  /dashboard/api/incidents` — declared incidents, worst severity first
- `GET  /dashboard/api/map` — phone number → country origin table
- `GET  /dashboard/api/models` — OpenRouter free-model chain and its health
- `POST /dashboard/api/debug/detect-scam` · `POST /dashboard/api/debug/extract-intelligence`
- `GET  /dashboard/api/debug/llm-gate` · `DELETE /dashboard/api/debug/sessions`

Dashboard and SOC endpoints are **open** — they serve read-only telemetry from an
in-memory store and hold no secrets. `POST /api/*` still enforces `x-api-key` when one
is configured.

---

## Report schema

`schemaVersion: honeypot-report/1.1`. A session report is shaped around the questions a
team actually asks — *what did we see / does it matter / what do we do* — not around any
external contract:

```jsonc
{
  "schemaVersion": "honeypot-report/1.1",
  "sessionId": "camp-b1",
  "sourceType": "honeypot",
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

---

## Environment variables

Set in `.env` (auto-loaded) or the process environment. **All are optional** — the app
runs with none of them.

### Auth
- `HONEY_POT_API_KEY` or `API_KEY` — if set, `POST /api/*` requires a matching
  `x-api-key` header. `HONEY_POT_API_KEY` takes precedence.

### LLM — Groq or OpenRouter (recommended, not required)
Both speak the OpenAI chat-completions wire format, so one client serves both. Groq is
tried first when its key is set; OpenRouter's free tier caps at 50 requests/day per
account, which one afternoon of testing exhausts.
- `GROQ_API_KEY` — get one at <https://console.groq.com/keys>.
- `GROQ_MODELS` — comma-separated override. Default `openai/gpt-oss-120b`.
- `GROQ_REASONING_EFFORT` — `low` (default) / `medium` / `high`. Higher settings spend the
  reply budget on chain-of-thought and get rejected by `sanitize_reply`.
- `OPENROUTER_API_KEY` — fallback provider, used only when `GROQ_API_KEY` is empty.
  Get one at <https://openrouter.ai/keys>.
- `OPENROUTER_MODELS` — comma-separated override of the free-model fallback chain.

Without either key, replies use the deterministic per-language fallback.

All three LLM stages (reply, behaviour analysis, structured extraction) go through one
`OpenRouterClient`. It walks the free-model chain until one answers, then sticks to it. A
model returning 400/401/403/404 is dropped for the process lifetime; 429/5xx benches it
for 120s. `GET /dashboard/api/models` shows the configured chain vs. what OpenRouter
currently advertises as free.

### Behaviour / tuning (defaults shown)
- `AGENT_MAX_HISTORY_MESSAGES=12` · `LLM_TIMEOUT_SECONDS=12` · `REQUEST_TIMEOUT_BUDGET_SECONDS=26`
- `ENABLE_LLM_BEHAVIOR_ANALYSIS=true` · `ENABLE_LLM_EXTRACTION=true` · `LLM_EXTRACTION_MIN_INTERVAL_SECONDS=15`
- `HIGH_LOAD_MODE=false` and the RPM caps: `LLM_GLOBAL_RPM_LIMIT=26`, `LLM_REPLY_RPM_LIMIT=18`,
  `LLM_BEHAVIOR_RPM_LIMIT=8`, `LLM_EXTRACTION_RPM_LIMIT=6`, `LLM_BEHAVIOR_SAMPLE_EVERY_N_SCAM_MESSAGES=2`
- `FAST_SESSION_CLOSE=true` · `INACTIVITY_FINALIZE_SECONDS=120` (0 disables)
- `SESSION_TTL_SECONDS=21600` · `SESSION_CLEANUP_INTERVAL_SECONDS=60`
- `HONEY_POT_EXTENDED_RESPONSE=false` (`true` inlines the full session report in `/api/message`)
- `PORT=8000`

---

## Design notes

- **Offline-first.** Detection, correlation, UEBA, enrichment and the charts need no
  network. The LLM only improves reply quality and optional behaviour/extraction; the
  deterministic fallback keeps a rate-limited session alive.
- **Derived on read.** Incidents, entity profiles and investigations are recomputed from
  the live session store on each request — one source of truth, no second store to
  desync. Measured cost: ~0.4 ms at 30 sessions, ~9 ms at 1000.
- **Progressive detection.** Per-message rule score + optional LLM behaviour score +
  rolling session score. Strategy state machine: `Neutral → Suspicious → Extraction Mode
  → High Confidence Scam → Intelligence Harvest Mode`.
- **In-memory by design** for speed, with a JSON snapshot saved every 60s and on
  shutdown, restored on startup.
- **Indicators extracted:** phone numbers, bank accounts + IFSC, UPI IDs, phishing links,
  emails, case/reference IDs, policy and order numbers, crypto wallets, amounts, plus
  technical IPs / usernames / file hashes / endpoints.

---

## Render deployment (Docker)

1. Create a Render **Web Service** from this repo and select **Docker**.
2. Add environment variables in Render:
   - `API_KEY` (recommended, to lock down `POST /api/*`)
   - `GROQ_API_KEY` (optional — without it replies use the scripted fallback)
   - `OPENROUTER_API_KEY` (optional fallback provider)
3. Deploy. Render provides a public URL; the SOC console, dashboard and console are all
   served from it.
