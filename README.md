# OneEye360 — Autonomous AI Security Operations

Autonomous AI security operations for businesses that live online: pentest agents that find and verify weaknesses, an AI WAF that blocks live attacks, and a dashboard an owner can actually read — built to the OneEye360 Gate-1 plan (see `Gate1-WriteUp-OneEye360.pdf`).

## Product Components (per plan §08)

```
┌────────────────────────────────────────────────────────────────┐
│                     Customer Dashboard (public/)               │
│  posture timeline · readable attack log · findings · reports   │
└───────────────────────────┬────────────────────────────────────┘
                            │ simple API over the event store
┌───────────────────────────┴────────────────────────────────────┐
│                      Server (server.js)                        │
│  ┌──────────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ Agent            │  │ WAF Engine   │  │ Event Store      │  │
│  │ Orchestrator     │→ │ two-tier     │→ │ append-only JSONL│  │
│  │ scope + budget + │  │ pattern +    │  │ every decision & │  │
│  │ verification     │  │ anomaly,     │  │ finding logged   │  │
│  │ layer            │  │ typed &      │  │                  │  │
│  └────────┬─────────┘  │ calibrated   │  └──────────────────┘  │
│           │            └──────────────┘                        │
│  ┌────────┴─────────────────────────────────────────────────┐  │
│  │ Agent Loop (ReAct) + Tool Executor + Workflow Engine     │  │
│  │ browser pool (Playwright) · WSL2 security tools          │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

- **Agent Orchestrator** (`src/server/agent-orchestrator.js`) — every run gets a strict scope (target class, allowed toolset, budget: tool calls / time / cost). A verification layer only persists findings that carry real evidence, deduped against open findings. Closed loop v1: verified findings auto-tune WAF rules.
- **WAF Engine** (`src/server/waf-engine.js`) — Tier 1: established attack-pattern signatures (OWASP-class). Tier 2: anomaly scoring for payloads matching no signature. Decisions are typed and calibrated (`action / attackType / tier / confidence / reasons`) and every decision is logged with attack-type classification. Async LLM triage only on escalation.
- **Event Store** (`src/server/event-store.js`) — append-only JSONL with a query API; derives the posture score, timeline and monthly report. Never mutated, only appended.
- **Agent core** (`src/background/`) — unchanged ReAct brain (agent loop, OpenRouter/OpenAI clients, tool executor, workflow DAG) reused via the chrome-shim adapter. Tools do the heavy lifting; AI spend stays at orchestration level (cost engineering).

## Dashboard Views

| View | What it shows |
|------|---------------|
| **Dashboard** | Posture score /100, attacks blocked (24h), open findings by severity, scan count, 30-day posture timeline (SVG), recent attacks & findings, one-click attack simulation |
| **Attack Log** | Every WAF decision: time, action, attack type, severity, payload sample, path, confidence, latency — filterable |
| **Findings** | Verified findings as plain-language cards: what happened, how to fix it, technical evidence, status tracking (open → acknowledged → fixed) |
| **Agent** | Chat with the security agent — scoped runs, target URL, streaming tool calls |
| **Reports** | Monthly posture report in plain language — narrative, stats, top attack types; print/PDF and JSON download |
| **WAF Lab** | Test any payload against the shield, run the OWASP-class attack simulation, manage per-tenant rules (auto-tuned by agent findings) |

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dashboard/summary` | GET | Posture score + counts |
| `/api/dashboard/timeline?days=30` | GET | Daily posture/attack buckets |
| `/api/attacks` | GET | WAF decision log (filters: `action`, `attackType`, `severity`) |
| `/api/findings` | GET | Verified findings (filters: `severity`, `status`) |
| `/api/findings/:id` | PATCH | Update finding status |
| `/api/waf/evaluate` | POST | Evaluate a payload or request |
| `/api/waf/simulate` | POST | Replay classic OWASP-class probes |
| `/api/waf/rules` | GET/POST | List / add per-tenant rules |
| `/api/waf/rules/:id` | DELETE | Remove a rule |
| `/api/report/monthly?month=YYYY-MM` | GET | Plain-language posture report |
| `/api/agent/runs` | POST | Start a scoped agent run |
| `/api/agent/stop` | POST | Stop the active run |
| `/api/events` | GET | Raw event feed |
| `/api/settings`, `/api/models`, `/api/agent`, `/api/execute-workflow`, `/api/python` | — | Agent settings & execution (unchanged) |

## Architecture

```
server.js                     # Express + WS: API layer, wiring, security (helmet, rate limits, auth)
src/
├── server/                   # OneEye360 platform services
│   ├── event-store.js        #   append-only event store + posture/report derivation
│   ├── waf-engine.js         #   two-tier detection, typed calibrated decisions, rules
│   └── agent-orchestrator.js #   scoped runs, budget enforcement, verification layer
├── background/               # Agent brain (unchanged)
│   ├── agent-loop.js         #   ReAct loop with tool calling
│   ├── openrouter.js         #   OpenRouter client (streaming)
│   ├── openai.js             #   OpenAI client
│   ├── tool-executor.js      #   tool dispatcher (content script vs background)
│   └── workflow-engine.js    #   DAG workflow execution
├── tools/definitions.js      # Tool schemas (single universal tool + catalog)
├── content/content-script.js # DOM tool implementations
├── shared/constants.js       # Message types, storage keys, system prompt
└── sidepanel/                # Browser-extension side panel (legacy entry)
adapters/                     # chrome-shim, browser pool (Playwright), content bridge
public/                       # Customer dashboard (this UI)
  ├── index.html              #   app shell: nav + views
  ├── app.js                  #   agent chat + view router
  ├── dashboard.js            #   dashboard/attacks/findings/reports/WAF-lab views
  ├── style.css               #   design system
  └── workflows.html          #   workflow executor
native-host/                  # WSL2 bridge for native messaging
```

## Installation

1. Get an OpenRouter API key from [openrouter.ai/keys](https://openrouter.ai/keys)
2. `npm install`
3. Copy `.env.example` to `.env` and set `OPENROUTER_API_KEY`
4. `npm start`
5. Open `http://localhost:3000` — the dashboard loads first; use **Agent** to run scans

## Security Notes

- Server binds to localhost by default; set `AUTH_TOKEN` (required if `HOST=0.0.0.0`)
- Helmet headers, rate limiting, payload size limits, path-traversal protection on downloads
- Agent runs are scope-bounded and read-only-first; the verification layer blocks unevidenced findings

## Requirements

- Node.js ≥ 18
- Playwright Chromium (`npm run install-browser`)
- WSL2 with security tools (nmap, nikto, sqlmap, …) for network testing
- OpenRouter or OpenAI API key

## Tech Stack

- **Node.js / Express** + WebSocket
- **Vanilla JS** dashboard with modern CSS (no framework dependencies)
- **Playwright** browser pool for page-context tools
- **WSL2 (Kali)** security toolset
- **OpenRouter / OpenAI** LLMs with prompt caching and tiered models
