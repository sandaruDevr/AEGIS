# AEGIS — Autonomous AI Security Operations

Autonomous AI security operations for businesses that live online: pentest agents that find and verify weaknesses, an AI WAF that blocks live attacks, and a dashboard an owner can actually read — built to the AEGIS Gate-1 plan (see `Gate1-WriteUp- AEGIS.pdf`).

## Product Components (per plan §08)

```
┌────────────────────────────────────────────────────────────────────┐
│              Control Center (public/) — no chat, owner-first       │
│  Dashboard · Websites · Scan Center · Vulnerabilities · Mitigation │
│  Attack Log · Reports · WAF Shield                                 │
└───────────────────────────┬────────────────────────────────────────┘
                            │ REST + WebSocket (live scan events)
┌───────────────────────────┴────────────────────────────────────────┐
│                         Server (server.js)                         │
│  ┌────────────────┐  ┌──────────────┐  ┌────────────┐  ┌────────┐  │
│  │ Scan Manager   │→ │ Agent        │→ │ WAF Engine │→ │ Event  │  │
│  │ jobs, queue,   │  │ Orchestrator │  │ two-tier,  │  │ Store  │  │
│  │ phases, friend-│  │ scope+budget │  │ typed &    │  │ JSONL  │  │
│  │ ly translation │  │ + verification│ │ calibrated │  │        │  │
│  └────────────────┘  └──────────────┘  └────────────┘  └────────┘  │
│  ┌────────────────┐  ┌─────────────────────────────────────────┐  │
│  │ Asset Registry │  │ Agent Loop (ReAct) + Tools + Workflows   │  │
│  │ websites CRUD  │  │ browser pool (Playwright) · WSL2 tools   │  │
│  └────────────────┘  └─────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

- **Asset Registry** (`src/server/asset-registry.js`) — websites under protection; per-asset posture derived from the event store.
- **Credential Vault** (`src/server/credential-vault.js`) — sample test credentials per website for **authenticated scanning**. AES-256-GCM encrypted at rest (`CREDENTIALS_SECRET` env, or an auto-generated local key). The API returns masked status only; credentials are used server-side to sign the scan session in before testing — the agent never sees them. Sessions are cleaned up after each scan (page closed, cookies cleared).
- **Check Catalog** (`src/server/check-catalog.js`) — reference knowledge for the scan framework: the areas a complete assessment typically considers. **No fixed checklists** — the agent reconnoiters first, then directs its own test plan from what it learns, announces it as `[PLAN]` lines and accounts for each area with `[CHECK] id | pass|issue|skip | note` lines; suspected issues stream live as `[SUSPECT]` lines and are persisted only after the verification layer confirms them.
- **Scan Manager** (`src/server/scan-manager.js`) — job queue and lifecycle; scan types × profiles; phase-based progress driven by the agent's self-directed plan; **translation layer** that converts internal tool executions into plain-language activity — no tool names, prompts, or LLM text ever reach the UI; executive scan reports with per-area coverage.
- **Agent Orchestrator** (`src/server/agent-orchestrator.js`) — strict per-run scope (target class, allowed toolset, budget: tool calls / time / cost). Verification layer persists only evidence-backed findings, deduped. Closed loop v1: verified findings auto-tune WAF rules.
- **WAF Engine** (`src/server/waf-engine.js`) — Tier 1: established attack-pattern signatures (OWASP-class). Tier 2: anomaly scoring for unknown payloads. Tier 3 (async): **Jev typed triage** — escalated (held-for-review) decisions are resolved by the TypeSafe decision model via OpenRouter (`typesafe/jev-1.13`): calibrated malicious-probability, attack-class choice and severity score, merged by deterministic thresholds. Jev judges the **raw request on its own** — no pattern hints or example payloads are fed to it; the option keys are only the output vocabulary the UI branches on. Fail-safe: if Jev is unavailable, escalated decisions stay held for review. Typed, calibrated decisions (`action / attackType / tier / confidence / reasons`), every decision logged with attack-type classification.
- **Event Store** (`src/server/event-store.js`) — append-only JSONL with a query API; derives posture scores, timelines and reports. Never mutated, only appended.
- **Agent core** (`src/background/`) — unchanged ReAct brain reused via the chrome-shim adapter. Tools do the heavy lifting; AI spend stays at orchestration level (cost engineering).

## Control Center Views

| View | What it shows |
|------|---------------|
| **Dashboard** | Posture score /100, websites protected, open issues, attacks blocked (24h), live active-scan strip, 30-day posture timeline, recent scans & issues, quick actions |
| **Websites** | Registered websites as cards with posture rings, open-issue counts, last-scan time, one-click Quick / Full / Pen-test / Custom scans |
| **Scan Center** | New-scan launcher (website → type → depth → custom areas), **live scan monitor** (phase stepper, progress %, checks counter, suspected/confirmed issues, elapsed time, plain-language live activity feed, stop), scan history with reports and re-run |
| **Vulnerabilities** | Cross-website register: severity, SLA due dates, plain-language summary + fix, technical evidence, status lifecycle (open → acknowledged → fixed) |
| **Mitigation** | Prioritized remediation plans per website: ordered by risk, SLA due dates, progress bars, mark-as-fixed |
| **Attack Log** | Every WAF decision: time, action, attack type, severity, payload sample, path, confidence, latency — filterable |
| **Reports** | Executive scan reports (narrative, stats, prioritized fixes) + monthly posture report; print/PDF and JSON download |
| **WAF Shield** | Full protection console: status strip (mode, blocked 24h, held for review, AI-triage status), **live traffic monitor** (auto-refresh, verdict filters), attack analytics (24h timeline + top attack types), **protection setup** (Monitor/Enforce mode, tunable thresholds, AI-triage toggle), **install the shield** (per-website token + ready-to-paste adapters for Express, Next.js, Cloudflare Worker and nginx), custom rules, and the payload test lab |

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/assets` | GET/POST | List / register websites |
| `/api/assets/:id` | PATCH/DELETE | Update / remove a website |
| `/api/assets/:id/credentials` | GET/POST/DELETE | Test credentials for authenticated scanning (masked status only — never returns the password) |
| `/api/scans` | GET/POST | Job list / start a scan (type × profile × options) |
| `/api/scans/plan` | GET | Resolve the deterministic check plan for a type × profile × options (launcher preview) |
| `/api/scans/:id` | GET | Job detail |
| `/api/scans/:id/stop` | POST | Stop a queued/running scan |
| `/api/scans/:id/report` | GET | Executive scan report |
| `/api/mitigation-plans` | GET | Prioritized remediation plans (per website) |
| `/api/dashboard/summary` | GET | Posture score + counts + asset coverage |
| `/api/dashboard/timeline?days=30` | GET | Daily posture/attack buckets |
| `/api/attacks` | GET | WAF decision log (filters: `action`, `attackType`, `severity`) |
| `/api/findings` | GET | Verified issues (filters: `severity`, `status`) |
| `/api/findings/:id` | PATCH | Update issue status |
| `/api/waf/evaluate` | POST | Evaluate a payload or request (triage resolved inline) |
| `/api/waf/simulate` | POST | Replay classic OWASP-class probes |
| `/api/waf/rules` | GET/POST | List / add per-tenant rules |
| `/api/waf/rules/:id` | DELETE | Remove a rule |
| `/api/waf/overview` | GET | Protection console: stats, config, triage status, installs, 24h timeline, top attacks, per-asset tracking |
| `/api/waf/config` | GET/PUT | Operating config: mode (monitor/enforce), thresholds, AI-triage toggle |
| `/api/waf/decisions` | GET | Decision history, merged latest state (filters: `action`, `attackType`) |
| `/api/waf/installs` | GET/POST | List installs (masked tokens) / generate an install token per website |
| `/api/waf/installs/:token` | DELETE | Revoke an install token |
| `/api/waf/install-snippet` | GET | Ready-to-paste adapter (`platform`: express, nextjs, cloudflare, nginx) |
| `/api/waf/edge` | POST | **Edge endpoint for deployed adapters** (install-token auth; 403 = block, 200 = pass; triage resolves async) |
| `/api/report/monthly?month=YYYY-MM` | GET | Plain-language posture report |
| `/api/events` | GET | Raw event feed |
| `/api/settings`, `/api/models`, `/api/agent`, `/api/execute-workflow`, `/api/python` | — | Agent settings & execution (unchanged) |

WebSocket broadcasts scan lifecycle events (`SCAN_JOBS`, `SCAN_JOB`, `SCAN_PROGRESS`, `SCAN_ACTIVITY`, `SCAN_FINDING`) so every open dashboard stays in sync.

## Architecture

```
server.js                     # Express + WS: API layer, wiring, security (helmet, rate limits, auth)
src/
├── server/                   # AEGIS platform services
│   ├── event-store.js        #   append-only event store + posture/report derivation
│   ├── waf-engine.js         #   three-tier detection, typed calibrated decisions, rules, config, edge installs
│   ├── jev-client.js         #   Jev typed-decision client (OpenRouter / TypeSafe) with circuit breaker
│   ├── agent-orchestrator.js #   scoped runs, budget enforcement, verification layer
│   ├── asset-registry.js     #   websites under protection (CRUD + derived posture)
│   └── scan-manager.js       #   job queue, phases, friendly translation layer, reports
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
public/                       # Control Center (this UI)
  ├── index.html              #   app shell: nav + views
  ├── app.js                  #   infra: WebSocket, settings, router, toasts
  ├── dashboard.js            #   dashboard, websites, vulnerabilities, mitigation, reports, WAF Shield console
  ├── scan-center.js          #   scan launcher, live monitor, job history, scan reports
  ├── style.css               #   design system
  └── workflows.html          #   workflow executor (advanced)
native-host/                  # WSL2 bridge for native messaging
```

## Installation

1. Get an OpenRouter API key from [openrouter.ai/keys](https://openrouter.ai/keys)
2. `npm install`
3. Copy `.env.example` to `.env` and set `OPENROUTER_API_KEY`
4. `npm start`
5. Open `http://localhost:3000` — add a website under **Websites**, then start a scan from the **Scan Center**

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
