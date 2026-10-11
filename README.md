# AEGIS — Autonomous AI Security Operations

> **Affordable enterprise-grade autonomous cybersecurity for small and medium businesses — built for the agentic era, where attacks strike at machine speed and human-paced defense can't keep up.**
>
> Two components, one closed loop:
>
> - **WAF Layer** — continuously monitors, tracks, and measures every request. Three-tier detection blocks even the novel, AI-generated attacks that static rules miss.
> - **Penetration & Assessment Agents** — cover a month of manual effort in minutes, under $1. Saves your website. Your database. Your business. Your money. Your reputation. The manual equivalent costs hundreds of dollars.
>
> Real gap. Huge market. Endless potential. Unignorable.
> **Nothing today combines depth, continuity, and affordability.**

This repository is the working platform: pentest agents that find and verify weaknesses, a three-tier AI WAF that blocks live attacks, and a Control Center an owner can actually read — server, agent engine, WAF, and full UI.

## Key Features

**Autonomous pentest agents**
- **Self-directed scanning** — the agent reconnoiters the target first, then announces its own test plan (`[PLAN]` / `[CHECK]` protocol); suspected issues stream live and are persisted only after verification
- **Strict scope & budgets** — every run gets a target class, an allowed toolset, and hard caps (tool calls / time / LLM spend) enforced at the tool layer; violations are logged
- **Verification layer** — a finding is persisted only with title, severity, plain-language summary, and evidence; duplicates dropped; stored test credentials redacted before persistence
- **Authenticated scanning** — an AES-256-GCM credential vault signs the agent into the target; credentials never reach the agent or the UI
- **Closed loop** — verified findings auto-tune WAF rules; live attack telemetry steers the next scan

**WAF Shield**
- **Three-tier detection**: Tier 1 signatures (OWASP-class, decode-aware incl. URL/double-encoding) → Tier 2 anomaly scoring (tunable thresholds) → Tier 3 optional Jev typed triage
- **Monitor / enforce modes** — tune rules safely first, enforce after; every decision typed and logged (action, attack type, tier, confidence, reasons)
- **Deploy anywhere** — per-website install tokens and ready-to-paste adapters for Express, Next.js, Cloudflare Worker, and nginx
- **Payload test lab** and attack analytics (24h timeline, top attack types)

**Owner-first Control Center**
- Eight views, zero chat interface: Dashboard, Websites, Scan Center, Vulnerabilities, Mitigation, Attack Log, Reports, WAF Shield
- **Plain-language translation layer** — no tool names, prompts, or LLM text ever reach the UI
- Posture score /100, SLA due dates, executive scan reports, monthly posture report (print/PDF, JSON)

## What's Fully Functional vs. What Needs a Key

Honest status of every subsystem — nothing is silently mocked:

| Subsystem | Status |
|-----------|--------|
| Control Center — all 8 views | **Fully functional** — wired to the live API + WebSocket |
| WAF Tier 1 — signatures + custom rules | **Fully functional** — no external dependencies |
| WAF Tier 2 — anomaly scoring | **Fully functional** — no external dependencies |
| WAF installs, edge endpoint, 4 adapters | **Fully functional** |
| Credential vault (AES-256-GCM) | **Fully functional** |
| Event store, posture derivation, reports | **Fully functional** — append-only JSONL, never mutated |
| Scan pipeline (queue, phases, translation) | **Fully functional** |
| Agent (ReAct loop, tools, budgets, verification) | **Needs an LLM key** — OpenRouter or OpenAI. Without a key scans fail loudly; nothing is faked |
| WAF Tier 3 — Jev typed triage | **Optional** — reuses the OpenRouter key (or a separate JEV key). Without it the WAF runs unchanged: escalated decisions stay held for review (fail-safe, never fail-open) |
| Network/infrastructure scope | **Optional** — WSL2 with the Kali toolset (nmap, nikto, sqlmap) on Windows. Application-layer scans need none of it |
| E2E test suite | `scripts/test_waf.py` — 7 checks incl. the full request path through a real Express app |

**Deliberate simplifications (not hidden, just v1):**
- File-based persistence (JSONL + JSON state) — zero-database setup, no external DB
- Single `AUTH_TOKEN` tenancy — not yet a multi-tenant SaaS
- One agent run at a time
- The verification layer validates evidence presence, severity, and dedupe — it does not independently re-exploit findings

**Demo target:** `examples/waf-test-app` — an intentionally vulnerable Express app with the AEGIS middleware wired in (`npm run waf-test-app`).

## Architecture

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
│  │ jobs, queue,   │  │ Orchestrator │  │ three-tier │  │ Store  │  │
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

## Repository Layout

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
examples/waf-test-app/         # intentionally vulnerable demo target (Express + AEGIS middleware)
scripts/test_waf.py            # end-to-end WAF test suite
```

## Setup

1. **Install** — `npm install` (Playwright Chromium installs automatically)
2. **Configure** — copy `.env.example` to `.env`:
   - `OPENROUTER_API_KEY` *(required for scans)* — from [openrouter.ai/keys](https://openrouter.ai/keys); or `OPENAI_API_KEY` with `LLM_PROVIDER=openai`
   - `AUTH_TOKEN` *(optional on localhost, required if `HOST=0.0.0.0`)* — Bearer auth for all API + WebSocket endpoints
   - `CREDENTIALS_SECRET` *(optional)* — AES-256-GCM key for the credential vault; a local key file is auto-generated if empty
   - `WSL_ENABLED` *(optional)* — set `false` to skip network-scope tooling
3. **Run** — `npm start`, then open `http://localhost:3000`
4. **First scan** — add a website under **Websites**, then launch one from the **Scan Center**

**Verify the WAF end-to-end:**

```bash
python scripts/test_waf.py            # provisions its own test target + token
npm run waf-test-app                  # demo target app (Express + middleware)
python scripts/test_waf.py --app-url http://localhost:4000
```

## Security Notes

- Server binds to localhost by default; set `AUTH_TOKEN` (required if `HOST=0.0.0.0`)
- Helmet headers, rate limiting, payload size limits, path-traversal protection on downloads
- Agent runs are scope-bounded and read-only-first; the verification layer blocks unevidenced findings
- Escalated WAF decisions stay held for review if the triage model is unavailable — never fail-open
- Test only targets you own or are authorized to assess

## Tech Stack

- **Server:** Node.js ≥ 18 · Express 4 · ws (WebSocket) · helmet · express-rate-limit
- **Agent:** ReAct loop over OpenRouter / OpenAI — streaming, tool calling, prompt caching, tiered models
- **Browser automation:** Playwright (Chromium) + stealth plugin
- **Network tools (optional):** WSL2 Kali toolset — nmap, nikto, sqlmap
- **Decisions:** Jev typed triage (`typesafe/jev-1.13`) via the OpenRouter Decisions API — optional
- **Frontend:** vanilla JS + a custom CSS design system — no framework dependencies
- **Storage:** file-based — append-only JSONL event store + JSON state (zero-database)
