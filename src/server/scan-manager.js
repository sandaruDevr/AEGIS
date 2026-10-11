// Scan Manager — enterprise scan orchestration.
//
// Transforms the raw agent loop into a user-facing scan experience built on
// the universal check framework (check-catalog.js):
//   - Jobs with lifecycle (queued → running → completed / failed / stopped)
//   - Scan types (Security Assessment / Penetration Test) × profiles (Quick / Full / Custom)
//   - No fixed checklists: the agent reconnoiters first, then directs its own
//     test plan from what it learns
//   - Phase-based progress (Preparation → Exploration → Configuration → Deep
//     Inspection → Verification → Report) driven by the agent's self-directed
//     plan ([PLAN] lines announced after initial reconnaissance)
//   - A translation layer: internal tool executions become plain-language
//     activity — no tool names, no prompts, no LLM text ever reaches the UI
//   - Structured result protocol: [CHECK] plan results and [SUSPECT] likely
//     issues stream live; only verification-layer-confirmed findings persist
//   - Executive scan reports with per-check coverage

import { randomUUID } from 'crypto';
import { MSG } from '../shared/constants.js';
import { buildMissionPrompt, CHECK_STATUS, CHECK_GROUPS } from './check-catalog.js';

// ---- Scan types & profiles ----

const SCAN_TYPES = {
  assessment: {
    label: 'Security Assessment',
    description: 'Evaluates your website\u2019s configuration and code for weaknesses, with evidence for every issue.',
    scope: 'web_app',
  },
  pentest: {
    label: 'Penetration Test',
    description: 'Actively verifies that weaknesses are exploitable, the way a real attacker would — safely and read-only first. Months of expert effort, compressed.',
    scope: 'web_app',
  },
};

const PROFILES = {
  quick: {
    label: 'Quick Scan',
    description: 'Essential checks: security settings, cookies, forms and exposed keys. Days of manual review, done in minutes.',
    budget: { maxToolCalls: 45, maxDurationMs: 12 * 60_000, maxCostUsd: 1.2 },
    options: { headers: true, cookies: true, forms: true, secrets: true, js: false, network: false, deep: false },
  },
  full: {
    label: 'Full Scan',
    description: 'Everything we can safely test: configuration, forms, scripts, secrets, access control and network surface. Weeks of expert effort, compressed.',
    budget: { maxToolCalls: 200, maxDurationMs: 40 * 60_000, maxCostUsd: 4.0 },
    options: { headers: true, cookies: true, forms: true, secrets: true, js: true, network: true, deep: true },
  },
  custom: {
    label: 'Custom Scan',
    description: 'Choose exactly what to test.',
    budget: null, // computed from selected options
    options: null,
  },
};

// Human-effort equivalence — the platform compresses expert work that would
// take days (quick) to months (full pentest) into an automated run.
const EFFORT_EQUIVALENT = {
  'assessment|quick': 'several days',
  'assessment|full': 'several weeks to months of complete work',
  'pentest|quick': 'over a week',
  'pentest|full': 'one to two months',
};
const effortFor = (job) => job.profile === 'custom'
  ? 'days to weeks'
  : EFFORT_EQUIVALENT[`${job.type}|${job.profile}`] || 'days';

const CUSTOM_BUDGET = {
  maxToolCalls: (opts) => 30 + 25 * Object.values(opts).filter(Boolean).length,
  maxDurationMs: (opts) => (8 + 5 * Object.values(opts).filter(Boolean).length) * 60_000,
  maxCostUsd: (opts) => 0.6 + 0.5 * Object.values(opts).filter(Boolean).length,
};

const CUSTOM_OPTION_LABELS = { ...CHECK_GROUPS };

// ---- User-facing phases (antivirus-style, specialized for security testing) ----

const PHASES = [
  { id: 'preparing', label: 'Preparation', friendly: 'Getting ready and connecting to your website', weight: 5 },
  { id: 'exploring', label: 'Exploration', friendly: 'Mapping your website\u2019s structure and technology', weight: 15 },
  { id: 'config', label: 'Configuration', friendly: 'Checking security settings, headers and cookies', weight: 20 },
  { id: 'inspecting', label: 'Deep Inspection', friendly: 'Testing forms, scripts and hidden corners of your site', weight: 45 },
  { id: 'verifying', label: 'Verification', friendly: 'Double-checking every potential issue we found', weight: 10 },
  { id: 'reporting', label: 'Report', friendly: 'Writing your plain-language security report', weight: 5 },
];

const PHASE_IDS = Object.fromEntries(PHASES.map((p, i) => [p.id, i]));

// Tool → phase mapping (internal; never exposed to the user).
const TOOL_PHASE = {
  get_page_info: 'preparing',
  wait: 'preparing',
  read_page_structure: 'exploring',
  read_page_text: 'exploring',
  read_page_html: 'exploring',
  query_selector_all: 'exploring',
  extract_data: 'exploring',
  check_security_headers: 'config',
  check_cookies: 'config',
  analyze_forms: 'config',
  scan_for_secrets: 'inspecting',
  inspect_js_sources: 'inspecting',
  execute_script: 'inspecting',
  make_request: 'inspecting',
  run_wsl_command: 'inspecting',
  read_element: 'inspecting',
  modify_element: 'inspecting',
  click_element: 'inspecting',
  screenshot: 'inspecting',
  verify_authorization: 'inspecting',
  get_login_credentials: 'preparing',
  execute_python_file: 'inspecting',
  write_file: null,
  read_file: null,
  list_files: null,
  edit_file: null,
  delete_file: null,
  create_file: null,
};

// Tool → friendly activity message. null = internal housekeeping, not shown.
const TOOL_MESSAGES = {
  get_page_info: () => 'Reading your website\u2019s basic information',
  read_page_structure: () => 'Mapping your website\u2019s structure',
  read_page_text: () => 'Reading page content',
  read_page_html: () => 'Examining the page\u2019s underlying code',
  query_selector_all: () => 'Looking for interesting elements on the page',
  extract_data: () => 'Collecting data from the page',
  check_security_headers: () => 'Checking your site\u2019s security settings',
  check_cookies: () => 'Reviewing how cookies are handled',
  analyze_forms: () => 'Reviewing how your forms handle input',
  scan_for_secrets: () => 'Scanning for accidentally exposed keys and secrets',
  inspect_js_sources: () => 'Analyzing your website\u2019s scripts',
  execute_script: () => 'Inspecting page behavior in a safe sandbox',
  make_request: () => 'Testing how your site responds to crafted requests',
  read_element: () => 'Examining a specific element closely',
  modify_element: () => 'Testing how the page reacts to changes',
  click_element: () => 'Interacting with the page like a visitor would',
  screenshot: () => 'Capturing visual evidence',
  verify_authorization: () => 'Testing who can access what',
  get_login_credentials: () => 'Signing in to test member areas',
  execute_python_file: () => 'Running a specialized analysis',
  run_wsl_command: (args) => {
    const cmd = String(args?.command || '').toLowerCase();
    if (cmd.includes('nmap')) return 'Checking which doors to your server are open';
    if (cmd.includes('nikto')) return 'Running industry-standard web server checks';
    if (cmd.includes('sqlmap')) return 'Testing databases for injection weaknesses';
    if (cmd.includes('curl') || cmd.includes('wget')) return 'Probing how your server responds';
    if (cmd.includes('dirb') || cmd.includes('gobuster')) return 'Looking for hidden pages and folders';
    return 'Running a specialized security tool';
  },
  write_file: null,
  read_file: null,
  list_files: null,
  edit_file: null,
  delete_file: null,
  create_file: null,
};

// Friendly error translation — never expose stack traces or internals.
function friendlyError(err) {
  const msg = String(err?.message || err || 'Unknown error');
  if (/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(msg)) {
    return 'We couldn\u2019t reach that website. Please check the address and try again.';
  }
  if (/ECONNREFUSED/i.test(msg)) {
    return 'The website refused our connection. It may be offline or blocking automated visitors.';
  }
  if (/timeout|timed out|TimeoutError/i.test(msg)) {
    return 'The website took too long to respond. It may be slow or temporarily unavailable.';
  }
  if (/certificate|SSL|TLS/i.test(msg)) {
    return 'The website\u2019s security certificate could not be verified.';
  }
  if (/net::ERR/i.test(msg)) {
    return 'The browser couldn\u2019t load the website. Please check the address.';
  }
  if (/API key|401|Unauthorized/i.test(msg)) {
    return 'The AI service rejected the request. Please check your API key in Settings.';
  }
  if (/rate.?limit|429/i.test(msg)) {
    return 'The AI service is busy right now. Please try again in a moment.';
  }
  return 'The scan stopped unexpectedly. Our team can review the technical details.';
}

// ---- Scan Manager ----

export class ScanManager {
  constructor({ agent, orchestrator, eventStore, assetRegistry, credentialVault, broadcast }) {
    this.agent = agent;
    this.orchestrator = orchestrator;
    this.eventStore = eventStore;
    this.assets = assetRegistry;
    this.vault = credentialVault || null;
    this.broadcast = broadcast; // fn(data) → all connected dashboard clients
    this.jobs = new Map();      // jobId → job record (in-memory; lifecycle events persisted)
    this.queue = [];            // jobIds waiting to run
    this.running = false;
    this._activitySeq = 0;
  }

  // ---- Job creation & queue ----

  async createJob({ assetId, url, type = 'assessment', profile = 'quick', options = null } = {}) {
    // Resolve asset — auto-register ad-hoc URLs for a smooth flow.
    let asset = assetId ? this.assets.get(assetId) : this.assets.findByUrl(url);
    if (!asset && url) {
      asset = await this.assets.add({ url, name: null });
    }
    if (!asset) {
      throw new Error('Please choose a website to scan first.');
    }
    if (!SCAN_TYPES[type]) throw new Error('Unknown scan type.');
    if (!PROFILES[profile]) throw new Error('Unknown scan profile.');

    const resolvedOptions = profile === 'custom'
      ? this._resolveCustomOptions(options)
      : { ...PROFILES[profile].options };

    const budget = profile === 'custom'
      ? {
          maxToolCalls: CUSTOM_BUDGET.maxToolCalls(resolvedOptions),
          maxDurationMs: CUSTOM_BUDGET.maxDurationMs(resolvedOptions),
          maxCostUsd: CUSTOM_BUDGET.maxCostUsd(resolvedOptions),
        }
      : { ...PROFILES[profile].budget };

    const job = {
      id: `scan-${randomUUID().slice(0, 8)}`,
      assetId: asset.id,
      assetName: asset.name,
      target: asset.url,
      type,
      profile,
      options: resolvedOptions,
      budget,
      // Dynamic check plan — the agent announces its own plan after initial
      // reconnaissance ([PLAN] lines); until then there is no fixed list.
      checkPlan: [],
      planAnnounced: false,
      totalChecks: null,
      checkResults: {}, // checkId → { status, note, ts }
      checksCompleted: 0,
      status: 'queued',
      phaseId: 'preparing',
      progress: 0,
      checksDone: 0,
      estimatedChecks: Math.max(Math.round(budget.maxToolCalls * 0.85), 8),
      issuesSuspected: 0,
      issuesConfirmed: null,
      findingsBySeverity: null,
      authenticated: null, // null = no credentials stored; true/false = sign-in result
      createdAt: Date.now(),
      startedAt: null,
      completedAt: null,
      durationMs: null,
      currentMessage: 'Waiting in queue…',
      error: null,
      runId: null,
    };

    this.jobs.set(job.id, job);
    this.queue.push(job.id);
    this._emitJobs();
    this._pump();
    return this.snapshot(job);
  }

  _resolveCustomOptions(options) {
    const resolved = {};
    for (const key of Object.keys(CHECK_GROUPS)) {
      resolved[key] = Boolean(options?.[key]);
    }
    if (!Object.values(resolved).some(Boolean)) {
      throw new Error('Select at least one area to test for a custom scan.');
    }
    return resolved;
  }

  async _pump() {
    if (this.running) return;
    this.running = true;
    try {
      while (this.queue.length > 0) {
        const jobId = this.queue.shift();
        const job = this.jobs.get(jobId);
        if (!job || job.status !== 'queued') continue;
        await this._runJob(job);
      }
    } finally {
      this.running = false;
    }
  }

  // ---- Job execution ----

  async _runJob(job) {
    job.status = 'running';
    job.startedAt = Date.now();
    job.phaseId = 'preparing';
    job.progress = 2;
    job.currentMessage = 'Connecting to your website…';
    this._emitJob(job);
    this._activity(job, 'info', `Scan started for ${job.assetName} — ${job.totalChecks} checks planned.`);

    // Navigate the managed browser to the target (page context for DOM tools).
    const bp = await import('../../adapters/browser-pool.js');
    let pageId = null;
    try {
      pageId = await bp.createPage(job.target, { timeout: parseInt(process.env.BROWSER_TIMEOUT || '30000') });
    } catch (err) {
      console.warn(`[ScanManager] Navigation failed: ${err.message}`);
      this._activity(job, 'warning', 'The website was slow to load — continuing with what we could reach.');
    }

    // Authenticated access: sign the session in with the owner's test
    // credentials before testing starts. Server-side — the agent never
    // sees the credentials themselves.
    if (this.vault?.has(job.assetId)) {
      job.authenticated = await this._preAuthenticate(job, pageId);
      this._emitProgress(job);
    }

    // Intercept the agent's panel stream: translate to user-friendly progress.
    const restore = this._installTranslator(job);

    try {
      const result = await this.orchestrator.startRun({
        target: job.target,
        assetId: job.assetId,
        jobId: job.id,
        prompt: this._buildPrompt(job),
        scope: SCAN_TYPES[job.type].scope,
        budget: job.budget,
        clearConversation: true,
      });

      // Verification layer has confirmed findings — surface them.
      job.runId = result.runId;
      job.issuesConfirmed = result.findings.length;
      job.findingsBySeverity = this._countBySeverity(result.findings);

      this._setPhase(job, 'verifying');
      for (const finding of result.findings) {
        this.broadcast({ type: MSG.SCAN_FINDING, jobId: job.id, finding: this._findingView(finding) });
      }

      // Persist per-check results (durable, audit-grade coverage record).
      this.eventStore.append('scan_checks', {
        runId: result.runId,
        jobId: job.id,
        assetId: job.assetId,
        target: job.target,
        title: `Check results — ${job.checksCompleted}/${job.totalChecks} executed`,
        results: this._checkResultsArray(job),
      });

      this._setPhase(job, 'reporting');
      job.status = 'completed';
      job.progress = 100;
      job.completedAt = Date.now();
      job.durationMs = job.completedAt - job.startedAt;
      job.currentMessage = result.findings.length > 0
        ? `Scan complete — ${result.findings.length} issue${result.findings.length === 1 ? '' : 's'} confirmed and ready to review.`
        : 'Scan complete — no issues confirmed. Your website passed this round.';
      this._activity(job, 'success', job.currentMessage);
      this._emitJob(job);
      this._emitJobs();
    } catch (err) {
      const stopped = job.stopRequested || /abort/i.test(err?.name || '') || /abort/i.test(String(err?.message || ''));
      job.status = stopped ? 'stopped' : 'failed';
      job.completedAt = Date.now();
      job.durationMs = job.completedAt - job.startedAt;
      job.error = stopped ? 'Scan stopped at your request.' : friendlyError(err);
      job.currentMessage = job.error;
      this._activity(job, stopped ? 'info' : 'error', job.error);
      this._emitJob(job);
      this._emitJobs();
    } finally {
      restore();
      // Session hygiene: close the scan's page and, if we signed in, clear
      // the context cookies so this website's session never bleeds into
      // the next scan.
      try {
        if (pageId !== null) await bp.closePage(pageId);
        if (job.authenticated === true) await bp.clearCookies();
      } catch { /* hygiene is best-effort */ }
    }
  }

  // Sign the scan session in with the asset's stored test credentials.
  // Returns true on success; on any failure the scan continues
  // unauthenticated with a user-facing warning. Credentials are used
  // server-side only — never placed in prompts, logs or evidence.
  async _preAuthenticate(job, pageId) {
    const bp = await import('../../adapters/browser-pool.js');
    const entry = pageId !== null ? bp.getPage(pageId) : null;
    const page = entry?.page;
    const creds = this.vault.get(job.assetId);
    if (!page || !creds) return false;

    this._activity(job, 'info', 'Signing in with your test credentials…');
    const navTimeout = 15000;
    // SPAs (React/Vue/Angular) render forms after the HTML shell loads —
    // wait for the field instead of checking the instant the page loads.
    const renderWait = 6000;
    const waitForPasswordField = async () => {
      try {
        await page.waitForSelector('input[type="password"]:visible', { timeout: renderWait, state: 'visible' });
        return true;
      } catch {
        return false;
      }
    };

    try {
      // 1) Direct candidates: stored sign-in URL, the target itself,
      //    and common login paths.
      const candidates = [
        creds.loginUrl || null,
        job.target,
        new URL('/login', job.target).href,
        new URL('/signin', job.target).href,
        new URL('/sign-in', job.target).href,
        new URL('/log-in', job.target).href,
        new URL('/account/login', job.target).href,
        new URL('/auth/login', job.target).href,
        new URL('/user/login', job.target).href,
        new URL('/wp-login.php', job.target).href,
      ].filter(Boolean);

      let found = false;
      for (const url of candidates) {
        try {
          if (page.url() !== url) {
            await page.goto(url, { timeout: navTimeout, waitUntil: 'domcontentloaded' });
          }
          if (await waitForPasswordField()) {
            found = true;
            break;
          }
        } catch { /* try the next candidate */ }
      }

      // 2) Fallback: discover a sign-in control on the homepage (SPA
      //    modals, non-standard routes) and open it like a person would.
      if (!found) {
        try {
          await page.goto(job.target, { timeout: navTimeout, waitUntil: 'domcontentloaded' });
          const link = page.locator([
            'a[href*="login" i]:visible',
            'a[href*="signin" i]:visible',
            'a[href*="sign-in" i]:visible',
            'a:has-text("Sign in"):visible',
            'a:has-text("Log in"):visible',
            'a:has-text("Login"):visible',
            'button:has-text("Sign in"):visible',
            'button:has-text("Log in"):visible',
          ].join(', ')).first();
          if ((await link.count()) > 0) {
            await link.click({ timeout: 5000 });
            if (await waitForPasswordField()) found = true;
          }
        } catch { /* give up below */ }
      }

      if (!found) {
        this._activity(job, 'warning', 'Couldn\u2019t find a sign-in form — continuing without authentication. You can set the sign-in page URL in Test access to help.');
        return false;
      }

      // Fill the login form.
      const userField = page.locator([
        'input[type="email"]:visible',
        'input[name*="user" i]:visible',
        'input[name*="email" i]:visible',
        'input[name*="login" i]:visible',
        'input[autocomplete*="username" i]:visible',
        'input[autocomplete*="email" i]:visible',
      ].join(', ')).first();
      if ((await userField.count()) === 0) {
        this._activity(job, 'warning', 'Couldn\u2019t find the username field — continuing without authentication.');
        return false;
      }
      await userField.fill(creds.username, { timeout: 5000 });
      await page.locator('input[type="password"]:visible').first().fill(creds.password, { timeout: 5000 });

      // Submit: explicit submit control, else Enter in the password field.
      const submit = page.locator([
        'button[type="submit"]:visible',
        'input[type="submit"]:visible',
        'button:has-text("Sign in"):visible',
        'button:has-text("Log in"):visible',
        'button:has-text("Login"):visible',
      ].join(', ')).first();
      if ((await submit.count()) > 0) {
        await submit.click({ timeout: 5000 });
      } else {
        await page.locator('input[type="password"]:visible').first().press('Enter');
      }

      // Let the session establish (navigation or SPA route change), then
      // check whether we left the sign-in form behind.
      await page.waitForLoadState('domcontentloaded', { timeout: navTimeout }).catch(() => {});
      await page.waitForTimeout(2000);
      let stillOnForm = await page.locator('input[type="password"]:visible').count();
      if (stillOnForm > 0) {
        // One more patient check — slow transitions.
        await page.waitForTimeout(3000);
        stillOnForm = await page.locator('input[type="password"]:visible').count();
      }
      const ok = stillOnForm === 0;
      this._activity(job, ok ? 'success' : 'warning', ok
        ? 'Signed in — testing will include member-only areas.'
        : 'Sign-in didn\u2019t complete — continuing without authentication. Please check the saved credentials.');
      return ok;
    } catch (err) {
      console.warn(`[ScanManager] Pre-auth failed: ${err.message}`);
      this._activity(job, 'warning', 'Automatic sign-in failed — continuing without authentication.');
      return false;
    }
  }

  stopJob(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) return false;
    if (job.status === 'queued') {
      this.queue = this.queue.filter((id) => id !== jobId);
      job.status = 'stopped';
      job.completedAt = Date.now();
      job.currentMessage = 'Removed from queue.';
      this._emitJob(job);
      this._emitJobs();
      return true;
    }
    if (job.status === 'running') {
      job.stopRequested = true;
      this.orchestrator.stopRun('stopped by operator');
      return true;
    }
    return false;
  }

  // ---- Translation layer (the "no internals exposed" core) ----

  _installTranslator(job) {
    const agent = this.agent;
    const original = agent._sendToPanel.bind(agent);
    let assistantBuffer = '';
    const seenSuspects = new Set();

    agent._sendToPanel = (type, payload) => {
      try {
        switch (type) {
          case MSG.BG_TOOL_START: {
            this._onToolStart(job, payload);
            break;
          }
          case MSG.BG_TOOL_RESULT: {
            // Results are internal — only used to keep progress honest.
            break;
          }
          case MSG.BG_CHAT_CHUNK: {
            assistantBuffer += payload?.content || '';
            this._parseMarkers(job, assistantBuffer, seenSuspects);
            break;
          }
          case MSG.BG_CHAT_DONE: {
            // Surfaced via startRun's completion/abort path.
            break;
          }
          case MSG.BG_CHAT_ERROR: {
            // Surfaced via startRun's error path; avoid double-reporting here.
            break;
          }
          case MSG.BG_SESSION_COST: {
            // Cost/tokens flow to the header display via the normal port.
            original(type, payload);
            break;
          }
          default:
            break;
        }
      } catch (err) {
        console.warn(`[ScanManager] translator error: ${err.message}`);
      }
      // Suppress everything else — raw agent output never reaches the UI.
    };

    return () => {
      delete agent._sendToPanel;
    };
  }

  _onToolStart(job, payload) {
    const toolName = payload?.toolName;
    if (!toolName) return;
    job.checksDone++;

    const phaseId = TOOL_PHASE[toolName];
    if (phaseId && PHASE_IDS[phaseId] > PHASE_IDS[job.phaseId]) {
      this._setPhase(job, phaseId);
    }

    const message = TOOL_MESSAGES[toolName]?.(payload?.toolArgs);
    if (message) {
      job.currentMessage = message;
      this._activity(job, 'info', message);
    }

    this._updateProgress(job);
    this._emitProgress(job);
  }

  // Deterministic progress from the check plan, with tool activity as a
  // secondary signal. Monotonic — never goes backwards.
  _updateProgress(job) {
    const checkProgress = job.totalChecks > 0
      ? 2 + 93 * Math.min(job.checksCompleted / job.totalChecks, 1)
      : 0;
    const toolProgress = 2 + 93 * Math.min(job.checksDone / job.estimatedChecks, 1);
    job.progress = Math.min(95, Math.max(job.progress, checkProgress, toolProgress));
  }

  _advancePhaseByPlan(job) {
    if (!job.planAnnounced) return;
    const next = job.checkPlan.find((c) => !job.checkResults[c.id]);
    if (next) {
      if (PHASE_IDS[next.category] > PHASE_IDS[job.phaseId]) {
        this._setPhase(job, next.category);
      }
    } else if (job.status === 'running') {
      this._setPhase(job, 'verifying');
    }
  }

  _setPhase(job, phaseId) {
    if (job.phaseId === phaseId) return;
    job.phaseId = phaseId;
    const phase = PHASES.find((p) => p.id === phaseId);
    if (phase) {
      job.currentMessage = phase.friendly;
      this._activity(job, 'phase', phase.friendly);
    }
    this._emitProgress(job);
  }

  // Live marker parsing — the agent reports structured progress lines while
  // testing ([CHECK] plan results, [SUSPECT] likely issues). The verification
  // layer confirms suspects at the end; only then are they persisted.
  _parseMarkers(job, text, seenSuspects) {
    let match;
    // The agent's self-directed plan, announced after initial recon.
    const planRe = /\[PLAN\]\s*([a-z0-9-]+)\s*\|\s*([^\n|]+)/gi;
    while ((match = planRe.exec(text)) !== null) {
      const checkId = match[1].trim().toLowerCase();
      const title = match[2].trim().slice(0, 120);
      if (!checkId || job.checkPlan.some((c) => c.id === checkId)) continue;
      job.checkPlan.push({ id: checkId, title: title || checkId, category: 'inspecting' });
      job.totalChecks = job.checkPlan.length;
      if (!job.planAnnounced) {
        job.planAnnounced = true;
        this._activity(job, 'info', 'Reconnaissance complete — the agent is directing its own test plan.');
      }
      this._updateProgress(job);
      this._emitProgress(job);
    }

    const checkRe = /\[CHECK\]\s*([a-z0-9-]+)\s*\|\s*(pass|issue|skip)\s*\|\s*([^\n]*)/gi;
    while ((match = checkRe.exec(text)) !== null) {
      const checkId = match[1].trim().toLowerCase();
      const planned = job.checkPlan.find((c) => c.id === checkId);
      if (!planned || job.checkResults[checkId]) continue; // unknown or already marked

      const status = match[2].toLowerCase();
      const note = match[3].trim().slice(0, 200);
      job.checkResults[checkId] = { status, note, ts: Date.now() };
      job.checksCompleted++;

      const kind = status === 'issue' ? 'finding' : status === 'skip' ? 'info' : 'success';
      const message = status === 'issue'
        ? `Issue found while checking: ${planned.title}`
        : status === 'skip'
          ? `Skipped: ${planned.title} — ${note || 'not applicable'}`
          : `Check complete: ${planned.title}`;
      job.currentMessage = message;
      this._activity(job, kind, message);

      this._updateProgress(job);
      this._advancePhaseByPlan(job);
      this._emitProgress(job);
    }

    const suspectRe = /\[SUSPECT\]\s*([^\n|]+)\s*\|\s*(critical|high|medium|low|info)\s*\|\s*([a-z_]+)/gi;
    while ((match = suspectRe.exec(text)) !== null) {
      const key = match[1].trim().toLowerCase();
      if (seenSuspects.has(key)) continue;
      seenSuspects.add(key);
      job.issuesSuspected++;
      this._activity(job, 'finding', `Possible issue detected: ${match[1].trim()} — we\u2019re confirming it.`);
      this._emitProgress(job);
    }
  }

  _activity(job, kind, message) {
    const activity = {
      id: `${job.id}-${++this._activitySeq}`,
      jobId: job.id,
      kind,
      message,
      ts: Date.now(),
    };
    this.broadcast({ type: MSG.SCAN_ACTIVITY, activity });
  }

  _emitProgress(job) {
    this.broadcast({
      type: MSG.SCAN_PROGRESS,
      jobId: job.id,
      progress: Math.round(job.progress),
      phaseId: job.phaseId,
      message: job.currentMessage,
      checksCompleted: job.checksCompleted,
      totalChecks: job.totalChecks,
      issuesSuspected: job.issuesSuspected,
    });
  }

  _emitJob(job) {
    this.broadcast({ type: MSG.SCAN_JOB, job: this.snapshot(job) });
  }

  _emitJobs() {
    this.broadcast({ type: MSG.SCAN_JOBS, jobs: this.listJobs() });
  }

  // ---- Prompt construction (per type/profile/options) ----

  _buildPrompt(job) {
    const intent = job.type === 'pentest'
      ? [
          `You are running a controlled penetration test. Think like an attacker with signed authorization:`,
          `enumerate the attack surface, form attack hypotheses, and safely prove exploitability — including`,
          `multi-step chains (e.g. access control gap → sensitive data → exfiltration path). Read-only first —`,
          `never degrade, modify or delete anything.`,
        ].join(' ')
      : [
          `You are performing a security assessment. Hunt for real weaknesses like a senior penetration`,
          `tester: probe, tamper, chain and verify — then rate how serious each proven issue is for the business.`,
        ].join(' ');

    const doctrine = [
      `### How you work (operating doctrine)`,
      `You are an offensive security operator, not a scanner. Tools collect facts — YOU reason about what`,
      `they mean and what to try next. Every action should be driven by a hypothesis.`,
      ``,
      `- Observe → hypothesize → test → update. After each result ask: "what does this tell me about the`,
      `  target, and what is the most promising thing to probe next?"`,
      `- Depth rule: a coverage area is complete when you have tried the reasonable attack vectors for it`,
      `  at this depth — never after a single test. For every area ask "what ELSE could be wrong here?"`,
      `  and test it: tamper parameters, replay requests with modified values, try access without`,
      `  authentication, test reflection and encoding, enumerate variants.`,
      `- Follow every promising lead to its end before moving on: an interesting endpoint, parameter,`,
      `  token, header, redirect or behavior deserves real probing, not a glance.`,
      `- Chain findings: weaknesses combine. A reflected parameter + missing CSP; permissive CORS + a`,
      `  sensitive endpoint; a weak session policy + no rate limiting. Actively hunt for combinations —`,
      `  rate the chain, not the parts.`,
      `- Verify before reporting: for every suspect, try to prove or disprove it with concrete evidence`,
      `  (a response body, a rendered effect, a status or behavior change). Only evidence-backed issues`,
      `  go in the final report.`,
      `- Keep a mental model of the target (tech stack, endpoints, roles, inputs, behaviors) and update`,
      `  it as you learn — let it drive where you dig next.`,
    ].join('\n');

    return [
      intent,
      ``,
      `Target: ${job.target}`,
      job.options.network ? `Network testing is authorized for this target only (port/service discovery).` : `Do not use network-level tools; stay on application-layer testing.`,
      job.options.deep ? `Deep application testing is authorized: edge cases, unusual inputs, chained weaknesses.` : `Stay within the coverage areas listed below.`,
      ``,
      doctrine,
      ``,
      `You own the plan of attack: decide the sequence, methods and time allocation yourself.`,
      `The coverage contract below is your accountability backbone — it guarantees breadth. Your mission`,
      `is depth: real, proven, chained weaknesses. Marking a check is bookkeeping, not achievement.`,
      ``,
      job.authenticated !== null && job.authenticated !== undefined
        ? `Test credentials are stored for this target. ${job.authenticated ? 'The browser session is already signed in.' : 'Automatic sign-in did not succeed — you can sign in yourself.'} If you need to sign in or re-sign in (for example, if the session expires mid-scan), call get_login_credentials to fetch the stored test credentials and complete the sign-in in the browser. Never include the credentials themselves in findings, evidence, notes or reports.`
        : `No authenticated access is available — cover only what an anonymous visitor can reach.`,
      ``,
      buildMissionPrompt(job.profile),
      ``,
      `While testing, the moment you identify a likely issue, output a single line in this exact format`,
      `so the operator can watch progress — then KEEP WORKING it: try to confirm or refute it with`,
      `concrete evidence before the final report:`,
      `[SUSPECT] short plain-language title | severity | attackType`,
      ``,
      `Do not write conversational progress updates — a monitoring interface already shows status.`,
      `Spend your output budget on testing and the final findings report.`,
    ].join('\n');
  }

  // ---- Snapshots & reports ----

  snapshot(job) {
    // Client-facing job shape — no prompts, no raw budgets beyond estimates.
    return {
      id: job.id,
      assetId: job.assetId,
      assetName: job.assetName,
      target: job.target,
      type: job.type,
      typeLabel: SCAN_TYPES[job.type].label,
      profile: job.profile,
      profileLabel: PROFILES[job.profile].label,
      options: job.options,
      status: job.status,
      phaseId: job.phaseId,
      progress: Math.round(job.progress),
      checksDone: job.checksDone,
      checksCompleted: job.checksCompleted,
      totalChecks: job.totalChecks,
      checkResults: this._checkResultsArray(job),
      issuesSuspected: job.issuesSuspected,
      issuesConfirmed: job.issuesConfirmed,
      findingsBySeverity: job.findingsBySeverity,
      authenticated: job.authenticated,
      currentMessage: job.currentMessage,
      error: job.error,
      createdAt: job.createdAt,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
      durationMs: job.durationMs,
    };
  }

  _checkResultsArray(job) {
    return job.checkPlan.map((c) => ({
      id: c.id,
      title: c.title,
      category: c.category,
      status: job.checkResults[c.id]?.status || CHECK_STATUS.NOT_COMPLETED,
      note: job.checkResults[c.id]?.note || null,
    }));
  }

  listJobs() {
    return [...this.jobs.values()]
      .sort((a, b) => b.createdAt - a.createdAt)
      .map((j) => this.snapshot(j));
  }

  getJob(jobId) {
    const job = this.jobs.get(jobId);
    return job ? this.snapshot(job) : null;
  }

  getActiveJob() {
    for (const job of this.jobs.values()) {
      if (job.status === 'running' || job.status === 'queued') return this.snapshot(job);
    }
    return null;
  }

  _countBySeverity(findings) {
    const by = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      if (by[f.severity] !== undefined) by[f.severity]++;
    }
    return by;
  }

  _findingView(event) {
    return {
      id: event.id,
      title: event.title,
      severity: event.severity,
      attackType: event.attackType,
      summary: event.summary,
      fix: event.fix,
      evidence: event.evidence,
      cvss: event.cvss,
      status: event.status,
      target: event.target,
      assetId: event.assetId,
      ts: event.ts,
    };
  }

  // Executive scan report — derived from the job + its verified findings +
  // per-check coverage. Same structure for every scan type and profile.
  buildReport(jobId) {
    const job = this.jobs.get(jobId);
    if (!job) return null;
    const findings = this.eventStore
      .query({ types: ['finding'], limit: 500 })
      .filter((f) => f.runId === job.runId)
      .reverse();

    const by = this._countBySeverity(findings);
    const total = findings.length;
    const durationMin = job.durationMs ? Math.round(job.durationMs / 60_000) : null;

    // Check coverage summary
    const checkResults = this._checkResultsArray(job);
    const coverage = {
      total: job.totalChecks,
      passed: checkResults.filter((c) => c.status === CHECK_STATUS.PASS).length,
      issue: checkResults.filter((c) => c.status === CHECK_STATUS.ISSUE).length,
      skipped: checkResults.filter((c) => c.status === CHECK_STATUS.SKIP).length,
      notCompleted: checkResults.filter((c) => c.status === CHECK_STATUS.NOT_COMPLETED).length,
    };

    const narrative = [];
    narrative.push(
      `On ${new Date(job.startedAt || job.createdAt).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })}, our security agent ran a ${SCAN_TYPES[job.type].label.toLowerCase()} on ${job.assetName} (${job.target}).`
    );
    narrative.push(
      job.planAnnounced && job.totalChecks > 0
        ? `The agent directed its own test plan of ${job.totalChecks} areas based on initial reconnaissance and completed ${coverage.passed + coverage.issue} of them${coverage.skipped ? `, skipped ${coverage.skipped} as not applicable` : ''}${coverage.notCompleted ? `, with ${coverage.notCompleted} not reached before the scan ended` : ''}${durationMin ? ` over about ${durationMin} minute${durationMin === 1 ? '' : 's'}` : ''}.`
        : `The agent directed its own testing based on initial reconnaissance${durationMin ? ` over about ${durationMin} minute${durationMin === 1 ? '' : 's'}` : ''}.`
    );
    narrative.push(
      `A human security professional would need roughly ${effortFor(job)} of focused work to test this thoroughly — this scan completed it automatically.`
    );
    narrative.push(job.authenticated === true
      ? `Testing was performed while signed in with a test account, so member-only areas were included.`
      : `Testing was performed as an anonymous visitor.`);
    if (total === 0) {
      narrative.push(`No security issues were confirmed. That is a good result — keep protection running and re-test after major changes.`);
    } else {
      narrative.push(`It confirmed ${total} issue${total === 1 ? '' : 's'}: ${by.critical} critical, ${by.high} high, ${by.medium} medium, ${by.low} low. Every issue below includes a plain-language fix, ordered by priority.`);
    }
    const posture = this.eventStore.getAssetPosture(job.target);
    narrative.push(`Current security posture for this website: ${posture.postureScore}/100 (${posture.postureLabel}).`);

    return {
      jobId: job.id,
      runId: job.runId,
      status: job.status,
      asset: { id: job.assetId, name: job.assetName, url: job.target },
      type: job.type,
      typeLabel: SCAN_TYPES[job.type].label,
      profile: job.profile,
      profileLabel: PROFILES[job.profile].label,
      startedAt: job.startedAt,
      completedAt: job.completedAt,
      durationMs: job.durationMs,
      checks: job.checksDone,
      coverage,
      stats: { total, bySeverity: by, posture },
      narrative,
      findings: findings.map((f) => this._findingView(f)),
      checkResults,
    };
  }
}

export { SCAN_TYPES, PROFILES, PHASES, CUSTOM_OPTION_LABELS, friendlyError };
