// Agent Orchestrator — per AEGIS plan:
//   "Reconnaissance → attack planning → verified exploit chains → plain-language
//    fix reports, under strict per-agent scope assignment (one target class, one
//    toolset, one budget each). Verification layer before any finding is reported."
//
// The orchestrator wraps the existing AgentLoop WITHOUT modifying the brain files:
//   - assigns a scope profile to every run (target class, allowed toolset, budget)
//   - intercepts tool execution to enforce budget and log events
//   - runs a verification layer over reported findings (evidence required, dedupe)
//   - persists verified findings to the event store
//   - closes the loop: verified findings auto-tune WAF rules

import { randomUUID } from 'crypto';

const DEFAULT_BUDGET = {
  maxToolCalls: 120,     // hard cap on tool executions per run
  maxDurationMs: 20 * 60 * 1000,
  maxCostUsd: 2.0,       // LLM spend cap per run (cost engineering)
};

const SCOPE_PRESETS = {
  web_app: {
    label: 'Web application',
    allowedTools: null, // null = all tools except explicitly denied
    deniedTools: ['run_wsl_command'],
    guidance: 'Focus on application-layer testing of the target web application: headers, forms, cookies, secrets, JS sources, DOM, and HTTP behavior.',
  },
  network: {
    label: 'Network / infrastructure',
    allowedTools: ['run_wsl_command', 'make_request', 'check_security_headers', 'wait', 'create_file', 'write_file', 'read_file', 'list_files'],
    deniedTools: ['modify_element', 'inject_style', 'click_element'],
    guidance: 'Focus on network and infrastructure reconnaissance and service enumeration using the WSL2 toolset.',
  },
  full: {
    label: 'Full assessment',
    allowedTools: null,
    deniedTools: [],
    guidance: 'Full assessment authorized: application-layer and network testing within the declared target scope only.',
  },
};

// Finding types that map directly to a WAF defense (closed loop).
const WAF_RULE_MAPPING = {
  sqli: { pattern: "(\\b(union)\\b[\\s\\S]{0,40}\\bselect\\b)|(\\bor\\b\\s+1\\s*=\\s*1)|('\\s*or\\s*')", attackType: 'sqli' },
  xss: { pattern: '<\\s*(script|img|svg|iframe)\\b[^>]*\\bon[a-z]+\\s*=|javascript\\s*:', attackType: 'xss' },
  path_traversal: { pattern: '(\\.\\.[/\\\\]){2,}', attackType: 'path_traversal' },
  command_injection: { pattern: '[;|`]\\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|rm)\\b', attackType: 'command_injection' },
  ssti: { pattern: '\\{\\{[\\s\\S]*?[+*][\\s\\S]*?\\}\\}|\\$\\{jndi', attackType: 'template_injection' },
  xxe: { pattern: '<!ENTITY\\s+\\w+\\s+SYSTEM', attackType: 'xxe' },
};

export class AgentOrchestrator {
  constructor(agentLoop, eventStore, wafEngine, credentialVault = null) {
    this.agent = agentLoop;
    this.eventStore = eventStore;
    this.waf = wafEngine;
    this.vault = credentialVault;
    this.activeRun = null;
  }

  // ---- Scoped run ----

  buildScopedPrompt({ target, scope, budget }) {
    const preset = SCOPE_PRESETS[scope] || SCOPE_PRESETS.web_app;
    return [
      `## Run Scope (STRICT — overrides general instructions)`,
      `Target: ${target || 'not specified — ask the operator before testing'}`,
      `Scope class: ${preset.label}`,
      `Tool budget: max ${budget.maxToolCalls} tool calls, ${Math.round(budget.maxDurationMs / 60000)} minutes, $${budget.maxCostUsd.toFixed(2)} LLM spend.`,
      `Allowed testing surface: ${preset.guidance}`,
      ``,
      `### Hard rules for this run`,
      `- Test ONLY the declared target. If the target is missing or ambiguous, stop and ask.`,
      `- Read-only first: never modify, delete, or degrade the target.`,
      `- Stay within the tool budget; stop testing when it is reached and report.`,
      ``,
      `### Finding report format (REQUIRED at the end of testing)`,
      `After testing, emit one JSON array named FINDINGS with every confirmed issue:`,
      `\`\`\`json`,
      `[{"title":"...","severity":"critical|high|medium|low|info","attackType":"sqli|xss|path_traversal|command_injection|ssrf|xxe|template_injection|rce|misconfiguration|secrets_exposure|other","summary":"one plain-language sentence a business owner understands","evidence":"the exact tool result / request that proves it","fix":"plain-language remediation","cvss":0.0}]`,
      `\`\`\``,
      `Only include findings you verified with real evidence. No speculation.`,
    ].join('\n');
  }

  async startRun({ target, prompt, scope = 'web_app', budget = {}, clearConversation = true, assetId = null, jobId = null } = {}) {
    if (this.activeRun) {
      throw new Error('Another agent run is already in progress. Stop it first.');
    }

    const runBudget = { ...DEFAULT_BUDGET, ...budget };
    const run = {
      runId: `run-${randomUUID().slice(0, 8)}`,
      target: target || null,
      assetId,
      jobId,
      scope: SCOPE_PRESETS[scope] ? scope : 'web_app',
      budget: runBudget,
      toolCalls: 0,
      startedAt: Date.now(),
      costAtStart: this.agent.sessionCost || 0,
      findings: [],
      violations: [],
    };
    this.activeRun = run;
    // Per-run asset context — get_login_credentials serves only this asset's
    // stored test credentials, and only while this run is active.
    this.agent.executor.currentAssetId = run.assetId || null;

    this.eventStore.append('scan_started', {
      runId: run.runId,
      jobId: run.jobId,
      assetId: run.assetId,
      target: run.target,
      scope: run.scope,
      title: `Scan started${run.target ? ` — ${run.target}` : ''}`,
      budget: runBudget,
    });

    // Install tool interceptor (budget + logging) for the duration of the run.
    const uninstall = this._installToolInterceptor(run);
    const timeoutHandle = setTimeout(() => this.stopRun('time budget exceeded'), runBudget.maxDurationMs);

    try {
      const scopedPrompt = `${prompt || this._defaultPrompt(run)}\n\n${this.buildScopedPrompt(run)}`;
      if (clearConversation) this.agent.clearConversation();
      await this.agent.run(scopedPrompt);
    } finally {
      clearTimeout(timeoutHandle);
      uninstall();
      this.agent.executor.currentAssetId = null;
    }

    // Verification layer — extract, verify, dedupe, persist findings.
    const verified = await this._verifyAndPersistFindings(run);

    this.eventStore.append('scan_completed', {
      runId: run.runId,
      jobId: run.jobId,
      assetId: run.assetId,
      target: run.target,
      title: `Scan completed — ${verified.length} finding${verified.length === 1 ? '' : 's'}`,
      durationMs: Date.now() - run.startedAt,
      toolCalls: run.toolCalls,
      costUsd: Math.max(0, (this.agent.sessionCost || 0) - run.costAtStart),
      findingsCount: verified.length,
      violations: run.violations,
    });

    this.activeRun = null;
    return { runId: run.runId, findings: verified, violations: run.violations };
  }

  _defaultPrompt(run) {
    return run.target
      ? `Perform a full security assessment of ${run.target}. Check for OWASP Top 10 vulnerabilities, analyze forms, inspect headers, scan for secrets, and produce a plain-language fix report.`
      : 'How can I help with your security assessment?';
  }

  stopRun(reason = 'stopped by operator') {
    if (this.activeRun) {
      this.activeRun.stopped = true;
      this.activeRun.stopReason = reason;
    }
    this.agent.stop();
  }

  _installToolInterceptor(run) {
    const executor = this.agent.executor;
    const original = executor.executeTool.bind(executor);
    const self = this;

    executor.executeTool = async function (toolName, args) {
      // Budget enforcement — fail closed.
      if (run.toolCalls >= run.budget.maxToolCalls) {
        run.violations.push(`budget: tool-call cap reached (${run.budget.maxToolCalls})`);
        return { success: false, error: `Tool budget exhausted for this run (max ${run.budget.maxToolCalls} tool calls). Finish and report now.` };
      }
      const preset = SCOPE_PRESETS[run.scope];
      if (preset.allowedTools && !preset.allowedTools.includes(toolName)) {
        run.violations.push(`scope: tool '${toolName}' not allowed in '${run.scope}' scope`);
        return { success: false, error: `Tool '${toolName}' is outside this run's scope (${preset.label}).` };
      }
      if (preset.deniedTools.includes(toolName)) {
        run.violations.push(`scope: tool '${toolName}' is denied in '${run.scope}' scope`);
        return { success: false, error: `Tool '${toolName}' is denied for this run's scope.` };
      }

      run.toolCalls++;
      const t0 = Date.now();
      try {
        const result = await original(toolName, args);
        self.eventStore.append('tool_executed', {
          runId: run.runId,
          tool: toolName,
          success: result?.success !== false,
          durationMs: Date.now() - t0,
        });
        return result;
      } catch (err) {
        self.eventStore.append('tool_executed', {
          runId: run.runId,
          tool: toolName,
          success: false,
          durationMs: Date.now() - t0,
          error: err.message,
        });
        throw err;
      }
    };

    return () => {
      // Remove the own-property override; prototype method lookup is restored.
      delete executor.executeTool;
    };
  }

  // ---- Verification layer ----
  // A finding is persisted ONLY if it has: title, severity, summary, evidence.
  // Duplicates of existing open findings (same title+target) are dropped.

  async _verifyAndPersistFindings(run) {
    const raw = this._extractFindingsJson(this._lastAssistantText());
    if (!Array.isArray(raw)) return [];

    const verified = [];
    const existing = new Set(
      this.eventStore
        .query({ types: ['finding'], limit: 1000 })
        .filter((f) => f.status !== 'fixed')
        .map((f) => `${f.title}::${f.target}`)
    );

    for (const item of raw) {
      const check = this._verifyFinding(item, run);
      if (!check.ok) {
        run.violations.push(`finding rejected: ${check.reason}`);
        continue;
      }
      const key = `${item.title}::${run.target}`;
      if (existing.has(key)) {
        run.violations.push(`finding deduped: ${item.title}`);
        continue;
      }
      existing.add(key);

      // Defense in depth: scrub stored test credentials out of any finding
      // text before persistence, even if the agent was told not to include them.
      const secrets = this._credentialSecrets(run.assetId);
      const redact = (t) => this._redactSecrets(t, secrets);

      const event = this.eventStore.append('finding', {
        runId: run.runId,
        jobId: run.jobId,
        assetId: run.assetId,
        target: run.target,
        title: redact(String(item.title)).slice(0, 200),
        severity: this._normalizeSeverity(item.severity),
        attackType: item.attackType || 'other',
        summary: redact(String(item.summary)).slice(0, 1000),
        evidence: redact(String(item.evidence || '')).slice(0, 2000),
        fix: redact(String(item.fix || '')).slice(0, 1000),
        cvss: Number(item.cvss) || null,
        verified: true,
        status: 'open',
        statusUpdatedAt: Date.now(),
      });
      verified.push(event);

      // Closed loop v1 — verified findings of known types auto-tune WAF rules.
      const mapping = WAF_RULE_MAPPING[item.attackType];
      if (mapping && run.target) {
        await this.waf.addRule({
          pattern: mapping.pattern,
          attackType: mapping.attackType,
          severity: this._normalizeSeverity(item.severity),
          source: 'agent',
          note: `Auto-tuned from verified finding "${item.title}" on ${run.target}`,
        });
      }
    }
    run.findings = verified;
    return verified;
  }

  _verifyFinding(item, run) {
    if (!item || typeof item !== 'object') return { ok: false, reason: 'not an object' };
    if (!item.title) return { ok: false, reason: 'missing title' };
    if (!item.summary) return { ok: false, reason: 'missing plain-language summary' };
    if (!item.evidence) return { ok: false, reason: 'missing evidence — unverified' };
    if (!this._normalizeSeverity(item.severity)) return { ok: false, reason: `invalid severity '${item.severity}'` };
    return { ok: true };
  }

  // Decrypted credential strings for an asset (redaction source). Never logged.
  _credentialSecrets(assetId) {
    if (!this.vault || !assetId) return [];
    const creds = this.vault.get(assetId);
    if (!creds) return [];
    return [creds.username, creds.password].filter((s) => s && String(s).length >= 4);
  }

  _redactSecrets(text, secrets) {
    let out = String(text || '');
    for (const s of secrets) {
      out = out.split(s).join('[redacted]');
    }
    return out;
  }

  _normalizeSeverity(sev) {
    const s = String(sev || '').toLowerCase();
    return ['critical', 'high', 'medium', 'low', 'info'].includes(s) ? s : null;
  }

  _lastAssistantText() {
    const convo = this.agent.conversation || [];
    for (let i = convo.length - 1; i >= 0; i--) {
      if (convo[i].role === 'assistant' && typeof convo[i].content === 'string') {
        return convo[i].content;
      }
    }
    return '';
  }

  _extractFindingsJson(text) {
    if (!text) return null;
    const fence = text.match(/```json\s*([\s\S]*?)```/i);
    const candidates = [];
    if (fence) candidates.push(fence[1]);
    // Also accept a bare trailing JSON array.
    const bare = text.match(/\[\s*\{[\s\S]*\}\s*\]\s*$/);
    if (bare) candidates.push(bare[0]);
    for (const c of candidates) {
      try {
        const parsed = JSON.parse(c.trim());
        if (Array.isArray(parsed)) return parsed;
      } catch {
        // try next candidate
      }
    }
    return null;
  }
}

export { SCOPE_PRESETS, DEFAULT_BUDGET };
