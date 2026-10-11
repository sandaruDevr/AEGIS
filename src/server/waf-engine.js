// WAF Engine — two-tier detection per AEGIS plan:
//   Tier 1: recognition of established attack patterns (signature library)
//   Tier 2: anomaly scoring for payloads matching no known signature
//   Tier 3 (async): Jev typed triage for escalated ('held for review')
//     decisions — calibrated probabilities, never in the hot path
// Every decision is typed, calibrated and logged with attack-type classification.
//
// Decision shape (JEV-family style — typed, calibrated, cheap):
//   { action: 'allow' | 'triage' | 'block',
//     attackType: string | null,
//     tier: 1 | 2 | null,
//     confidence: number (0..1),
//     reasons: string[],
//     decisionId, ts }

import { readFile, writeFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { randomUUID, randomBytes } from 'crypto';

// ---- Tier 1: established attack-pattern signatures (OWASP-class) ----
const SIGNATURES = [
  {
    id: 'sqli-classic',
    attackType: 'sqli',
    severity: 'critical',
    pattern: /(\b(union)\b[\s\S]{0,40}\bselect\b)|(\bor\b\s+1\s*=\s*1)|('\s*or\s*')|(\bdrop\s+table\b)|(\binsert\s+into\b[\s\S]*\bvalues\b)/i,
    reason: 'Matches classic SQL injection structure',
  },
  {
    id: 'sqli-timebased',
    attackType: 'sqli',
    severity: 'critical',
    pattern: /\b(sleep|waitfor|pg_sleep|benchmark)\s*\(/i,
    reason: 'Time-based SQL injection probe',
  },
  {
    id: 'xss-tag',
    attackType: 'xss',
    severity: 'high',
    pattern: /<\s*(script|img|svg|iframe|body|object|embed|video|audio)\b[^>]*\bon[a-z]+\s*=/i,
    reason: 'HTML tag with event handler (script injection)',
  },
  {
    id: 'xss-jsproto',
    attackType: 'xss',
    severity: 'high',
    pattern: /(javascript\s*:)|(onerror\s*=)|(onload\s*=)|(alert\s*\(\s*['"]?x?ss)/i,
    reason: 'JavaScript execution payload',
  },
  {
    id: 'traversal',
    attackType: 'path_traversal',
    severity: 'high',
    pattern: /(\.\.[\/\\]){2,}|(%2e%2e[\/\\]){2,}|(\.\.;\/)/i,
    reason: 'Path traversal sequence',
  },
  {
    id: 'cmd-injection',
    attackType: 'command_injection',
    severity: 'critical',
    pattern: /[;|`]\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|rm)\b|\$\((whoami|id|uname)\)|`{1,2}(whoami|id|uname)`{1,2}/i,
    reason: 'OS command injection attempt',
  },
  {
    id: 'lfi-sensitive',
    attackType: 'file_inclusion',
    severity: 'high',
    pattern: /(\/etc\/(passwd|shadow|hosts))|(c:\\windows\\system32)|(\/proc\/self\/)/i,
    reason: 'Attempt to read sensitive system files',
  },
  {
    id: 'php-wrapper',
    attackType: 'file_inclusion',
    severity: 'high',
    pattern: /(php|data|expect|zip|phar):\/\//i,
    reason: 'PHP stream wrapper abuse',
  },
  {
    id: 'ssrf-local',
    attackType: 'ssrf',
    severity: 'high',
    pattern: /(127\.0\.0\.1|0\.0\.0\.0|localhost|169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)/i,
    reason: 'Request targeting internal/cloud metadata endpoints',
  },
  {
    id: 'xxe',
    attackType: 'xxe',
    severity: 'high',
    pattern: /<!ENTITY\s+\w+\s+SYSTEM|<!DOCTYPE[^>]*\[/i,
    reason: 'XML external entity injection',
  },
  {
    id: 'ssti',
    attackType: 'template_injection',
    severity: 'critical',
    pattern: /\{\{[\s\S]*?[\+\*]\s*[\d'"][\s\S]*?\}\}|\$\{jndi:(ldap|rmi|dns):/i,
    reason: 'Server-side template / JNDI injection probe',
  },
  {
    id: 'log4shell',
    attackType: 'template_injection',
    severity: 'critical',
    pattern: /\$\{jndi/i,
    reason: 'Log4Shell (JNDI) payload',
  },
  {
    id: 'rce-webshell',
    attackType: 'rce',
    severity: 'critical',
    pattern: /(eval\s*\(|system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\().{0,40}\$(_GET|_POST|REQUEST)/i,
    reason: 'Webshell-style code execution pattern',
  },
];

// ---- Tier 2: anomaly scoring for payloads with no signature match ----
const ANOMALY = {
  // Payloads longer than typical parameters get a small score bump.
  length: (s) => Math.min(s.length / 2048, 0.3),
  // Security-sensitive tokens that alone are not proof of attack.
  keyword: (s) => {
    const hits = s.match(/\b(union|select|insert|update|delete|drop|exec|execute|system|passwd|shadow|token|admin|base64|eval|cmd|shell)\b/gi);
    return Math.min((hits ? hits.length : 0) * 0.08, 0.35);
  },
  // High density of special characters common in exploit payloads.
  specialChars: (s) => {
    const special = s.replace(/[a-z0-9\s]/gi, '').length;
    return Math.min(special / Math.max(s.length, 1) / 1.2, 0.3);
  },
  // Multi-layer encoding often hides payloads from naive filters.
  encoding: (s) => {
    let score = 0;
    if (/%[0-9a-f]{2}/i.test(s)) score += 0.15;
    if (/[A-Za-z0-9+/=]{24,}/.test(s)) score += 0.15; // base64-like run
    if (/\\u[0-9a-f]{4}|\\x[0-9a-f]{2}/i.test(s)) score += 0.1;
    return Math.min(score, 0.3);
  },
  // Shannon entropy — random-looking strings are rarely legitimate input.
  entropy: (s) => {
    if (!s) return 0;
    const freq = new Map();
    for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
    let h = 0;
    for (const count of freq.values()) {
      const p = count / s.length;
      h -= p * Math.log2(p);
    }
    return Math.min(Math.max(0, (h - 3.2) / 2.8), 0.25);
  },
};

// Normalize input before matching: percent-decode (twice, to catch
// double-encoding) so encoded payloads are inspected in decoded form.
// Standard WAF behavior — without it, encoded attacks slip past
// \b-anchored signatures (e.g. "UNION%20SELECT" never matches \bselect\b).
function normalizeInput(input) {
  let out = String(input ?? '');
  for (let pass = 0; pass < 2; pass++) {
    if (!/%[0-9a-f]{2}/i.test(out)) break;
    let next;
    try {
      next = decodeURIComponent(out);
    } catch {
      // Tolerate malformed sequences — decode each %XX independently.
      next = out.replace(/%[0-9a-f]{2}/gi, (m) => {
        try { return decodeURIComponent(m); } catch { return m; }
      });
    }
    if (next === out) break;
    out = next;
  }
  return out;
}

// Calibrated action mapping (Tier 2 anomaly score → typed decision).
// Thresholds are defaults — the operator can tune them in the WAF setup UI.
const ANOMALY_THRESHOLDS = { block: 0.85, triage: 0.6 };

// WAF operating modes (enterprise standard: monitor first, enforce after tuning).
//   monitor — every decision is logged; blocks are recorded as "would have
//             blocked" and held, so nothing breaks while tuning.
//   enforce — blocks are enforced.
const DEFAULT_CONFIG = {
  mode: 'monitor',
  thresholds: { triage: 0.6, block: 0.85 },
  triage: true, // Jev typed triage for escalated decisions (when a provider is configured)
};

export class WafEngine {
  constructor(dataDir, eventStore, { jev = null } = {}) {
    this.dataDir = dataDir;
    this.eventStore = eventStore;
    this.rulesPath = join(dataDir, 'waf-rules.json');
    this.configPath = join(dataDir, 'waf-config.json');
    this.installsPath = join(dataDir, 'waf-installs.json');
    // Jev typed triage — only invoked on 'triage' escalation, never in the
    // hot path (plan: "async triage only on escalation").
    this.jev = jev;
    this.customRules = [];
    this.config = { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_CONFIG.thresholds } };
    this.installs = []; // edge deployments: { token, assetId, createdAt, lastSeenAt, requests, revoked }
    this._stats = { total: 0, blocked: 0, triaged: 0, allowed: 0 };
  }

  async init() {
    await this._loadConfig();
    await this._loadInstalls();
    await this._loadRules();
  }

  // ---- Operating config (mode / thresholds / triage) ----

  async _loadConfig() {
    if (!existsSync(this.configPath)) return;
    try {
      const parsed = JSON.parse(await readFile(this.configPath, 'utf-8'));
      this.config = this._mergeConfig(parsed);
    } catch (err) {
      console.warn(`[WAF] Failed to load config: ${err.message}`);
    }
  }

  _mergeConfig(patch) {
    const next = { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_CONFIG.thresholds } };
    if (patch && typeof patch === 'object') {
      if (patch.mode === 'monitor' || patch.mode === 'enforce') next.mode = patch.mode;
      if (patch.thresholds && typeof patch.thresholds === 'object') {
        const t = Number(patch.thresholds.triage);
        const b = Number(patch.thresholds.block);
        if (Number.isFinite(t) && t >= 0.1 && t <= 1) next.thresholds.triage = t;
        if (Number.isFinite(b) && b >= 0.2 && b <= 1) next.thresholds.block = b;
      }
      if (typeof patch.triage === 'boolean') next.triage = patch.triage;
    }
    if (next.thresholds.triage > next.thresholds.block) next.thresholds.triage = next.thresholds.block;
    return next;
  }

  async _saveConfig() {
    await mkdir(this.dataDir, { recursive: true });
    await writeFile(this.configPath, JSON.stringify(this.config, null, 2), 'utf-8');
  }

  getConfig() {
    return JSON.parse(JSON.stringify(this.config));
  }

  async updateConfig(patch = {}) {
    this.config = this._mergeConfig({ ...this.config, ...patch });
    await this._saveConfig();
    this.eventStore?.append('waf_config_updated', {
      mode: this.config.mode,
      thresholds: this.config.thresholds,
      triage: this.config.triage,
      title: `WAF set to ${this.config.mode} mode`,
    });
    return this.getConfig();
  }

  // ---- Edge installs (per-asset deployment tokens) ----

  async _loadInstalls() {
    if (!existsSync(this.installsPath)) return;
    try {
      const parsed = JSON.parse(await readFile(this.installsPath, 'utf-8'));
      this.installs = Array.isArray(parsed.installs) ? parsed.installs : [];
    } catch (err) {
      console.warn(`[WAF] Failed to load installs: ${err.message}`);
      this.installs = [];
    }
  }

  async _saveInstalls() {
    await mkdir(this.dataDir, { recursive: true });
    await writeFile(this.installsPath, JSON.stringify({ installs: this.installs }, null, 2), 'utf-8');
  }

  async createInstall(assetId) {
    // One active token per asset — regenerating revokes the old one.
    const existing = this.installs.find((i) => i.assetId === assetId && !i.revoked);
    if (existing) existing.revoked = true;
    const install = {
      token: `wafinst_${randomBytes(24).toString('base64url')}`,
      assetId,
      createdAt: Date.now(),
      lastSeenAt: null,
      requests: 0,
      revoked: false,
    };
    this.installs.push(install);
    await this._saveInstalls();
    this.eventStore?.append('waf_install_updated', {
      assetId,
      action: existing ? 'regenerated' : 'created',
      title: existing ? 'WAF install token regenerated' : 'WAF install created',
    });
    return install;
  }

  // Hot-path token check — no I/O; usage stats are persisted lazily.
  authenticateInstall(token) {
    if (!token) return null;
    const install = this.installs.find((i) => i.token === token && !i.revoked);
    if (!install) return null;
    install.lastSeenAt = Date.now();
    install.requests++;
    if (!install._dirty) {
      install._dirty = true;
      setTimeout(() => {
        install._dirty = false;
        this._saveInstalls().catch(() => {});
      }, 5000).unref?.();
    }
    return install;
  }

  async revokeInstall(token) {
    const install = this.installs.find((i) => i.token === token);
    if (!install || install.revoked) return false;
    install.revoked = true;
    await this._saveInstalls();
    this.eventStore?.append('waf_install_updated', {
      assetId: install.assetId,
      action: 'revoked',
      title: 'WAF install token revoked',
    });
    return true;
  }

  listInstalls() {
    return this.installs
      .filter((i) => !i.revoked)
      .map(({ token, ...rest }) => ({ ...rest, tokenMasked: `${token.slice(0, 12)}…` }));
  }

  getInstallByToken(token) {
    return this.installs.find((i) => i.token === token) || null;
  }

  // Full install (with token) for snippet generation — never expose via list APIs.
  getActiveInstall(assetId) {
    return this.installs.find((i) => i.assetId === assetId && !i.revoked) || null;
  }

  async _loadRules() {
    if (!existsSync(this.rulesPath)) {
      this.customRules = [];
      return;
    }
    try {
      const raw = await readFile(this.rulesPath, 'utf-8');
      const parsed = JSON.parse(raw);
      this.customRules = Array.isArray(parsed.rules) ? parsed.rules : [];
    } catch (err) {
      console.warn(`[WAF] Failed to load rules: ${err.message}`);
      this.customRules = [];
    }
  }

  async _saveRules() {
    await mkdir(this.dataDir, { recursive: true });
    await writeFile(this.rulesPath, JSON.stringify({ rules: this.customRules }, null, 2), 'utf-8');
  }

  // Add a rule — used by the closed loop (agent findings auto-tune WAF rules)
  // and manually from the dashboard.
  async addRule({ pattern, attackType, severity = 'high', source = 'manual', note = '' }) {
    const rule = {
      id: `rule-${randomUUID().slice(0, 8)}`,
      pattern: String(pattern),
      attackType,
      severity,
      source,
      note,
      enabled: true,
      createdAt: Date.now(),
    };
    this.customRules.push(rule);
    await this._saveRules();
    if (this.eventStore) {
      this.eventStore.append('waf_rule_updated', {
        ruleId: rule.id,
        source,
        attackType,
        severity,
        title: `WAF rule added (${source})`,
        pattern: rule.pattern,
      });
    }
    return rule;
  }

  async removeRule(ruleId) {
    const before = this.customRules.length;
    this.customRules = this.customRules.filter((r) => r.id !== ruleId);
    if (this.customRules.length !== before) {
      await this._saveRules();
      return true;
    }
    return false;
  }

  listRules() {
    return [...this.customRules];
  }

  // ---- Core evaluation ----

  evaluatePayload(payload, context = {}) {
    const input = typeof payload === 'string' ? payload : JSON.stringify(payload ?? '');
    return this._decide(input, context);
  }

  // Evaluate an inbound HTTP request the way an edge proxy would.
  // assetId links the decision to a protected website (per-asset tracking).
  evaluateRequest({ method = 'GET', path = '', query = '', headers = {}, body = '', assetId = null } = {}) {
    const parts = [path, query];
    for (const [k, v] of Object.entries(headers || {})) {
      // Skip infrastructure / low-signal headers — not attack surface, and they
      // cause false positives (e.g. "Host: localhost" tripping the SSRF rule).
      if (/user-agent|referer|cookie|origin|x-forwarded|^host$|^accept|^connection$|^content-(length|type)$|^x-real-ip$/i.test(k)) continue;
      parts.push(`${k}: ${v}`);
    }
    if (body) parts.push(typeof body === 'string' ? body : JSON.stringify(body));
    return this._decide(parts.join('\n'), { method, path, assetId });
  }

  _decide(input, context) {
    const t0 = Date.now();
    const { mode, thresholds } = this.config;
    const monitor = mode === 'monitor';

    // Decode before matching so encoded payloads are inspected in decoded form.
    input = normalizeInput(input);

    // Tier 1 — established patterns (built-in signatures + per-tenant custom rules)
    for (const sig of SIGNATURES) {
      const match = input.match(sig.pattern);
      if (match) {
        return this._log({
          action: monitor ? 'triage' : 'block',
          wouldBlock: monitor || undefined,
          attackType: sig.attackType,
          tier: 1,
          confidence: 0.95,
          reasons: monitor
            ? [sig.reason, 'Monitor mode — attack identified, enforcement off', `signature:${sig.id}`]
            : [sig.reason, `signature:${sig.id}`],
          matchedSample: match[0],
          input,
          context,
          severity: sig.severity,
          latencyMs: Date.now() - t0,
        });
      }
    }
    for (const rule of this.customRules) {
      if (!rule.enabled) continue;
      let matched = false;
      try {
        matched = new RegExp(rule.pattern, 'i').test(input);
      } catch {
        matched = input.toLowerCase().includes(String(rule.pattern).toLowerCase());
      }
      if (matched) {
        return this._log({
          action: monitor ? 'triage' : 'block',
          wouldBlock: monitor || undefined,
          attackType: rule.attackType,
          tier: 1,
          confidence: 0.9,
          reasons: monitor
            ? [`Custom rule matched (${rule.source})`, 'Monitor mode — attack identified, enforcement off', `rule:${rule.id}`]
            : [`Custom rule matched (${rule.source})`, `rule:${rule.id}`],
          matchedSample: input.slice(0, 120),
          input,
          context,
          severity: rule.severity,
          latencyMs: Date.now() - t0,
        });
      }
    }

    // Tier 2 — anomaly scoring (no known signature matched)
    let score = 0;
    const reasons = [];
    for (const [name, fn] of Object.entries(ANOMALY)) {
      const contribution = fn(input);
      if (contribution > 0.05) {
        reasons.push(`${name}: +${contribution.toFixed(2)}`);
      }
      score += contribution;
    }
    score = Math.min(score, 1);

    if (score >= thresholds.block) {
      return this._log({
        action: monitor ? 'triage' : 'block',
        wouldBlock: monitor || undefined,
        attackType: 'anomaly',
        tier: 2,
        confidence: score,
        reasons: monitor
          ? [`Anomaly score ${score.toFixed(2)} ≥ block threshold`, 'Monitor mode — would have blocked', ...reasons]
          : [`Anomaly score ${score.toFixed(2)} ≥ block threshold`, ...reasons],
        matchedSample: input.slice(0, 120),
        input,
        context,
        severity: 'medium',
        latencyMs: Date.now() - t0,
      });
    }

    if (score >= thresholds.triage) {
      return this._log({
        action: 'triage',
        attackType: 'anomaly',
        tier: 2,
        confidence: score,
        reasons: [`Anomaly score ${score.toFixed(2)} — escalated for review`, ...reasons],
        matchedSample: input.slice(0, 120),
        input,
        context,
        severity: 'low',
        latencyMs: Date.now() - t0,
      });
    }

    return this._log({
      action: 'allow',
      attackType: null,
      tier: null,
      confidence: 1 - score,
      reasons: ['No attack pattern or anomaly detected'],
      matchedSample: null,
      input,
      context,
      severity: null,
      latencyMs: Date.now() - t0,
    });
  }

  // Jev typed triage — resolves escalated ('held for review') decisions with
  // calibrated probabilities. One batched call, three typed questions, answers
  // branch in plain code (no free-text parsing).
  //
  // Fail-safe policy: if Jev is unavailable or fails, the decision STAYS
  // 'triage' (held for human review) — never auto-allowed (security) and
  // never auto-blocked (false positives).
  async triageAsync(decision) {
    if (decision.action !== 'triage' || !this.jev?.available || !this.config.triage) return decision;

    // Raw request only — Jev judges it on its own. We do not describe what any
    // attack class looks like; the option keys below are just the output
    // vocabulary the UI branches on, not detection rules.
    const state = [
      `HTTP ${decision.method || 'GET'} ${decision.path || '/'}`,
      `Anomaly score: ${Number(decision.confidence ?? 0).toFixed(2)}`,
      `Signals: ${(decision.reasons || []).join(' | ')}`,
      `Payload: ${decision.payloadSample || ''}`,
    ].join('\n');

    const answers = await this.jev.decide(state, {
      malicious: {
        type: 'noul',
        instructions: 'Is this a genuine attack attempt?',
      },
      attackType: {
        type: 'choice',
        instructions: 'What kind of attack is this?',
        criteria: {
          sqli: 'SQL injection',
          xss: 'Cross-site scripting',
          path_traversal: 'Path traversal',
          command_injection: 'Command injection',
          ssrf: 'Server-side request forgery',
          xxe: 'XML external entity injection',
          template_injection: 'Template / JNDI injection',
          rce: 'Remote code execution',
          file_inclusion: 'File inclusion',
          benign: 'Not an attack',
        },
      },
      severity: {
        type: 'score',
        instructions: 'How severe is the impact if this is an attack?',
        criteria: ['low', 'medium', 'high', 'critical'],
      },
    });

    const p = answers?.malicious?.noul;
    if (typeof p !== 'number' || p < 0 || p > 1) return decision; // malformed — stay held for review

    const prevAction = decision.action;
    const type = answers.attackType?.choice || 'anomaly';
    const sevIdx = Math.round(Number(answers.severity?.score ?? 0));
    const severity = ['low', 'medium', 'high', 'critical'][Math.min(Math.max(sevIdx, 0), 3)] || 'low';

    // Typed merge policy — deterministic, documented thresholds.
    decision.attackType = type === 'benign' ? 'anomaly' : type;
    decision.severity = severity;
    decision.confidence = p;
    decision.reasons.push(`Jev triage: malicious ${p.toFixed(2)} · ${decision.attackType} · ${decision.severity}`);
    if (p >= 0.75) {
      decision.action = 'block';
    } else if (p <= 0.35) {
      decision.action = 'allow';
    } // else: stays 'triage' — held for human review

    this._log(decision, true, prevAction);
    return decision;
  }

  _log(decision, isUpdate = false, prevAction = null) {
    const record = {
      decisionId: decision.decisionId || `waf-${randomUUID().slice(0, 8)}`,
      action: decision.action,
      wouldBlock: decision.wouldBlock || undefined,
      attackType: decision.attackType,
      tier: decision.tier,
      confidence: Number(decision.confidence?.toFixed(3) ?? 0),
      reasons: decision.reasons,
      severity: decision.severity,
      payloadSample: decision.matchedSample ? decision.matchedSample.slice(0, 200) : (decision.payloadSample || null),
      method: decision.context?.method || decision.method,
      path: decision.context?.path || decision.path,
      assetId: decision.context?.assetId || null,
      latencyMs: decision.latencyMs,
      title:
        decision.action === 'block'
          ? `Blocked ${decision.attackType || 'anomaly'} attack`
          : decision.action === 'triage'
            ? decision.wouldBlock
              ? `Would have blocked — ${decision.attackType || 'anomaly'} (monitor mode)`
              : `Suspicious payload held for review`
            : null,
    };
    if (this.eventStore) {
      if (isUpdate) {
        // Audit trail for the resolution — every state change is recorded.
        this.eventStore.append('waf_decision_updated', { ...record, prevAction });
      } else {
        this.eventStore.append('waf_decision', record);
      }
    }
    if (isUpdate && prevAction) {
      // Stats move with the decision — no double counting.
      if (prevAction === 'triage') this._stats.triaged = Math.max(0, this._stats.triaged - 1);
    }
    this._stats.total++;
    if (decision.action === 'block') this._stats.blocked++;
    else if (decision.action === 'triage') this._stats.triaged++;
    else this._stats.allowed++;
    return { ...record, input: undefined };
  }

  getStats() {
    return { ...this._stats, customRules: this.customRules.length };
  }
}

export { SIGNATURES, ANOMALY_THRESHOLDS };
