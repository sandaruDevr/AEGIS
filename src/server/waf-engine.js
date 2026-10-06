// WAF Engine — two-tier detection per OneEye360 plan:
//   Tier 1: recognition of established attack patterns (signature library)
//   Tier 2: anomaly scoring for payloads matching no known signature
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
import { randomUUID } from 'crypto';

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

// Calibrated action mapping (Tier 2 anomaly score → typed decision).
const ANOMALY_THRESHOLDS = { block: 0.85, triage: 0.6 };

export class WafEngine {
  constructor(dataDir, eventStore, { llmTriage = null } = {}) {
    this.dataDir = dataDir;
    this.eventStore = eventStore;
    this.rulesPath = join(dataDir, 'waf-rules.json');
    // Optional async LLM triage — only invoked on 'triage' escalation (plan: "async LLM triage only on escalation").
    this.llmTriage = llmTriage;
    this.customRules = [];
    this._stats = { total: 0, blocked: 0, triaged: 0, allowed: 0 };
  }

  async init() {
    await this._loadRules();
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
  evaluateRequest({ method = 'GET', path = '', query = '', headers = {}, body = '' } = {}) {
    const parts = [path, query];
    for (const [k, v] of Object.entries(headers || {})) {
      if (/user-agent|referer|cookie|origin|x-forwarded/i.test(k)) continue; // low-signal headers
      parts.push(`${k}: ${v}`);
    }
    if (body) parts.push(typeof body === 'string' ? body : JSON.stringify(body));
    return this._decide(parts.join('\n'), { method, path });
  }

  _decide(input, context) {
    const t0 = Date.now();

    // Tier 1 — established patterns (built-in signatures + per-tenant custom rules)
    for (const sig of SIGNATURES) {
      const match = input.match(sig.pattern);
      if (match) {
        return this._log({
          action: 'block',
          attackType: sig.attackType,
          tier: 1,
          confidence: 0.95,
          reasons: [sig.reason, `signature:${sig.id}`],
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
          action: 'block',
          attackType: rule.attackType,
          tier: 1,
          confidence: 0.9,
          reasons: [`Custom rule matched (${rule.source})`, `rule:${rule.id}`],
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

    if (score >= ANOMALY_THRESHOLDS.block) {
      return this._log({
        action: 'block',
        attackType: 'anomaly',
        tier: 2,
        confidence: score,
        reasons: [`Anomaly score ${score.toFixed(2)} ≥ block threshold`, ...reasons],
        matchedSample: input.slice(0, 120),
        input,
        context,
        severity: 'medium',
        latencyMs: Date.now() - t0,
      });
    }

    if (score >= ANOMALY_THRESHOLDS.triage) {
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

  // Async LLM triage — only for escalated decisions, never in the hot path.
  async triageAsync(decision) {
    if (decision.action !== 'triage' || !this.llmTriage) return decision;
    try {
      const verdict = await this.llmTriage({
        payloadSample: decision.payloadSample,
        anomalyScore: decision.confidence,
        reasons: decision.reasons,
      });
      if (verdict && typeof verdict === 'object' && 'action' in verdict) {
        decision.action = verdict.action;
        decision.confidence = verdict.confidence ?? decision.confidence;
        decision.reasons.push(`LLM triage: ${verdict.reason || 'escalated review complete'}`);
        this._log(decision, true);
      }
    } catch (err) {
      console.warn(`[WAF] LLM triage failed: ${err.message}`);
    }
    return decision;
  }

  _log(decision, isUpdate = false) {
    const record = {
      decisionId: decision.decisionId || `waf-${randomUUID().slice(0, 8)}`,
      action: decision.action,
      attackType: decision.attackType,
      tier: decision.tier,
      confidence: Number(decision.confidence?.toFixed(3) ?? 0),
      reasons: decision.reasons,
      severity: decision.severity,
      payloadSample: decision.matchedSample ? decision.matchedSample.slice(0, 200) : null,
      method: decision.context?.method,
      path: decision.context?.path,
      latencyMs: decision.latencyMs,
      title:
        decision.action === 'block'
          ? `Blocked ${decision.attackType || 'anomaly'} attack`
          : decision.action === 'triage'
            ? `Suspicious payload held for review`
            : null,
    };
    if (this.eventStore && (decision.action !== 'allow' || !isUpdate)) {
      this.eventStore.append('waf_decision', record);
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
