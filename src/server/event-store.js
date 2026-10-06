// Event Store — append-only JSONL store with a simple query API.
// Per OneEye360 plan: "Web dashboard + simple API over the event store."
// Every WAF decision, agent finding, scan lifecycle event and report is an
// append-only event. Posture is derived, never mutated.

import { appendFile, mkdir, readFile, rename } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';

const EVENT_TYPES = [
  'scan_started',
  'scan_completed',
  'tool_executed',
  'finding',
  'finding_updated',
  'waf_decision',
  'waf_rule_updated',
  'report_generated',
];

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// Posture score weights — deterministic and explainable, built for an owner.
const SEVERITY_DEDUCTION = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
const ATTACK_BLOCK_DEDUCTION = 0.25; // per blocked attack in trailing 24h
const ATTACK_DEDUCTION_CAP = 20;     // cap so a flood doesn't zero the score

export class EventStore {
  constructor(dataDir, tenantId = 'default') {
    this.dataDir = dataDir;
    this.tenantId = tenantId;
    this.filePath = join(dataDir, 'events.jsonl');
    this.events = [];
    this._seq = 0;
  }

  async init() {
    if (!existsSync(this.dataDir)) {
      await mkdir(this.dataDir, { recursive: true });
    }
    await this._load();
  }

  async _load() {
    if (!existsSync(this.filePath)) return;
    try {
      const raw = await readFile(this.filePath, 'utf-8');
      for (const line of raw.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          this.events.push(JSON.parse(trimmed));
        } catch {
          // Skip corrupted lines — never fail boot on bad data.
        }
      }
      this._seq = this.events.length;
    } catch (err) {
      console.warn(`[EventStore] Failed to load events: ${err.message}`);
    }
  }

  append(type, data = {}) {
    if (!EVENT_TYPES.includes(type)) {
      throw new Error(`Unknown event type: ${type}`);
    }
    const event = {
      id: `${Date.now().toString(36)}-${(++this._seq).toString(36)}`,
      ts: Date.now(),
      tenantId: this.tenantId,
      type,
      ...data,
    };
    this.events.push(event);
    // Append-only write; data loss on crash is bounded to the last line.
    appendFile(this.filePath, JSON.stringify(event) + '\n', 'utf-8').catch((err) => {
      console.error(`[EventStore] Append failed: ${err.message}`);
    });
    return event;
  }

  // ---- Query API ----

  query({ types, severity, attackType, since, until, limit = 100, offset = 0 } = {}) {
    const typeSet = types ? new Set(types) : null;
    const out = [];
    // Iterate newest-first; events are appended chronologically.
    for (let i = this.events.length - 1; i >= 0; i--) {
      const e = this.events[i];
      if (typeSet && !typeSet.has(e.type)) continue;
      if (severity && e.severity !== severity) continue;
      if (attackType && e.attackType !== attackType) continue;
      if (since && e.ts < since) continue;
      if (until && e.ts > until) continue;
      out.push(e);
      if (out.length >= offset + limit) break;
    }
    return out.slice(offset, offset + limit);
  }

  getEvent(id) {
    return this.events.find((e) => e.id === id) || null;
  }

  updateFindingStatus(findingId, status, note = '') {
    const finding = this.events.find((e) => e.id === findingId && e.type === 'finding');
    if (!finding) return null;
    finding.status = status;
    if (note) finding.statusNote = note;
    this.append('finding_updated', {
      findingId,
      status,
      title: finding.title,
      severity: finding.severity,
    });
    return finding;
  }

  // ---- Derived views ----

  getSummary({ now = Date.now() } = {}) {
    const dayMs = 24 * 60 * 60 * 1000;
    const openFindings = this.events.filter((e) => e.type === 'finding' && e.status !== 'fixed');
    const fixedFindings = this.events.filter((e) => e.type === 'finding' && e.status === 'fixed');
    const wafDecisions = this.events.filter((e) => e.type === 'waf_decision');
    const blocked24h = wafDecisions.filter((e) => e.action === 'block' && now - e.ts < dayMs);
    const attacks7d = wafDecisions.filter((e) => e.action !== 'allow' && now - e.ts < 7 * dayMs);
    const scans = this.events.filter((e) => e.type === 'scan_started');
    const lastScan = scans.length > 0 ? scans[scans.length - 1] : null;

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of openFindings) {
      if (bySeverity[f.severity] !== undefined) bySeverity[f.severity]++;
    }

    const postureScore = this._postureScore(openFindings, blocked24h.length, now);

    return {
      tenantId: this.tenantId,
      postureScore,
      postureLabel: this._postureLabel(postureScore),
      openFindings: openFindings.length,
      findingsBySeverity: bySeverity,
      fixedFindings: fixedFindings.length,
      attacksBlocked24h: blocked24h.length,
      attacks7d: attacks7d.length,
      totalDecisions: wafDecisions.length,
      totalScans: scans.length,
      lastScanAt: lastScan ? lastScan.ts : null,
      lastScanTarget: lastScan ? lastScan.target : null,
    };
  }

  _postureScore(openFindings, blocked24h, now) {
    let score = 100;
    for (const f of openFindings) {
      score -= SEVERITY_DEDUCTION[f.severity] || 0;
    }
    score -= Math.min(blocked24h * ATTACK_BLOCK_DEDUCTION, ATTACK_DEDUCTION_CAP);
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  _postureLabel(score) {
    if (score >= 90) return 'Good';
    if (score >= 70) return 'Needs attention';
    if (score >= 40) return 'At risk';
    return 'Critical';
  }

  // Daily-bucketed timeline for the posture chart.
  getTimeline({ days = 30, now = Date.now() } = {}) {
    const dayMs = 24 * 60 * 60 * 1000;
    const buckets = [];
    const byDay = new Map();
    for (let i = days - 1; i >= 0; i--) {
      const dayStart = Math.floor((now - i * dayMs) / dayMs) * dayMs;
      const key = new Date(dayStart).toISOString().slice(0, 10);
      const bucket = {
        date: key,
        ts: dayStart,
        attacksBlocked: 0,
        attacksTriaged: 0,
        findingsOpened: 0,
        findingsFixed: 0,
        scans: 0,
        postureScore: null,
      };
      buckets.push(bucket);
      byDay.set(key, bucket);
    }

    for (const e of this.events) {
      const key = new Date(e.ts).toISOString().slice(0, 10);
      const bucket = byDay.get(key);
      if (!bucket) continue;
      if (e.type === 'waf_decision') {
        if (e.action === 'block') bucket.attacksBlocked++;
        else if (e.action === 'triage') bucket.attacksTriaged++;
      } else if (e.type === 'finding') {
        bucket.findingsOpened++;
      } else if (e.type === 'finding_updated' && e.status === 'fixed') {
        bucket.findingsFixed++;
      } else if (e.type === 'scan_started') {
        bucket.scans++;
      }
    }

    // Rebuild posture score per day: open findings as of end-of-day + that day's blocks.
    const dayMs2 = 24 * 60 * 60 * 1000;
    for (const bucket of buckets) {
      const dayEnd = bucket.ts + dayMs2;
      const openAsOf = this.events.filter(
        (e) => e.type === 'finding' && e.ts <= dayEnd && (e.status !== 'fixed' || (e.statusUpdatedAt || 0) > dayEnd)
      );
      const blockedThatDay = bucket.attacksBlocked;
      bucket.postureScore = this._postureScore(openAsOf, blockedThatDay, dayEnd);
    }

    return buckets;
  }

  // ---- Monthly posture report (plain language, for an owner) ----

  getMonthlyReport({ month } = {}) {
    const now = new Date();
    const target = month ? new Date(`${month}-01T00:00:00Z`) : new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
    const monthStart = target.getTime();
    const monthEnd = new Date(Date.UTC(target.getUTCFullYear(), target.getUTCMonth() + 1, 1)).getTime();
    const monthLabel = target.toISOString().slice(0, 7);

    const inMonth = (e) => e.ts >= monthStart && e.ts < monthEnd;
    const findings = this.events.filter((e) => e.type === 'finding' && inMonth(e));
    const decisions = this.events.filter((e) => e.type === 'waf_decision' && inMonth(e));
    const scans = this.events.filter((e) => e.type === 'scan_started' && inMonth(e));
    const blocked = decisions.filter((e) => e.action === 'block');

    const byAttackType = {};
    for (const d of decisions) {
      if (d.action === 'allow') continue;
      const t = d.attackType || 'unknown';
      byAttackType[t] = (byAttackType[t] || 0) + 1;
    }
    const topAttackTypes = Object.entries(byAttackType)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([attackType, count]) => ({ attackType, count }));

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      if (bySeverity[f.severity] !== undefined) bySeverity[f.severity]++;
    }

    const summary = this.getSummary();
    const timeline = this.getTimeline({
      days: Math.ceil((monthEnd - monthStart) / (24 * 60 * 60 * 1000)),
      now: Math.min(Date.now(), monthEnd),
    });

    // Plain-language narrative — the owner should understand this without help.
    const narrative = [];
    narrative.push(
      scans.length > 0
        ? `Your site was tested by our security agents ${scans.length} time${scans.length === 1 ? '' : 's'} this month.`
        : `No security tests were run this month. Start a scan from the Agent view to check your site.`
    );
    narrative.push(
      blocked.length > 0
        ? `Your protection shield blocked ${blocked.length} attack${blocked.length === 1 ? '' : 's'} before they could reach your website.`
        : `No attacks were blocked this month — that is good news, but protection stays on around the clock.`
    );
    if (findings.length > 0) {
      narrative.push(
        `Testing found ${findings.length} issue${findings.length === 1 ? '' : 's'}: ${bySeverity.critical} critical, ${bySeverity.high} high, ${bySeverity.medium} medium, ${bySeverity.low} low. Each one comes with a plain-language fix.`
      );
    } else {
      narrative.push(`Testing found no new issues this month.`);
    }
    narrative.push(`Your current security posture score is ${summary.postureScore}/100 (${summary.postureLabel}).`);

    return {
      month: monthLabel,
      generatedAt: Date.now(),
      tenantId: this.tenantId,
      narrative,
      stats: {
        scans: scans.length,
        attacksBlocked: blocked.length,
        decisionsTotal: decisions.length,
        findingsOpened: findings.length,
        findingsBySeverity: bySeverity,
        topAttackTypes,
        postureScore: summary.postureScore,
        postureLabel: summary.postureLabel,
      },
      timeline,
      findings: findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        attackType: f.attackType,
        summary: f.summary,
        fix: f.fix,
        status: f.status,
      })),
    };
  }

  // ---- Compact for API responses ----

  static toListItem(e) {
    return {
      id: e.id,
      ts: e.ts,
      type: e.type,
      severity: e.severity,
      attackType: e.attackType,
      title: e.title,
      summary: e.summary,
      action: e.action,
      tier: e.tier,
      confidence: e.confidence,
      reasons: e.reasons,
      target: e.target,
      runId: e.runId,
      tool: e.tool,
      status: e.status,
      verified: e.verified,
      fix: e.fix,
      evidence: e.evidence,
      payloadSample: e.payloadSample,
      source: e.source,
    };
  }
}

export { SEVERITY_ORDER };
