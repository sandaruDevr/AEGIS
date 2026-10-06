// OneEye360 Dashboard — views over the event-store API
// Views: dashboard (posture timeline, stats), attack log, findings,
// monthly report, WAF lab. The agent chat lives in app.js.

// ---- Shared helpers ----

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = String(text ?? '');
  return div.innerHTML;
}

function timeAgo(ts) {
  if (!ts) return '';
  const diff = Date.now() - ts;
  if (diff < 60_000) return 'just now';
  const mins = Math.floor(diff / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(ts).toLocaleDateString();
}

function formatTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

const ATTACK_TYPE_LABELS = {
  sqli: 'SQL injection',
  xss: 'Cross-site scripting',
  path_traversal: 'Path traversal',
  command_injection: 'Command injection',
  ssrf: 'SSRF',
  xxe: 'XML external entity',
  template_injection: 'Template injection',
  rce: 'Remote code execution',
  file_inclusion: 'File inclusion',
  anomaly: 'Anomalous payload',
  misconfiguration: 'Misconfiguration',
  secrets_exposure: 'Secrets exposure',
  other: 'Other',
};

function attackTypeLabel(type) {
  return ATTACK_TYPE_LABELS[type] || type || 'Unknown';
}

async function api(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `${res.status} ${res.statusText}`);
  }
  return res.json();
}

// ---- Dashboard view ----

async function loadDashboard() {
  try {
    const [summary, attacks, findings] = await Promise.all([
      api('/api/dashboard/summary'),
      api('/api/attacks?action=block&limit=6'),
      api('/api/findings?limit=6'),
    ]);
    renderSummary(summary);
    renderMiniList('dash-recent-attacks', attacks.items, (a) => ({
      badge: a.action,
      title: a.title || `${attackTypeLabel(a.attackType)} on ${a.path || 'request'}`,
      time: a.ts,
    }));
    renderMiniList('dash-recent-findings', findings.items, (f) => ({
      badge: f.severity,
      title: f.title,
      time: f.ts,
    }));
    const timeline = await api('/api/dashboard/timeline?days=30');
    renderPostureChart(timeline.timeline);
  } catch (err) {
    console.warn('[Dashboard] load failed:', err.message);
  }
}

function renderSummary(s) {
  const set = (id, value) => {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
  };
  set('stat-posture-score', s.postureScore ?? '—');
  set('stat-posture-label', s.postureLabel ?? '');
  set('stat-blocked', s.attacksBlocked24h ?? 0);
  set('stat-findings', s.openFindings ?? 0);
  set('stat-scans', s.totalScans ?? 0);
  set('stat-last-scan', s.lastScanAt ? `last: ${timeAgo(s.lastScanAt)}` : 'no scans yet');

  const bySev = s.findingsBySeverity || {};
  set('stat-findings-breakdown',
    `${bySev.critical || 0} critical · ${bySev.high || 0} high · ${bySev.medium || 0} medium · ${bySev.low || 0} low`);

  const bar = document.getElementById('stat-posture-bar');
  if (bar) {
    bar.style.width = `${s.postureScore ?? 0}%`;
    bar.classList.remove('warn', 'bad');
    if (s.postureScore < 40) bar.classList.add('bad');
    else if (s.postureScore < 70) bar.classList.add('warn');
  }
}

function renderMiniList(containerId, items, map) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';
  if (!items || items.length === 0) {
    container.innerHTML = '<div class="mini-empty">Nothing recorded yet.</div>';
    return;
  }
  for (const item of items) {
    const { badge, title, time } = map(item);
    const row = el('div', 'mini-item');
    row.appendChild(severityBadge(badge));
    row.appendChild(el('div', 'mini-item-title', title));
    row.appendChild(el('div', 'mini-item-time', timeAgo(time)));
    container.appendChild(row);
  }
}

function severityBadge(value) {
  const known = ['critical', 'high', 'medium', 'low', 'info', 'block', 'triage', 'allow'];
  const v = String(value || 'info').toLowerCase();
  const cls = known.includes(v) ? v : 'info';
  const labelMap = { block: 'Blocked', triage: 'Review', allow: 'Allowed' };
  return el('span', `badge badge-${cls === 'block' ? 'blocked' : cls === 'triage' ? 'triage' : cls === 'allow' ? 'allowed' : cls}`,
    labelMap[v] || v.toUpperCase());
}

// SVG posture chart — posture score line + blocked-attack bars, no dependencies.
function renderPostureChart(timeline) {
  const container = document.getElementById('posture-chart');
  if (!container || !timeline || timeline.length === 0) return;

  const W = 800, H = 220;
  const PAD_L = 34, PAD_R = 10, PAD_T = 14, PAD_B = 24;
  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;

  const maxAttacks = Math.max(1, ...timeline.map((d) => d.attacksBlocked));
  const x = (i) => PAD_L + (i / Math.max(timeline.length - 1, 1)) * innerW;
  const yScore = (v) => PAD_T + (1 - v / 100) * innerH;
  const yAttacks = (v) => PAD_T + (1 - v / maxAttacks) * innerH;

  let svg = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Posture timeline">`;

  // Gridlines at 0/50/100
  for (const g of [0, 50, 100]) {
    svg += `<line x1="${PAD_L}" y1="${yScore(g)}" x2="${W - PAD_R}" y2="${yScore(g)}" stroke="rgba(139,145,158,0.12)" stroke-width="1" />`;
    svg += `<text x="${PAD_L - 6}" y="${yScore(g) + 3}" fill="#5c6270" font-size="9" text-anchor="end" font-family="monospace">${g}</text>`;
  }

  // Blocked-attack bars
  const barW = Math.max(innerW / timeline.length - 2, 2);
  timeline.forEach((d, i) => {
    if (d.attacksBlocked > 0) {
      svg += `<rect x="${x(i) - barW / 2}" y="${yAttacks(d.attacksBlocked)}" width="${barW}" height="${innerH + PAD_T - yAttacks(d.attacksBlocked)}" fill="rgba(240,85,106,0.25)" rx="2" />`;
    }
  });

  // Posture score area + line
  const points = timeline.map((d, i) => `${x(i)},${yScore(d.postureScore ?? 100)}`).join(' ');
  svg += `<polygon points="${PAD_L},${yScore(0)} ${points} ${W - PAD_R},${yScore(0)}" fill="rgba(91,124,250,0.10)" />`;
  svg += `<polyline points="${points}" fill="none" stroke="#5b7cfa" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />`;

  // X labels (weekly ticks)
  timeline.forEach((d, i) => {
    if (i % 7 === 0 || i === timeline.length - 1) {
      svg += `<text x="${x(i)}" y="${H - 6}" fill="#5c6270" font-size="9" text-anchor="middle" font-family="monospace">${d.date.slice(5)}</text>`;
    }
  });

  svg += '</svg>';
  container.innerHTML = svg;
}

// ---- Attack Log view ----

async function loadAttacks() {
  const action = document.getElementById('filter-attack-action')?.value || '';
  const attackType = document.getElementById('filter-attack-type')?.value || '';
  const container = document.getElementById('attacks-table');
  if (!container) return;

  try {
    const params = new URLSearchParams({ limit: '200' });
    if (action) params.set('action', action);
    if (attackType) params.set('attackType', attackType);
    const data = await api(`/api/attacks?${params}`);
    renderAttackTable(container, data.items);
  } catch (err) {
    container.innerHTML = `<div class="attack-empty">Failed to load attack log: ${escapeHtml(err.message)}</div>`;
  }
}

function renderAttackTable(container, items) {
  if (!items || items.length === 0) {
    container.innerHTML = '<div class="attack-empty">No attacks recorded yet. Run the simulation from the Dashboard or WAF Lab to see the shield in action.</div>';
    return;
  }
  const rows = items.map((a) => {
    const conf = a.confidence !== undefined ? `${Math.round(a.confidence * 100)}%` : '—';
    return `<tr>
      <td class="at-time">${formatTime(a.ts)}</td>
      <td>${severityBadge(a.action)}</td>
      <td>${escapeHtml(attackTypeLabel(a.attackType))}</td>
      <td>${a.severity ? severityBadge(a.severity) : '—'}</td>
      <td class="at-payload" title="${escapeHtml(a.payloadSample || '')}">${escapeHtml(a.payloadSample || '—')}</td>
      <td class="at-payload">${escapeHtml(a.path || '—')}</td>
      <td class="at-conf">${conf}</td>
      <td class="at-conf">${a.latencyMs != null ? `${a.latencyMs}ms` : '—'}</td>
    </tr>`;
  }).join('');
  container.innerHTML = `<table>
    <thead><tr><th>Time</th><th>Action</th><th>Attack type</th><th>Severity</th><th>Payload</th><th>Path</th><th>Confidence</th><th>Latency</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

// ---- Findings view ----

async function loadFindings() {
  const severity = document.getElementById('filter-finding-severity')?.value || '';
  const status = document.getElementById('filter-finding-status')?.value || '';
  const container = document.getElementById('findings-list');
  if (!container) return;

  try {
    const params = new URLSearchParams({ limit: '200' });
    if (severity) params.set('severity', severity);
    if (status) params.set('status', status);
    const data = await api(`/api/findings?${params}`);
    renderFindings(container, data.items);
  } catch (err) {
    container.innerHTML = `<div class="mini-empty">Failed to load findings: ${escapeHtml(err.message)}</div>`;
  }
}

function renderFindings(container, items) {
  container.innerHTML = '';
  if (!items || items.length === 0) {
    container.innerHTML = '<div class="mini-empty">No findings match. Run a security scan from the Agent view.</div>';
    return;
  }
  for (const f of items) {
    const card = el('div', `finding-card sev-${f.severity || 'info'}`);

    const header = el('div', 'finding-header');
    header.appendChild(severityBadge(f.severity));
    if (f.verified) header.appendChild(el('span', 'badge badge-verified', 'Verified'));
    header.appendChild(el('div', 'finding-title', f.title));
    header.appendChild(el('div', 'finding-meta', `${f.target || ''} · ${formatTime(f.ts)}`));
    card.appendChild(header);

    if (f.summary) card.appendChild(el('div', 'finding-summary', f.summary));

    if (f.fix) {
      const fix = el('div', 'finding-fix');
      fix.innerHTML = `<strong>How to fix:</strong> ${escapeHtml(f.fix)}`;
      card.appendChild(fix);
    }

    if (f.evidence) {
      const details = el('details', 'finding-evidence-details');
      const summaryEl = el('summary', '', 'Technical evidence');
      summaryEl.style.cssText = 'cursor:pointer;font-size:12px;color:var(--text-3);margin-bottom:6px;';
      details.appendChild(summaryEl);
      details.appendChild(el('div', 'finding-evidence', f.evidence));
      card.appendChild(details);
    }

    const footer = el('div', 'finding-footer');
    const currentStatus = f.status || 'open';
    for (const s of ['open', 'acknowledged', 'fixed']) {
      const btn = el('button', `finding-status-btn${currentStatus === s ? ' active' : ''}`,
        s === 'open' ? 'Open' : s === 'acknowledged' ? 'Acknowledged' : 'Fixed');
      btn.addEventListener('click', async () => {
        try {
          await api(`/api/findings/${f.id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: s }),
          });
          showToastSafe(`Finding marked ${s}`, 'success');
          loadFindings();
        } catch (err) {
          showToastSafe(err.message, 'error');
        }
      });
      footer.appendChild(btn);
    }
    if (f.attackType) {
      footer.appendChild(el('div', 'finding-meta', attackTypeLabel(f.attackType)));
    }
    card.appendChild(footer);

    container.appendChild(card);
  }
}

// ---- Reports view ----

let lastReport = null;

async function generateReport() {
  const output = document.getElementById('report-output');
  const month = document.getElementById('report-month')?.value || '';
  try {
    lastReport = await api(`/api/report/monthly${month ? `?month=${month}` : ''}`);
    renderReport(output, lastReport);
    document.getElementById('btn-print-report')?.classList.remove('hidden');
    document.getElementById('btn-download-report')?.classList.remove('hidden');
  } catch (err) {
    output.innerHTML = `<div class="mini-empty">Failed to generate report: ${escapeHtml(err.message)}</div>`;
  }
}

function renderReport(container, report) {
  const stats = report.stats || {};
  container.innerHTML = `
    <div class="report-title">Security Posture Report — ${escapeHtml(report.month)}</div>
    <div class="report-narrative">
      ${(report.narrative || []).map((n) => `<p>${escapeHtml(n)}</p>`).join('')}
    </div>
    <div class="report-stats">
      <div class="report-stat"><div class="report-stat-value">${stats.postureScore ?? '—'}</div><div class="report-stat-label">Posture score / 100 (${escapeHtml(stats.postureLabel || '')})</div></div>
      <div class="report-stat"><div class="report-stat-value">${stats.attacksBlocked ?? 0}</div><div class="report-stat-label">Attacks blocked</div></div>
      <div class="report-stat"><div class="report-stat-value">${stats.findingsOpened ?? 0}</div><div class="report-stat-label">Issues found</div></div>
      <div class="report-stat"><div class="report-stat-value">${stats.scans ?? 0}</div><div class="report-stat-label">Security scans</div></div>
    </div>
    <div class="report-findings">
      <h4>Issues found this month</h4>
      ${(report.findings || []).length === 0
        ? '<div class="mini-empty">No issues were found this month.</div>'
        : (report.findings || []).map((f) => `
          <div class="mini-item">
            ${severityBadge(f.severity)}
            <div class="mini-item-title" title="${escapeHtml(f.summary || '')}">${escapeHtml(f.title)}</div>
            <span class="badge badge-status-${escapeHtml(f.status || 'open')}">${escapeHtml(f.status || 'open')}</span>
          </div>`).join('')}
    </div>
    <div class="report-findings">
      <h4>Most common attack types</h4>
      ${(stats.topAttackTypes || []).length === 0
        ? '<div class="mini-empty">No attacks were detected this month.</div>'
        : (stats.topAttackTypes || []).map((t) => `
          <div class="mini-item">
            <div class="mini-item-title">${escapeHtml(attackTypeLabel(t.attackType))}</div>
            <div class="mini-item-time">${t.count} attempt${t.count === 1 ? '' : 's'}</div>
          </div>`).join('')}
    </div>`;
}

function downloadReport() {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `oneeye360-posture-report-${lastReport.month}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ---- WAF Lab view ----

async function loadWafRules() {
  try {
    const data = await api('/api/waf/rules');
    const statsEl = document.getElementById('waf-stats');
    if (statsEl && data.stats) {
      statsEl.textContent = `${data.stats.total} decisions · ${data.stats.blocked} blocked · ${data.customRules} custom rules`;
    }
    const list = document.getElementById('waf-rules-list');
    if (!list) return;
    list.innerHTML = '';
    if (!data.rules || data.rules.length === 0) {
      list.innerHTML = '<div class="mini-empty">No custom rules yet. Verified agent findings add rules here automatically.</div>';
      return;
    }
    for (const rule of data.rules) {
      const item = el('div', 'rule-item');
      item.appendChild(severityBadge(rule.severity));
      item.appendChild(el('div', 'rule-pattern', rule.pattern));
      item.appendChild(el('span', 'rule-source', rule.source));
      const del = el('button', 'rule-delete');
      del.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
      del.title = 'Delete rule';
      del.addEventListener('click', async () => {
        try {
          await api(`/api/waf/rules/${rule.id}`, { method: 'DELETE' });
          loadWafRules();
        } catch (err) {
          showToastSafe(err.message, 'error');
        }
      });
      item.appendChild(del);
      list.appendChild(item);
    }
  } catch (err) {
    console.warn('[WAF Lab] rules load failed:', err.message);
  }
}

async function evaluatePayload() {
  const payload = document.getElementById('waf-payload')?.value.trim();
  const box = document.getElementById('waf-decision');
  if (!payload || !box) return;
  try {
    const d = await api('/api/waf/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload }),
    });
    renderDecision(box, d);
  } catch (err) {
    box.classList.remove('hidden');
    box.className = 'waf-decision';
    box.innerHTML = `<div class="waf-decision-verdict">Error</div><div class="waf-reasons">${escapeHtml(err.message)}</div>`;
  }
}

function renderDecision(box, d) {
  box.className = `waf-decision action-${d.action}`;
  box.classList.remove('hidden');
  const verdict = d.action === 'block' ? 'Blocked' : d.action === 'triage' ? 'Held for review' : 'Allowed';
  const conf = d.confidence != null ? Math.round(d.confidence * 100) : null;
  box.innerHTML = `
    <div class="waf-decision-top">
      <span class="waf-decision-verdict">${verdict}</span>
      ${d.attackType ? severityBadge(d.attackType === 'anomaly' ? 'medium' : 'high') : ''}
      <span class="badge badge-info">${escapeHtml(attackTypeLabel(d.attackType))}</span>
      ${d.tier ? `<span class="badge badge-info">Tier ${d.tier}</span>` : ''}
      <div class="waf-confidence"><div class="waf-confidence-fill" style="width:${conf ?? 0}%"></div></div>
      <span class="at-conf">${conf !== null ? `${conf}% confidence` : ''}</span>
    </div>
    <div class="waf-reasons">${(d.reasons || []).map(escapeHtml).join('<br>')}</div>`;
}

async function simulateAttacks(targetContainerId = 'waf-sim-results') {
  const container = document.getElementById(targetContainerId);
  if (!container) return;
  try {
    const data = await api('/api/waf/simulate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    container.classList.remove('hidden');
    container.innerHTML = '';
    for (const r of data.results) {
      const item = el('div', 'mini-item');
      item.appendChild(severityBadge(r.decision.action));
      item.appendChild(el('div', 'mini-item-title', `${r.label} — ${r.decision.action === 'block' ? 'blocked' : r.decision.action === 'triage' ? 'held for review' : 'allowed'}`));
      item.appendChild(el('div', 'mini-item-time', r.decision.latencyMs != null ? `${r.decision.latencyMs}ms` : ''));
      container.appendChild(item);
    }
    loadWafRules();
  } catch (err) {
    container.classList.remove('hidden');
    container.innerHTML = `<div class="mini-empty">Simulation failed: ${escapeHtml(err.message)}</div>`;
  }
}

async function addWafRule() {
  const pattern = document.getElementById('waf-rule-pattern')?.value.trim();
  const attackType = document.getElementById('waf-rule-type')?.value.trim() || 'other';
  if (!pattern) {
    showToastSafe('Pattern is required', 'error');
    return;
  }
  try {
    await api('/api/waf/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pattern, attackType, severity: 'high', source: 'manual' }),
    });
    const p = document.getElementById('waf-rule-pattern');
    if (p) p.value = '';
    showToastSafe('Rule added', 'success');
    loadWafRules();
  } catch (err) {
    showToastSafe(err.message, 'error');
  }
}

function showToastSafe(message, type) {
  if (typeof window.showToast === 'function') {
    window.showToast(message, type);
  } else {
    console.log(`[${type}] ${message}`);
  }
}

// ---- Wire up ----

document.getElementById('btn-refresh-attacks')?.addEventListener('click', loadAttacks);
document.getElementById('filter-attack-action')?.addEventListener('change', loadAttacks);
document.getElementById('filter-attack-type')?.addEventListener('change', loadAttacks);

document.getElementById('btn-refresh-findings')?.addEventListener('click', loadFindings);
document.getElementById('filter-finding-severity')?.addEventListener('change', loadFindings);
document.getElementById('filter-finding-status')?.addEventListener('change', loadFindings);

document.getElementById('btn-generate-report')?.addEventListener('click', generateReport);
document.getElementById('btn-print-report')?.addEventListener('click', () => window.print());
document.getElementById('btn-download-report')?.addEventListener('click', downloadReport);

document.getElementById('btn-waf-evaluate')?.addEventListener('click', evaluatePayload);
document.getElementById('btn-waf-simulate')?.addEventListener('click', () => simulateAttacks('waf-sim-results'));
document.getElementById('btn-waf-add-rule')?.addEventListener('click', addWafRule);

document.getElementById('btn-goto-agent')?.addEventListener('click', () => window.navigateTo?.('agent'));
document.getElementById('btn-goto-report')?.addEventListener('click', () => window.navigateTo?.('reports'));
document.getElementById('btn-simulate')?.addEventListener('click', () => {
  simulateAttacks('simulate-result');
});

// Default the report month to the current month.
const monthInput = document.getElementById('report-month');
if (monthInput) {
  const now = new Date();
  monthInput.value = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

// ---- View lifecycle (called by the router in app.js) ----

window.onViewChanged = (view) => {
  if (view === 'dashboard') loadDashboard();
  else if (view === 'attacks') loadAttacks();
  else if (view === 'findings') loadFindings();
  else if (view === 'waf') loadWafRules();
  else if (view === 'reports') { /* report renders on demand */ }
};

// Initial load for the default view.
window.onViewChanged('dashboard');
