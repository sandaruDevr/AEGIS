// AEGIS Control Center — overview views
// Dashboard (posture + live scan strip), Websites (assets), Vulnerabilities
// register, Mitigation plans, Reports, WAF Lab. Scan orchestration UI lives
// in scan-center.js.

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

const SLA_DAYS = { critical: 7, high: 30, medium: 90, low: 180, info: 365 };

async function api(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `${res.status} ${res.statusText}`);
  }
  return res.json();
}

// ---- Assets cache (shared with scan-center launcher) ----

let assetsCache = [];

window.getAssets = async () => {
  try {
    const data = await api('/api/assets');
    assetsCache = data.assets || [];
  } catch (err) {
    console.warn('[Assets] load failed:', err.message);
    assetsCache = [];
  }
  return assetsCache;
};

// ============================================================
// Dashboard
// ============================================================

async function loadDashboard() {
  try {
    const [summary, findings] = await Promise.all([
      api('/api/dashboard/summary'),
      api('/api/findings?limit=6'),
    ]);
    renderSummary(summary);
    renderMiniList('dash-recent-findings', findings.items, (f) => ({
      badge: f.severity,
      title: f.title,
      time: f.ts,
    }));
    const [timeline, scans] = await Promise.all([
      api('/api/dashboard/timeline?days=30'),
      api('/api/scans'),
    ]);
    renderPostureChart(timeline.timeline);
    renderRecentScans(scans.jobs || []);
    // Live active scan (if any)
    window.onDashboardActiveScan?.(scans.active);
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

  // Asset coverage (composed server-side into summary when assets exist)
  const assets = s.assets || { total: 0, protected: 0 };
  set('stat-assets', assets.total);
  set('stat-assets-sub', assets.protected > 0
    ? `${assets.protected} scanned at least once`
    : 'add a website to begin');
}

function renderRecentScans(jobs) {
  const container = document.getElementById('dash-recent-scans');
  if (!container) return;
  container.innerHTML = '';
  if (!jobs || jobs.length === 0) {
    container.innerHTML = '<div class="mini-empty">No scans yet — start one from the Scan Center.</div>';
    return;
  }
  for (const job of jobs.slice(0, 6)) {
    const row = el('div', 'mini-item');
    row.appendChild(statusBadge(job.status));
    row.appendChild(el('div', 'mini-item-title', `${job.assetName} · ${job.typeLabel} (${job.profileLabel})`));
    row.appendChild(el('div', 'mini-item-time', timeAgo(job.createdAt)));
    container.appendChild(row);
  }
}

function statusBadge(status) {
  const map = {
    queued: ['badge-info', 'Queued'],
    running: ['badge-triage', 'Running'],
    completed: ['badge-blocked', 'Completed'],
    failed: ['badge-status-open', 'Failed'],
    stopped: ['badge-allowed', 'Stopped'],
    open: ['badge-status-open', 'Open'],
    acknowledged: ['badge-status-acknowledged', 'Acknowledged'],
    fixed: ['badge-status-fixed', 'Fixed'],
  };
  const [cls, label] = map[status] || ['badge-info', status];
  return el('span', `badge ${cls}`, label);
}

function severityBadge(value) {
  const known = ['critical', 'high', 'medium', 'low', 'info', 'block', 'triage', 'allow'];
  const v = String(value || 'info').toLowerCase();
  const cls = known.includes(v) ? v : 'info';
  const labelMap = { block: 'Blocked', triage: 'Review', allow: 'Allowed' };
  return el('span', `badge badge-${cls === 'block' ? 'blocked' : cls === 'triage' ? 'triage' : cls === 'allow' ? 'allowed' : cls}`,
    labelMap[v] || v.toUpperCase());
}

// Live active-scan strip on the dashboard.
window.onDashboardActiveScan = (job) => {
  const strip = document.getElementById('dash-active-scan');
  if (!strip) return;
  if (!job || (job.status !== 'running' && job.status !== 'queued')) {
    strip.classList.add('hidden');
    return;
  }
  strip.classList.remove('hidden');
  document.getElementById('dash-active-title').textContent =
    `${job.typeLabel} in progress — ${job.assetName}`;
  document.getElementById('dash-active-message').textContent = job.currentMessage || 'Working…';
  document.getElementById('dash-active-bar').style.width = `${job.progress || 0}%`;
  document.getElementById('dash-active-pct').textContent = `${job.progress || 0}%`;
};

// Scan jobs push (from scan-center) — refresh the recent-scans list live.
window.onScanJobsChanged = (jobs) => {
  const container = document.getElementById('dash-recent-scans');
  if (container && document.getElementById('view-dashboard')?.classList.contains('hidden') === false) {
    renderRecentScans(jobs || []);
  }
};

// SVG posture chart — posture score line + blocked-attack bars.
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

  for (const g of [0, 50, 100]) {
    svg += `<line x1="${PAD_L}" y1="${yScore(g)}" x2="${W - PAD_R}" y2="${yScore(g)}" stroke="rgba(139,145,158,0.12)" stroke-width="1" />`;
    svg += `<text x="${PAD_L - 6}" y="${yScore(g) + 3}" fill="#5c6270" font-size="9" text-anchor="end" font-family="monospace">${g}</text>`;
  }

  const barW = Math.max(innerW / timeline.length - 2, 2);
  timeline.forEach((d, i) => {
    if (d.attacksBlocked > 0) {
      svg += `<rect x="${x(i) - barW / 2}" y="${yAttacks(d.attacksBlocked)}" width="${barW}" height="${innerH + PAD_T - yAttacks(d.attacksBlocked)}" fill="rgba(240,85,106,0.25)" rx="2" />`;
    }
  });

  const points = timeline.map((d, i) => `${x(i)},${yScore(d.postureScore ?? 100)}`).join(' ');
  svg += `<polygon points="${PAD_L},${yScore(0)} ${points} ${W - PAD_R},${yScore(0)}" fill="rgba(91,124,250,0.10)" />`;
  svg += `<polyline points="${points}" fill="none" stroke="#5b7cfa" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />`;

  timeline.forEach((d, i) => {
    if (i % 7 === 0 || i === timeline.length - 1) {
      svg += `<text x="${x(i)}" y="${H - 6}" fill="#5c6270" font-size="9" text-anchor="middle" font-family="monospace">${d.date.slice(5)}</text>`;
    }
  });

  svg += '</svg>';
  container.innerHTML = svg;
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

// ============================================================
// Websites (assets)
// ============================================================

async function loadAssets() {
  await window.getAssets();
  renderAssetsGrid();
}

function postureRing(score) {
  if (score === null || score === undefined) {
    return `<svg class="posture-ring" viewBox="0 0 44 44"><circle cx="22" cy="22" r="18" fill="none" stroke="var(--bg-3)" stroke-width="4" /><text x="22" y="26" text-anchor="middle" font-size="11" fill="var(--text-3)" font-family="monospace">?</text></svg>`;
  }
  const dash = (score / 100) * (2 * Math.PI * 18);
  const color = score >= 90 ? 'var(--success)' : score >= 70 ? 'var(--warning)' : 'var(--error)';
  return `<svg class="posture-ring" viewBox="0 0 44 44">
    <circle cx="22" cy="22" r="18" fill="none" stroke="var(--bg-3)" stroke-width="4" />
    <circle cx="22" cy="22" r="18" fill="none" stroke="${color}" stroke-width="4" stroke-linecap="round"
      stroke-dasharray="${dash} ${2 * Math.PI * 18}" transform="rotate(-90 22 22)" />
    <text x="22" y="26" text-anchor="middle" font-size="11" fill="var(--text-0)" font-family="monospace">${score}</text>
  </svg>`;
}

function renderAssetsGrid() {
  const grid = document.getElementById('assets-grid');
  if (!grid) return;
  grid.innerHTML = '';
  if (assetsCache.length === 0) {
    grid.innerHTML = `<div class="assets-empty">
      <div class="assets-empty-icon">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10" /><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /></svg>
      </div>
      <h3>No websites yet</h3>
      <p>Add your first website above. AEGIS will watch it, test it and report in plain language.</p>
    </div>`;
    return;
  }

  for (const asset of assetsCache) {
    const card = el('div', 'asset-card');
    const p = asset.posture || {};

    const head = el('div', 'asset-head');
    head.innerHTML = postureRing(p.postureScore);
    const info = el('div', 'asset-info');
    info.appendChild(el('div', 'asset-name', asset.name));
    info.appendChild(el('div', 'asset-url', asset.url));
    card.appendChild(head);
    card.appendChild(info);

    const stats = el('div', 'asset-stats');
    stats.appendChild(el('div', 'asset-stat',
      p.openFindings > 0 ? `${p.openFindings} open issue${p.openFindings === 1 ? '' : 's'}` : 'No open issues'));
    stats.appendChild(el('div', 'asset-stat', p.lastScanAt ? `Last scan ${timeAgo(p.lastScanAt)}` : 'Never scanned'));
    if (asset.credentials?.has) {
      const badge = el('div', 'asset-stat cred-badge', 'Test access saved');
      stats.appendChild(badge);
    }
    card.appendChild(stats);

    const actions = el('div', 'asset-actions');
    const mkBtn = (label, cls, fn) => {
      const b = el('button', cls, label);
      b.addEventListener('click', fn);
      return b;
    };
    actions.appendChild(mkBtn('Quick scan', 'btn-primary btn-sm', () => startAssetScan(asset, 'assessment', 'quick')));
    actions.appendChild(mkBtn('Full scan', 'btn-secondary btn-sm', () => startAssetScan(asset, 'assessment', 'full')));
    actions.appendChild(mkBtn('Pen test', 'btn-secondary btn-sm', () => startAssetScan(asset, 'pentest', 'full')));
    actions.appendChild(mkBtn('Custom', 'btn-secondary btn-sm', () => { window.navigateTo?.('scans'); }));
    actions.appendChild(mkBtn('Issues', 'btn-secondary btn-sm', () => {
      const filter = document.getElementById('filter-finding-asset');
      if (filter) filter.value = asset.id;
      window.navigateTo?.('vulnerabilities');
      loadFindings();
    }));
    actions.appendChild(mkBtn('Test access', 'btn-secondary btn-sm', () => openCredModal(asset)));
    const removeBtn = mkBtn('', 'icon-btn asset-remove', async () => {
      if (!confirm(`Remove ${asset.name} from protection? Its history stays in reports.`)) return;
      try {
        await api(`/api/assets/${asset.id}`, { method: 'DELETE' });
        window.showToast?.('Website removed', 'success');
        loadAssets();
      } catch (err) {
        window.showToast?.(err.message, 'error');
      }
    });
    removeBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
    actions.appendChild(removeBtn);
    card.appendChild(actions);

    grid.appendChild(card);
  }
}

async function startAssetScan(asset, type, profile) {
  try {
    const data = await api('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assetId: asset.id, type, profile }),
    });
    window.showToast?.(`${profile === 'quick' ? 'Quick scan' : 'Scan'} started for ${asset.name}`, 'success');
    window.handleScanEvent?.({ type: 'SCAN_JOB', job: data.job });
    window.navigateTo?.('scans');
  } catch (err) {
    window.showToast?.(err.message, 'error');
  }
}

// ---- Test credentials (authenticated scanning) ----

let credAssetId = null;

async function openCredModal(asset) {
  credAssetId = asset.id;
  const modal = document.getElementById('cred-modal');
  if (!modal) return;
  modal.classList.remove('hidden');
  document.getElementById('cred-label').value = '';
  document.getElementById('cred-username').value = '';
  document.getElementById('cred-password').value = '';
  document.getElementById('cred-login-url').value = '';
  const statusEl = document.getElementById('cred-status');
  const removeBtn = document.getElementById('btn-remove-cred');
  try {
    const status = await api(`/api/assets/${asset.id}/credentials`);
    if (status.has) {
      statusEl.textContent = `Saved: ${status.label} (${status.username}) — encrypted, never shown again`;
      statusEl.classList.add('has');
      removeBtn.classList.remove('hidden');
      document.getElementById('cred-label').value = status.label || '';
      document.getElementById('cred-username').value = status.username || '';
      document.getElementById('cred-login-url').value = status.loginUrl || '';
    } else {
      statusEl.textContent = 'No test credentials saved yet — scans will run as a visitor.';
      statusEl.classList.remove('has');
      removeBtn.classList.add('hidden');
    }
  } catch {
    statusEl.textContent = '';
  }
}

function closeCredModal() {
  credAssetId = null;
  document.getElementById('cred-modal')?.classList.add('hidden');
}

document.getElementById('btn-close-cred')?.addEventListener('click', closeCredModal);
document.getElementById('cred-modal')?.addEventListener('click', (e) => {
  if (e.target === e.currentTarget) closeCredModal();
});

document.getElementById('btn-save-cred')?.addEventListener('click', async () => {
  if (!credAssetId) return;
  const body = {
    label: document.getElementById('cred-label').value.trim() || undefined,
    username: document.getElementById('cred-username').value.trim(),
    password: document.getElementById('cred-password').value,
    loginUrl: document.getElementById('cred-login-url').value.trim() || undefined,
  };
  try {
    await api(`/api/assets/${credAssetId}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    window.showToast?.('Test credentials saved — encrypted', 'success');
    closeCredModal();
    loadAssets();
  } catch (err) {
    window.showToast?.(err.message, 'error');
  }
});

document.getElementById('btn-remove-cred')?.addEventListener('click', async () => {
  if (!credAssetId) return;
  if (!confirm('Remove the saved test credentials? Scans will run as a visitor.')) return;
  try {
    await api(`/api/assets/${credAssetId}/credentials`, { method: 'DELETE' });
    window.showToast?.('Test credentials removed', 'success');
    closeCredModal();
    loadAssets();
  } catch (err) {
    window.showToast?.(err.message, 'error');
  }
});

document.getElementById('btn-add-asset')?.addEventListener('click', async () => {
  const nameEl = document.getElementById('asset-name');
  const urlEl = document.getElementById('asset-url');
  const url = urlEl?.value.trim();
  if (!url) {
    window.showToast?.('Enter a website URL', 'error');
    return;
  }
  try {
    await api('/api/assets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, name: nameEl?.value.trim() || undefined }),
    });
    if (urlEl) urlEl.value = '';
    if (nameEl) nameEl.value = '';
    window.showToast?.('Website added', 'success');
    loadAssets();
  } catch (err) {
    window.showToast?.(err.message, 'error');
  }
});

// ============================================================
// Vulnerabilities register
// ============================================================

async function loadFindings() {
  const severity = document.getElementById('filter-finding-severity')?.value || '';
  const status = document.getElementById('filter-finding-status')?.value || '';
  const assetId = document.getElementById('filter-finding-asset')?.value || '';
  const container = document.getElementById('findings-list');
  if (!container) return;

  try {
    const params = new URLSearchParams({ limit: '200' });
    if (severity) params.set('severity', severity);
    if (status) params.set('status', status);
    const data = await api(`/api/findings?${params}`);
    let items = data.items;
    if (assetId) items = items.filter((f) => f.assetId === assetId);
    renderFindings(container, items);
  } catch (err) {
    container.innerHTML = `<div class="mini-empty">Failed to load issues: ${escapeHtml(err.message)}</div>`;
  }
}

function slaBadge(finding) {
  const slaDays = SLA_DAYS[finding.severity] ?? 365;
  const due = (finding.ts || 0) + slaDays * 24 * 60 * 60 * 1000;
  const daysLeft = Math.ceil((due - Date.now()) / (24 * 60 * 60 * 1000));
  if ((finding.status || 'open') === 'fixed') return null;
  if (daysLeft < 0) return el('span', 'badge badge-status-open', `Overdue ${-daysLeft}d`);
  if (daysLeft <= 7) return el('span', 'badge badge-triage', `Due in ${daysLeft}d`);
  return el('span', 'badge badge-info', `Due in ${daysLeft}d`);
}

function renderFindings(container, items) {
  container.innerHTML = '';
  if (!items || items.length === 0) {
    container.innerHTML = '<div class="mini-empty">No issues match. Run a scan from the Scan Center.</div>';
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
          window.showToast?.(`Issue marked ${s}`, 'success');
          loadFindings();
        } catch (err) {
          window.showToast?.(err.message, 'error');
        }
      });
      footer.appendChild(btn);
    }
    const sla = slaBadge(f);
    if (sla) footer.appendChild(sla);
    if (f.attackType) footer.appendChild(el('div', 'finding-meta', attackTypeLabel(f.attackType)));
    card.appendChild(footer);

    container.appendChild(card);
  }
}

// ============================================================
// Mitigation plans
// ============================================================

async function loadMitigation() {
  const container = document.getElementById('mitigation-plans');
  if (!container) return;
  try {
    const data = await api('/api/mitigation-plans');
    renderMitigation(container, data.plans || []);
  } catch (err) {
    container.innerHTML = `<div class="mini-empty">Failed to load plans: ${escapeHtml(err.message)}</div>`;
  }
}

function renderMitigation(container, plans) {
  container.innerHTML = '';
  if (plans.length === 0) {
    container.innerHTML = `<div class="assets-empty">
      <div class="assets-empty-icon">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" /></svg>
      </div>
      <h3>No open mitigation work</h3>
      <p>When a scan confirms issues, a prioritized fix plan appears here — ordered by risk, in plain language.</p>
    </div>`;
    return;
  }

  for (const plan of plans) {
    const panel = el('div', 'panel plan-panel');

    const header = el('div', 'plan-header');
    const title = el('div', 'plan-title', plan.assetName);
    header.appendChild(title);
    header.appendChild(el('div', 'plan-progress-label', `${plan.fixed}/${plan.total} fixed`));
    panel.appendChild(header);

    const bar = el('div', 'plan-progress');
    const fill = el('div', 'plan-progress-fill');
    fill.style.width = `${plan.progress}%`;
    if (plan.progress < 40) fill.classList.add('bad');
    else if (plan.progress < 100) fill.classList.add('warn');
    bar.appendChild(fill);
    panel.appendChild(bar);

    for (const step of plan.steps) {
      const item = el('div', `plan-step sev-${step.severity}${step.status === 'fixed' ? ' done' : ''}`);
      const main = el('div', 'plan-step-main');
      const top = el('div', 'plan-step-top');
      top.appendChild(severityBadge(step.severity));
      top.appendChild(el('div', 'plan-step-title', step.title));
      if (step.status !== 'fixed') {
        const due = new Date(step.dueAt);
        const daysLeft = Math.ceil((step.dueAt - Date.now()) / (24 * 60 * 60 * 1000));
        top.appendChild(el('div', 'finding-meta', daysLeft < 0 ? `Overdue ${-daysLeft}d` : `Due ${due.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}`));
      }
      main.appendChild(top);
      if (step.summary) main.appendChild(el('div', 'plan-step-summary', step.summary));
      if (step.fix) main.appendChild(el('div', 'plan-step-fix', step.fix));
      item.appendChild(main);

      const action = el('div', 'plan-step-action');
      if (step.status === 'fixed') {
        action.appendChild(el('span', 'badge badge-status-fixed', 'Fixed'));
      } else {
        const btn = el('button', 'finding-status-btn', 'Mark fixed');
        btn.addEventListener('click', async () => {
          try {
            await api(`/api/findings/${step.findingId}`, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ status: 'fixed' }),
            });
            window.showToast?.('Marked as fixed — posture updated', 'success');
            loadMitigation();
          } catch (err) {
            window.showToast?.(err.message, 'error');
          }
        });
        action.appendChild(btn);
      }
      item.appendChild(action);
      panel.appendChild(item);
    }
    container.appendChild(panel);
  }
}

// ============================================================
// Reports (scan reports + monthly posture)
// ============================================================

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
            ${severityBadge(f.severity).outerHTML}
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
  a.download = `aegis-posture-report-${lastReport.month}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function loadScanReportsList() {
  const container = document.getElementById('scan-reports-list');
  if (!container) return;
  try {
    const data = await api('/api/scans');
    const completed = (data.jobs || []).filter((j) => j.status === 'completed');
    container.innerHTML = '';
    if (completed.length === 0) {
      container.innerHTML = '<div class="mini-empty">Complete a scan to generate its report.</div>';
      return;
    }
    for (const job of completed) {
      const row = el('div', 'mini-item');
      row.appendChild(severityBadge(job.findingsBySeverity?.critical > 0 ? 'critical' : job.findingsBySeverity?.high > 0 ? 'high' : 'info'));
      row.appendChild(el('div', 'mini-item-title', `${job.assetName} · ${job.typeLabel} (${job.profileLabel}) · ${timeAgo(job.completedAt)}`));
      const btn = el('button', 'finding-status-btn', 'Open report');
      btn.addEventListener('click', async () => {
        try {
          const report = await api(`/api/scans/${job.id}/report`);
          const output = document.getElementById('scan-report-output');
          window.renderScanReportInto?.(output, report);
          output?.classList.remove('hidden');
          output?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } catch (err) {
          window.showToast?.(err.message, 'error');
        }
      });
      row.appendChild(btn);
      container.appendChild(row);
    }
  } catch (err) {
    container.innerHTML = `<div class="mini-empty">Failed to load scan reports: ${escapeHtml(err.message)}</div>`;
  }
}

// ============================================================
// WAF Shield — monitor / setup / tracking / install
// ============================================================

let wafMonitorFilter = '';
let wafMonitorTimer = null;
let wafPlatform = 'express';
let wafCurrentInstall = null; // { token, assetId } for the selected asset

function verdictMeta(action) {
  if (action === 'block') return { label: 'Blocked', cls: 'block' };
  if (action === 'triage') return { label: 'Held for review', cls: 'triage' };
  return { label: 'Allowed', cls: 'allow' };
}

async function loadWafOverview() {
  try {
    const o = await api('/api/waf/overview');

    // Status strip
    const modeEl = document.getElementById('waf-mode-value');
    if (modeEl) {
      modeEl.textContent = o.config.mode === 'enforce' ? 'Enforce' : 'Monitor';
      modeEl.className = `waf-stat-value waf-mode-${o.config.mode}`;
    }
    const modeNote = document.getElementById('waf-mode-note');
    if (modeNote) {
      modeNote.textContent = o.config.mode === 'enforce'
        ? 'Attacks are blocked in real time'
        : 'Attacks are logged, nothing is blocked yet';
    }
    const blockedEl = document.getElementById('waf-stat-blocked');
    if (blockedEl) blockedEl.textContent = o.stats.blocked24h;
    const totalEl = document.getElementById('waf-stat-total');
    if (totalEl) totalEl.textContent = `${o.stats.total} decisions total`;
    const heldEl = document.getElementById('waf-stat-held');
    if (heldEl) heldEl.textContent = o.stats.held;

    const triageEl = document.getElementById('waf-triage-status');
    if (triageEl) {
      triageEl.textContent = o.triage.available ? 'Live' : 'Offline';
      triageEl.className = `waf-stat-value waf-triage-${o.triage.available ? 'live' : 'off'}`;
    }
    const triageModel = document.getElementById('waf-triage-model');
    if (triageModel) {
      triageModel.textContent = o.triage.available
        ? `${o.triage.model} via ${o.triage.provider}`
        : 'no decision-model key configured';
    }

    renderWafTimeline(o.timeline);
    renderWafTopAttacks(o.topAttacks);
    renderWafSetup(o);
    renderWafInstallStatus(o.installs || []);
  } catch (err) {
    console.warn('[WAF] overview load failed:', err.message);
  }
}

function renderWafTimeline(timeline) {
  const box = document.getElementById('waf-timeline');
  if (!box) return;
  const max = Math.max(1, ...timeline.map((t) => Math.max(t.blocked, t.triaged, t.allowed)));
  box.innerHTML = timeline.map((t) => {
    const h = new Date(t.ts).getHours();
    const bars = [
      { v: t.blocked, cls: 'bar-block' },
      { v: t.triaged, cls: 'bar-triage' },
      { v: t.allowed, cls: 'bar-allow' },
    ].filter((b) => b.v > 0)
      .map((b) => `<i class="waf-bar ${b.cls}" style="height:${Math.max(8, Math.round((b.v / max) * 100))}%"></i>`)
      .join('');
    return `<div class="waf-tl-col" title="${h}:00 — ${t.blocked} blocked, ${t.triaged} held, ${t.allowed} allowed">${bars}</div>`;
  }).join('');
}

function renderWafTopAttacks(top) {
  const box = document.getElementById('waf-top-attacks');
  if (!box) return;
  box.innerHTML = '';
  if (!top || top.length === 0) {
    box.innerHTML = '<div class="mini-empty">No attacks in the last 7 days.</div>';
    return;
  }
  const max = Math.max(...top.map((t) => t.count));
  for (const t of top) {
    const item = el('div', 'waf-top-item');
    item.innerHTML = `
      <div class="waf-top-row">
        <span class="waf-top-label">${escapeHtml(attackTypeLabel(t.attackType))}</span>
        <span class="waf-top-count">${t.count}</span>
      </div>
      <div class="waf-top-bar"><i style="width:${Math.round((t.count / max) * 100)}%"></i></div>`;
    box.appendChild(item);
  }
}

// ---- Live monitor ----

async function loadWafMonitor() {
  const box = document.getElementById('waf-monitor');
  if (!box) return;
  try {
    const params = new URLSearchParams({ limit: '60' });
    if (wafMonitorFilter) params.set('action', wafMonitorFilter);
    const data = await api(`/api/waf/decisions?${params}`);
    box.innerHTML = '';
    if (!data.items || data.items.length === 0) {
      box.innerHTML = '<div class="mini-empty">No traffic decisions yet. Install the shield on a website or test a payload below.</div>';
      return;
    }
    for (const d of data.items) {
      const v = verdictMeta(d.action);
      const conf = d.confidence != null ? Math.round(d.confidence * 100) : null;
      const row = el('div', `waf-monitor-row v-${v.cls}`);
      row.innerHTML = `
        <span class="waf-verdict-chip">${v.label}</span>
        <span class="waf-monitor-type">${escapeHtml(attackTypeLabel(d.attackType))}</span>
        <span class="waf-monitor-path" title="${escapeHtml(d.payloadSample || '')}">${escapeHtml(`${d.method || 'GET'} ${d.path || '/'}`)}</span>
        <span class="waf-monitor-conf"><i style="width:${conf ?? 0}%"></i></span>
        <span class="waf-monitor-time">${timeAgo(d.ts)}</span>`;
      box.appendChild(row);
    }
  } catch (err) {
    box.innerHTML = `<div class="mini-empty">Monitor unavailable: ${escapeHtml(err.message)}</div>`;
  }
}

function startWafMonitor() {
  loadWafMonitor();
  clearInterval(wafMonitorTimer);
  wafMonitorTimer = setInterval(loadWafMonitor, 5000);
}

function stopWafMonitor() {
  clearInterval(wafMonitorTimer);
  wafMonitorTimer = null;
}

// ---- Setup ----

function renderWafSetup(o) {
  const toggle = document.getElementById('waf-mode-toggle');
  if (toggle) {
    toggle.querySelectorAll('button').forEach((b) => b.classList.toggle('active', b.dataset.mode === o.config.mode));
  }
  const modeNote = document.getElementById('waf-mode-note');
  if (modeNote) {
    modeNote.textContent = o.config.mode === 'enforce'
      ? 'Enforce — attacks are blocked at the edge. Switch to Monitor first when tuning new rules.'
      : 'Monitor — every attack is logged as "would have blocked" so you can tune safely, then switch to Enforce.';
  }
  const t = document.getElementById('waf-th-triage');
  if (t) { t.value = o.config.thresholds.triage; document.getElementById('waf-th-triage-val').textContent = Number(o.config.thresholds.triage).toFixed(2); }
  const b = document.getElementById('waf-th-block');
  if (b) { b.value = o.config.thresholds.block; document.getElementById('waf-th-block-val').textContent = Number(o.config.thresholds.block).toFixed(2); }
  const tri = document.getElementById('waf-triage-toggle');
  if (tri) tri.checked = o.config.triage;
  const triNote = document.getElementById('waf-triage-note');
  if (triNote) {
    triNote.textContent = o.triage.available
      ? `Calibrated decisions via ${o.triage.model} (${o.triage.provider}).`
      : 'No decision-model key configured — escalated payloads stay held for human review.';
  }
}

async function saveWafConfig() {
  const mode = document.querySelector('#waf-mode-toggle button.active')?.dataset.mode || 'monitor';
  const thresholds = {
    triage: parseFloat(document.getElementById('waf-th-triage')?.value ?? 0.6),
    block: parseFloat(document.getElementById('waf-th-block')?.value ?? 0.85),
  };
  const triage = document.getElementById('waf-triage-toggle')?.checked ?? true;
  try {
    await api('/api/waf/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode, thresholds, triage }),
    });
    window.showToast?.(`WAF setup saved — ${mode} mode`, 'success');
    loadWafOverview();
  } catch (err) {
    window.showToast?.(err.message, 'error');
  }
}

// ---- Install ----

function renderWafInstallStatus(installs) {
  const box = document.getElementById('waf-install-status');
  if (!box) return;
  box.innerHTML = '';
  const assetId = document.getElementById('waf-install-asset')?.value;
  const mine = installs.filter((i) => !assetId || i.assetId === assetId);
  if (mine.length === 0) {
    box.innerHTML = '<div class="mini-empty">No install yet for this website. Generate one to get a token.</div>';
    return;
  }
  for (const i of mine) {
    const item = el('div', 'mini-item');
    item.innerHTML = `
      <div class="mini-item-title">${escapeHtml(i.assetName)}</div>
      <div class="mini-item-time">${i.requests} requests seen · last ${i.lastSeenAt ? timeAgo(i.lastSeenAt) : 'never'} · token ${escapeHtml(i.tokenMasked)}</div>`;
    box.appendChild(item);
  }
}

async function loadWafInstallAssets() {
  const select = document.getElementById('waf-install-asset');
  if (!select) return;
  try {
    const data = await api('/api/assets');
    const assets = data.assets || [];
    select.innerHTML = assets.length
      ? assets.map((a) => `<option value="${escapeHtml(a.id)}">${escapeHtml(a.name)}</option>`).join('')
      : '<option value="">Register a website first</option>';
    const o = await api('/api/waf/overview');
    renderWafInstallStatus(o.installs || []);
  } catch (err) {
    select.innerHTML = '<option value="">Failed to load websites</option>';
  }
}

async function generateWafInstall() {
  const assetId = document.getElementById('waf-install-asset')?.value;
  if (!assetId) {
    window.showToast?.('Register a website first', 'error');
    return;
  }
  try {
    const data = await api('/api/waf/installs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assetId }),
    });
    wafCurrentInstall = { token: data.install.token, assetId };
    await loadWafSnippet();
    window.showToast?.('Install token generated — paste the snippet into your site', 'success');
    loadWafOverview();
  } catch (err) {
    window.showToast?.(err.message, 'error');
  }
}

async function loadWafSnippet() {
  const assetId = document.getElementById('waf-install-asset')?.value;
  const steps = document.getElementById('waf-install-steps');
  const pre = document.getElementById('waf-install-snippet');
  if (!assetId || !pre) return;
  try {
    const data = await api(`/api/waf/install-snippet?assetId=${encodeURIComponent(assetId)}&platform=${encodeURIComponent(wafPlatform)}`);
    pre.querySelector('code').textContent = data.snippet;
    pre.classList.remove('hidden');
    if (steps) {
      steps.innerHTML = PLATFORM_STEPS[wafPlatform] || '';
    }
  } catch (err) {
    pre.classList.add('hidden');
    if (steps) steps.innerHTML = `<div class="mini-empty">${escapeHtml(err.message)}</div>`;
  }
}

const PLATFORM_STEPS = {
  express: '<div class="waf-step">1 · Generate an install token (one per website)</div><div class="waf-step">2 · Paste the middleware into your Express app, before your routes</div><div class="waf-step">3 · Restart your app — blocked requests get a 403, everything else passes</div>',
  nextjs: '<div class="waf-step">1 · Generate an install token (one per website)</div><div class="waf-step">2 · Save the snippet as middleware.js in your project root</div><div class="waf-step">3 · Redeploy — blocked requests get a 403 before reaching your app</div>',
  cloudflare: '<div class="waf-step">1 · Generate an install token (one per website)</div><div class="waf-step">2 · Create a Worker and paste the snippet</div><div class="waf-step">3 · Attach the Worker to your site\'s route — attacks are stopped at the edge</div>',
  nginx: '<div class="waf-step">1 · Generate an install token (one per website)</div><div class="waf-step">2 · Add the internal location block inside your server { } block</div><div class="waf-step">3 · Add auth_request to your app location, then nginx -t && nginx -s reload</div>',
};

async function revokeWafInstall() {
  const assetId = document.getElementById('waf-install-asset')?.value;
  if (!assetId) return;
  try {
    const data = await api('/api/waf/installs');
    const install = (data.installs || []).find((i) => i.assetId === assetId);
    if (!install) {
      window.showToast?.('No install token for this website', 'error');
      return;
    }
    await api(`/api/waf/installs/${encodeURIComponent(install.token)}`, { method: 'DELETE' });
    window.showToast?.('Install token revoked — the deployed adapter will stop being authorized', 'success');
    document.getElementById('waf-install-snippet').classList.add('hidden');
    loadWafOverview();
  } catch (err) {
    window.showToast?.(err.message, 'error');
  }
}

async function copyWafSnippet() {
  const code = document.querySelector('#waf-install-snippet code')?.textContent;
  if (!code) {
    window.showToast?.('Generate an install first', 'error');
    return;
  }
  try {
    await navigator.clipboard.writeText(code);
    window.showToast?.('Snippet copied', 'success');
  } catch {
    window.showToast?.('Copy failed — select the code manually', 'error');
  }
}

// ---- Rules ----

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
      list.innerHTML = '<div class="mini-empty">No custom rules yet — the signature library is always active.</div>';
      return;
    }
    for (const rule of data.rules) {
      const item = el('div', 'mini-item');
      const main = el('div', 'mini-item-main');
      main.appendChild(el('div', 'mini-item-title', rule.pattern));
      main.appendChild(el('div', 'mini-item-time', `${attackTypeLabel(rule.attackType)} · ${rule.severity} · added ${timeAgo(rule.createdAt)}`));
      item.appendChild(main);
      const del = el('button', 'mini-del', '×');
      del.title = 'Delete rule';
      del.addEventListener('click', async () => {
        try {
          await api(`/api/waf/rules/${rule.id}`, { method: 'DELETE' });
          loadWafRules();
        } catch (err) {
          window.showToast?.(err.message, 'error');
        }
      });
      item.appendChild(del);
      list.appendChild(item);
    }
  } catch (err) {
    console.warn('[WAF] rules load failed:', err.message);
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
  const severity = document.getElementById('waf-rule-severity')?.value || 'high';
  if (!pattern) {
    window.showToast?.('Pattern is required', 'error');
    return;
  }
  try {
    await api('/api/waf/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pattern, attackType, severity, source: 'manual' }),
    });
    const p = document.getElementById('waf-rule-pattern');
    if (p) p.value = '';
    window.showToast?.('Rule added', 'success');
    loadWafRules();
  } catch (err) {
    window.showToast?.(err.message, 'error');
  }
}

// ============================================================
// Wire up
// ============================================================

// Dashboard
document.getElementById('btn-goto-scans')?.addEventListener('click', () => window.navigateTo?.('scans'));
document.getElementById('btn-goto-websites')?.addEventListener('click', () => window.navigateTo?.('websites'));
document.getElementById('dash-active-goto')?.addEventListener('click', () => window.navigateTo?.('scans'));
document.getElementById('btn-simulate')?.addEventListener('click', () => simulateAttacks('simulate-result'));

// Websites
// (btn-add-asset handler registered in the Websites section above)

// Vulnerabilities
document.getElementById('btn-refresh-findings')?.addEventListener('click', loadFindings);
document.getElementById('filter-finding-severity')?.addEventListener('change', loadFindings);
document.getElementById('filter-finding-status')?.addEventListener('change', loadFindings);
document.getElementById('filter-finding-asset')?.addEventListener('change', loadFindings);

// Reports
document.getElementById('btn-generate-report')?.addEventListener('click', generateReport);
document.getElementById('btn-print-report')?.addEventListener('click', () => window.print());
document.getElementById('btn-download-report')?.addEventListener('click', downloadReport);

document.getElementById('tab-scan-reports')?.addEventListener('click', () => {
  document.getElementById('tab-scan-reports')?.classList.add('active');
  document.getElementById('tab-monthly')?.classList.remove('active');
  document.getElementById('reports-scan')?.classList.remove('hidden');
  document.getElementById('reports-monthly')?.classList.add('hidden');
  loadScanReportsList();
});
document.getElementById('tab-monthly')?.addEventListener('click', () => {
  document.getElementById('tab-monthly')?.classList.add('active');
  document.getElementById('tab-scan-reports')?.classList.remove('active');
  document.getElementById('reports-monthly')?.classList.remove('hidden');
  document.getElementById('reports-scan')?.classList.add('hidden');
});

// WAF Shield
document.getElementById('btn-waf-evaluate')?.addEventListener('click', evaluatePayload);
document.getElementById('btn-waf-simulate')?.addEventListener('click', () => simulateAttacks('waf-sim-results'));
document.getElementById('btn-waf-add-rule')?.addEventListener('click', addWafRule);
document.getElementById('btn-waf-save-config')?.addEventListener('click', saveWafConfig);
document.getElementById('btn-waf-create-install')?.addEventListener('click', generateWafInstall);
document.getElementById('btn-waf-copy-snippet')?.addEventListener('click', copyWafSnippet);
document.getElementById('btn-waf-revoke-install')?.addEventListener('click', revokeWafInstall);
document.getElementById('waf-install-asset')?.addEventListener('change', async () => {
  wafCurrentInstall = null;
  document.getElementById('waf-install-snippet')?.classList.add('hidden');
  await loadWafSnippet();
  const o = await api('/api/waf/overview').catch(() => null);
  if (o) renderWafInstallStatus(o.installs || []);
});
document.querySelectorAll('#waf-filter-chips .waf-chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    document.querySelectorAll('#waf-filter-chips .waf-chip').forEach((c) => c.classList.toggle('active', c === chip));
    wafMonitorFilter = chip.dataset.filter || '';
    loadWafMonitor();
  });
});
document.querySelectorAll('#waf-platform-tabs .waf-chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    document.querySelectorAll('#waf-platform-tabs .waf-chip').forEach((c) => c.classList.toggle('active', c === chip));
    wafPlatform = chip.dataset.platform || 'express';
    loadWafSnippet();
  });
});
document.querySelectorAll('#waf-mode-toggle button').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#waf-mode-toggle button').forEach((b) => b.classList.toggle('active', b === btn));
    const modeNote = document.getElementById('waf-mode-note');
    if (modeNote) {
      modeNote.textContent = btn.dataset.mode === 'enforce'
        ? 'Enforce — attacks are blocked at the edge. Switch to Monitor first when tuning new rules.'
        : 'Monitor — every attack is logged as "would have blocked" so you can tune safely, then switch to Enforce.';
    }
  });
});
for (const [sliderId, valId] of [['waf-th-triage', 'waf-th-triage-val'], ['waf-th-block', 'waf-th-block-val']]) {
  const slider = document.getElementById(sliderId);
  slider?.addEventListener('input', () => {
    const val = document.getElementById(valId);
    if (val) val.textContent = Number(slider.value).toFixed(2);
  });
}

// Attack log
document.getElementById('btn-refresh-attacks')?.addEventListener('click', loadAttacks);
document.getElementById('filter-attack-action')?.addEventListener('change', loadAttacks);
document.getElementById('filter-attack-type')?.addEventListener('change', loadAttacks);

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
      <td>${severityBadge(a.action).outerHTML}</td>
      <td>${escapeHtml(attackTypeLabel(a.attackType))}</td>
      <td>${a.severity ? severityBadge(a.severity).outerHTML : '—'}</td>
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

// Default the report month to the current month.
const monthInput = document.getElementById('report-month');
if (monthInput) {
  const now = new Date();
  monthInput.value = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

// ---- View lifecycle (called by the router in app.js) ----

window.onViewChanged = (view) => {
  if (view === 'dashboard') loadDashboard();
  else if (view === 'websites') loadAssets();
  else if (view === 'vulnerabilities') { loadFindings(); populateAssetFilter(); }
  else if (view === 'mitigation') loadMitigation();
  else if (view === 'attacks') loadAttacks();
  else if (view === 'reports') loadScanReportsList();
  else if (view === 'waf') {
    loadWafOverview();
    loadWafRules();
    loadWafInstallAssets();
    startWafMonitor();
  } else if (view === 'scans') { /* scan-center.js handles its own view */ }
  if (view !== 'waf') stopWafMonitor();
};

async function populateAssetFilter() {
  const filter = document.getElementById('filter-finding-asset');
  if (!filter) return;
  const prev = filter.value;
  const assets = await window.getAssets();
  filter.innerHTML = '<option value="">All websites</option>';
  for (const asset of assets) {
    const opt = document.createElement('option');
    opt.value = asset.id;
    opt.textContent = asset.name;
    filter.appendChild(opt);
  }
  if (prev && assets.some((a) => a.id === prev)) filter.value = prev;
}

// Initial load for the default view.
window.onViewChanged('dashboard');
