// AEGIS Scan Center — scan launcher, live monitor, job history, scan reports.
// The live monitor is the user-facing scan experience: phase stepper, progress,
// plain-language activity feed. Internal mechanisms never appear here.

// ---- Shared helpers (mirror dashboard.js) ----

function scEl(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function scTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function scDuration(ms) {
  if (!ms && ms !== 0) return '—';
  const mins = Math.floor(ms / 60000);
  const secs = Math.floor((ms % 60000) / 1000);
  if (mins === 0) return `${secs}s`;
  return `${mins}m ${secs}s`;
}

function scBadge(value) {
  const known = ['critical', 'high', 'medium', 'low', 'info'];
  const v = String(value || 'info').toLowerCase();
  const cls = known.includes(v) ? v : 'info';
  return scEl('span', `badge badge-${cls}`, v.toUpperCase());
}

function scStatusBadge(status) {
  const map = {
    queued: ['badge-info', 'Queued'],
    running: ['badge-triage', 'Running'],
    completed: ['badge-blocked', 'Completed'],
    failed: ['badge-status-open', 'Failed'],
    stopped: ['badge-allowed', 'Stopped'],
  };
  const [cls, label] = map[status] || ['badge-info', status];
  return scEl('span', `badge ${cls}`, label);
}

async function scApi(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `${res.status} ${res.statusText}`);
  }
  return res.json();
}

// ---- State ----

const PHASE_STEPS = [
  { id: 'preparing', label: 'Preparation' },
  { id: 'exploring', label: 'Exploration' },
  { id: 'config', label: 'Configuration' },
  { id: 'inspecting', label: 'Deep Inspection' },
  { id: 'verifying', label: 'Verification' },
  { id: 'reporting', label: 'Report' },
];

let jobs = [];
let activeJobId = null;   // job shown in the monitor
let elapsedTimer = null;
let launcherType = 'assessment';
let launcherProfile = 'quick';

// ---- WS event intake ----

window.handleScanEvent = (msg) => {
  switch (msg.type) {
    case 'SCAN_JOBS':
      jobs = msg.jobs || [];
      syncMonitorFromJobs();
      renderJobsTable();
      window.onScanJobsChanged?.(jobs);
      break;
    case 'SCAN_JOB':
      upsertJob(msg.job);
      break;
    case 'SCAN_PROGRESS':
      applyProgress(msg);
      break;
    case 'SCAN_ACTIVITY':
      appendActivity(msg.activity);
      break;
    case 'SCAN_FINDING':
      onFindingConfirmed(msg);
      break;
  }
};

function upsertJob(job) {
  const idx = jobs.findIndex((j) => j.id === job.id);
  if (idx >= 0) jobs[idx] = job;
  else jobs.unshift(job);
  jobs.sort((a, b) => b.createdAt - a.createdAt);

  syncMonitorFromJobs();
  renderJobsTable();
  window.onScanJobsChanged?.(jobs);
}

function syncMonitorFromJobs() {
  const active = jobs.find((j) => j.status === 'running' || j.status === 'queued');
  if (active) {
    if (activeJobId !== active.id) {
      activeJobId = active.id;
      resetMonitor(active);
    }
    renderMonitor(active);
  } else if (activeJobId) {
    const finished = jobs.find((j) => j.id === activeJobId);
    if (finished) renderMonitor(finished);
    stopElapsedTimer();
  }
  updateNavDot();
}

function updateNavDot() {
  const dot = document.getElementById('nav-scan-dot');
  if (!dot) return;
  const active = jobs.some((j) => j.status === 'running' || j.status === 'queued');
  dot.classList.toggle('hidden', !active);
}

// ---- Live monitor ----

function resetMonitor(job) {
  const feed = document.getElementById('scan-feed');
  if (feed) feed.innerHTML = '';
  const banner = document.getElementById('scan-result-banner');
  if (banner) banner.classList.add('hidden');
  renderStepper(job.phaseId);
  startElapsedTimer(job);
}

function renderMonitor(job) {
  const monitor = document.getElementById('scan-monitor');
  if (!monitor) return;
  monitor.classList.remove('hidden');

  document.getElementById('monitor-title').textContent =
    `${job.typeLabel} — ${job.assetName}`;
  document.getElementById('monitor-sub').textContent =
    `${job.profileLabel} · ${job.target}${job.authenticated === true ? ' · signed in' : ''}`;

  document.getElementById('monitor-progress').style.width = `${job.progress}%`;
  document.getElementById('monitor-progress-pct').textContent = `${job.progress}%`;
  document.getElementById('monitor-checks').textContent =
    job.totalChecks !== undefined && job.totalChecks !== null
      ? `${job.checksCompleted ?? 0}/${job.totalChecks}`
      : job.checksDone;
  document.getElementById('monitor-suspects').textContent = job.issuesSuspected;
  document.getElementById('monitor-confirmed').textContent =
    job.issuesConfirmed !== null && job.issuesConfirmed !== undefined ? job.issuesConfirmed : '—';

  renderStepper(job.phaseId, job.status);

  const stopBtn = document.getElementById('btn-stop-scan');
  const isActive = job.status === 'running' || job.status === 'queued';
  stopBtn.classList.toggle('hidden', !isActive);

  if (job.status === 'completed' || job.status === 'failed' || job.status === 'stopped') {
    stopElapsedTimer();
    renderResultBanner(job);
  }

  window.onDashboardActiveScan?.(isActive ? job : null);
}

function renderStepper(currentPhaseId, status = 'running') {
  const stepper = document.getElementById('scan-stepper');
  if (!stepper) return;
  const currentIdx = PHASE_STEPS.findIndex((p) => p.id === currentPhaseId);
  stepper.innerHTML = '';
  PHASE_STEPS.forEach((phase, i) => {
    const step = scEl('div', 'stepper-step');
    const done = status === 'completed' || i < currentIdx;
    const isCurrent = status === 'running' && i === currentIdx;
    if (done) step.classList.add('done');
    if (isCurrent) step.classList.add('current');
    if (status === 'failed' && i === currentIdx) step.classList.add('failed');

    const dot = scEl('div', 'stepper-dot');
    if (done) {
      dot.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="m5 13 4 4L19 7"/></svg>';
    }
    step.appendChild(dot);
    step.appendChild(scEl('div', 'stepper-label', phase.label));
    stepper.appendChild(step);
    if (i < PHASE_STEPS.length - 1) {
      const line = scEl('div', `stepper-line${i < currentIdx || status === 'completed' ? ' done' : ''}`);
      stepper.appendChild(line);
    }
  });
}

function renderResultBanner(job) {
  const banner = document.getElementById('scan-result-banner');
  if (!banner) return;
  banner.classList.remove('hidden');
  banner.className = `scan-result-banner ${job.status}`;

  if (job.status === 'completed') {
    const by = job.findingsBySeverity || {};
    const total = job.issuesConfirmed || 0;
    const sevSummary = total > 0
      ? `${by.critical || 0} critical · ${by.high || 0} high · ${by.medium || 0} medium · ${by.low || 0} low`
      : 'No issues confirmed';
    const coverage = job.totalChecks
      ? `${job.checksCompleted ?? 0}/${job.totalChecks} checks completed`
      : `${job.checksDone} checks`;
    banner.innerHTML = `
      <div class="scan-result-title">${total > 0 ? `${total} issue${total === 1 ? '' : 's'} confirmed` : 'Scan passed — no issues confirmed'}</div>
      <div class="scan-result-sub">${scEscape(sevSummary)} · ${scEscape(coverage)} · ${scDuration(job.durationMs)}</div>
      <div class="scan-result-actions">
        <button class="btn-primary btn-sm" id="banner-view-report">View report</button>
        <button class="btn-secondary btn-sm" id="banner-view-issues">View issues</button>
      </div>`;
    document.getElementById('banner-view-report')?.addEventListener('click', () => openScanReport(job.id));
    document.getElementById('banner-view-issues')?.addEventListener('click', () => window.navigateTo?.('vulnerabilities'));
  } else {
    banner.innerHTML = `
      <div class="scan-result-title">${job.status === 'failed' ? 'Scan could not finish' : 'Scan stopped'}</div>
      <div class="scan-result-sub">${scEscape(job.error || 'No further details.')}</div>`;
  }
}

function scEscape(text) {
  const div = document.createElement('div');
  div.textContent = String(text ?? '');
  return div.innerHTML;
}

function appendActivity(activity) {
  // Only show activity for the job currently in the monitor.
  if (activeJobId && activity.jobId !== activeJobId) return;
  const feed = document.getElementById('scan-feed');
  if (!feed) return;

  const item = scEl('div', `feed-item kind-${activity.kind}`);
  const dot = scEl('span', 'feed-dot');
  item.appendChild(dot);
  item.appendChild(scEl('span', 'feed-message', activity.message));
  item.appendChild(scEl('span', 'feed-time', new Date(activity.ts).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })));
  feed.prepend(item);

  // Keep the feed light.
  while (feed.children.length > 60) feed.lastChild.remove();
}

function onFindingConfirmed(msg) {
  if (msg.jobId !== activeJobId) return;
  const feed = document.getElementById('scan-feed');
  if (!feed) return;
  const f = msg.finding;
  const item = scEl('div', 'feed-item kind-confirmed');
  item.appendChild(scEl('span', 'feed-dot'));
  item.appendChild(scEl('span', 'feed-message', `Confirmed: ${f.title} (${(f.severity || '').toUpperCase()})`));
  item.appendChild(scEl('span', 'feed-time', ''));
  feed.prepend(item);
}

function startElapsedTimer(job) {
  stopElapsedTimer();
  const el = document.getElementById('monitor-elapsed');
  if (!el || !job.startedAt) return;
  const tick = () => {
    const active = jobs.find((j) => j.id === activeJobId);
    if (!active || (active.status !== 'running' && active.status !== 'queued')) {
      stopElapsedTimer();
      return;
    }
    const base = active.startedAt || active.createdAt;
    const ms = Date.now() - base;
    const mins = Math.floor(ms / 60000);
    const secs = Math.floor((ms % 60000) / 1000);
    el.textContent = `${mins}:${String(secs).padStart(2, '0')}`;
  };
  tick();
  elapsedTimer = setInterval(tick, 1000);
}

function stopElapsedTimer() {
  if (elapsedTimer) {
    clearInterval(elapsedTimer);
    elapsedTimer = null;
  }
}

// ---- Launcher ----

function renderLauncher() {
  const select = document.getElementById('scan-asset');
  if (!select) return;
  window.getAssets?.().then((assets) => {
    const prev = select.value;
    select.innerHTML = '';
    if (!assets || assets.length === 0) {
      select.innerHTML = '<option value="">No websites registered — add one first</option>';
      return;
    }
    for (const asset of assets) {
      const opt = document.createElement('option');
      opt.value = asset.id;
      opt.textContent = `${asset.name} — ${asset.url}`;
      select.appendChild(opt);
    }
    if (prev && assets.some((a) => a.id === prev)) select.value = prev;
  });
}

function updateEstimate() {
  const el = document.getElementById('scan-estimate');
  if (!el) return;
  const estimates = {
    quick: 'A few minutes — replaces days of manual security review',
    full: '15–25 minutes — replaces weeks of expert assessment',
    custom: 'Minutes — replaces days to weeks of manual work',
  };
  el.textContent = estimates[launcherProfile] || '';
}

// ---- Check plan preview (universal framework) ----

async function refreshPlanPreview() {
  const container = document.getElementById('scan-plan-preview');
  if (!container) return;
  const options = launcherProfile === 'custom'
    ? {
        headers: document.getElementById('opt-headers')?.checked,
        cookies: document.getElementById('opt-cookies')?.checked,
        forms: document.getElementById('opt-forms')?.checked,
        secrets: document.getElementById('opt-secrets')?.checked,
        js: document.getElementById('opt-js')?.checked,
        network: document.getElementById('opt-network')?.checked,
        deep: document.getElementById('opt-deep')?.checked,
      }
    : undefined;
  const params = new URLSearchParams({ type: launcherType, profile: launcherProfile });
  if (options) params.set('options', JSON.stringify(options));
  try {
    const plan = await scApi(`/api/scans/plan?${params}`);
    const byCat = {};
    for (const c of plan.checks) {
      (byCat[c.category] = byCat[c.category] || []).push(c.title);
    }
    const catLabels = { preparing: 'Preparation', exploring: 'Exploration', config: 'Configuration', inspecting: 'Deep Inspection' };
    container.innerHTML = `
      <div class="plan-preview-head">Typical coverage areas — the agent decides the actual plan from initial recon</div>
      ${Object.entries(byCat).map(([cat, titles]) => `
        <div class="plan-preview-group">
          <div class="plan-preview-cat">${scEscape(catLabels[cat] || cat)}</div>
          <div class="plan-preview-checks">${titles.map((t) => scEscape(t)).join(' · ')}</div>
        </div>`).join('')}`;
    container.classList.remove('hidden');
  } catch (err) {
    container.classList.add('hidden');
  }
}

document.querySelectorAll('.type-card').forEach((btn) => {
  btn.addEventListener('click', () => {
    launcherType = btn.dataset.type;
    document.querySelectorAll('.type-card').forEach((b) => b.classList.toggle('active', b === btn));
    refreshPlanPreview();
  });
});

document.querySelectorAll('.profile-card').forEach((btn) => {
  btn.addEventListener('click', () => {
    launcherProfile = btn.dataset.profile;
    document.querySelectorAll('.profile-card').forEach((b) => b.classList.toggle('active', b === btn));
    document.getElementById('custom-options').classList.toggle('hidden', launcherProfile !== 'custom');
    updateEstimate();
    refreshPlanPreview();
  });
});

document.querySelectorAll('#custom-options input[type="checkbox"]').forEach((cb) => {
  cb.addEventListener('change', refreshPlanPreview);
});

document.getElementById('btn-start-scan')?.addEventListener('click', async () => {
  const assetId = document.getElementById('scan-asset')?.value;
  if (!assetId) {
    window.showToast?.('Register a website first', 'error');
    window.navigateTo?.('websites');
    return;
  }
  const options = launcherProfile === 'custom'
    ? {
        headers: document.getElementById('opt-headers')?.checked,
        cookies: document.getElementById('opt-cookies')?.checked,
        forms: document.getElementById('opt-forms')?.checked,
        secrets: document.getElementById('opt-secrets')?.checked,
        js: document.getElementById('opt-js')?.checked,
        network: document.getElementById('opt-network')?.checked,
        deep: document.getElementById('opt-deep')?.checked,
      }
    : undefined;

  try {
    const data = await scApi('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assetId, type: launcherType, profile: launcherProfile, options }),
    });
    upsertJob(data.job);
    activeJobId = data.job.id;
    resetMonitor(data.job);
    renderMonitor(data.job);
    document.getElementById('scan-monitor').scrollIntoView({ behavior: 'smooth', block: 'start' });
    window.showToast?.('Scan started', 'success');
  } catch (err) {
    window.showToast?.(err.message, 'error', 6000);
  }
});

document.getElementById('btn-stop-scan')?.addEventListener('click', async () => {
  if (!activeJobId) return;
  try {
    await scApi(`/api/scans/${activeJobId}/stop`, { method: 'POST' });
    window.showToast?.('Stopping scan…', 'info');
  } catch (err) {
    window.showToast?.(err.message, 'error');
  }
});

document.getElementById('btn-refresh-jobs')?.addEventListener('click', refreshJobs);

async function refreshJobs() {
  try {
    const data = await scApi('/api/scans');
    jobs = data.jobs || [];
    syncMonitorFromJobs();
    renderJobsTable();
    window.onScanJobsChanged?.(jobs);
  } catch (err) {
    console.warn('[ScanCenter] refresh failed:', err.message);
  }
}

// ---- Job history ----

function renderJobsTable() {
  const container = document.getElementById('jobs-table');
  if (!container) return;
  if (!jobs || jobs.length === 0) {
    container.innerHTML = '<div class="attack-empty">No scans yet. Configure one above and press Start scan.</div>';
    return;
  }
  const rows = jobs.slice(0, 50).map((job) => {
    const issues = job.issuesConfirmed !== null && job.issuesConfirmed !== undefined
      ? `${job.issuesConfirmed}`
      : job.status === 'running' ? `${job.issuesSuspected} suspected` : '—';
    const actions = [];
    if (job.status === 'completed') {
      actions.push(`<button class="finding-status-btn" data-report="${job.id}">Report</button>`);
    }
    if (job.status === 'running' || job.status === 'queued') {
      actions.push(`<button class="finding-status-btn" data-stop="${job.id}">Stop</button>`);
    }
    if (job.status === 'completed' || job.status === 'failed' || job.status === 'stopped') {
      actions.push(`<button class="finding-status-btn" data-rerun="${job.id}">Run again</button>`);
    }
    return `<tr>
      <td class="at-time">${scTime(job.createdAt)}</td>
      <td>${scEscape(job.assetName)}</td>
      <td>${scEscape(job.typeLabel)}</td>
      <td>${scEscape(job.profileLabel)}</td>
      <td>${scStatusBadge(job.status).outerHTML}</td>
      <td class="at-conf">${scEscape(issues)}</td>
      <td class="at-conf">${scDuration(job.durationMs)}</td>
      <td><div class="job-actions">${actions.join('')}</div></td>
    </tr>`;
  }).join('');
  container.innerHTML = `<table>
    <thead><tr><th>Started</th><th>Website</th><th>Type</th><th>Depth</th><th>Status</th><th>Issues</th><th>Duration</th><th></th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;

  container.querySelectorAll('[data-report]').forEach((btn) =>
    btn.addEventListener('click', () => openScanReport(btn.dataset.report)));
  container.querySelectorAll('[data-stop]').forEach((btn) =>
    btn.addEventListener('click', async () => {
      try {
        await scApi(`/api/scans/${btn.dataset.stop}/stop`, { method: 'POST' });
      } catch (err) {
        window.showToast?.(err.message, 'error');
      }
    }));
  container.querySelectorAll('[data-rerun]').forEach((btn) =>
    btn.addEventListener('click', async () => {
      const job = jobs.find((j) => j.id === btn.dataset.rerun);
      if (!job) return;
      try {
        const data = await scApi('/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ assetId: job.assetId, type: job.type, profile: job.profile, options: job.options }),
        });
        upsertJob(data.job);
        activeJobId = data.job.id;
        resetMonitor(data.job);
        renderMonitor(data.job);
        window.navigateTo?.('scans');
      } catch (err) {
        window.showToast?.(err.message, 'error');
      }
    }));
}

// ---- Scan report (executive) ----

async function openScanReport(jobId) {
  try {
    const report = await scApi(`/api/scans/${jobId}/report`);
    const output = document.getElementById('scan-report-output');
    if (!output) return;
    renderScanReportInto(output, report);
    output.classList.remove('hidden');
    output.scrollIntoView({ behavior: 'smooth', block: 'start' });
    window.navigateTo?.('reports');
    // Switch to the scan-reports tab.
    document.getElementById('tab-scan-reports')?.click();
  } catch (err) {
    window.showToast?.(err.message, 'error');
  }
}

window.renderScanReportInto = (container, report) => {
  const stats = report.stats || {};
  const by = stats.bySeverity || {};
  container.innerHTML = `
    <div class="report-title">${scEscape(report.typeLabel)} Report — ${scEscape(report.asset.name)}</div>
    <div class="finding-meta">${scEscape(report.asset.url)} · ${scEscape(report.profileLabel)} · ${scTime(report.startedAt)}${report.durationMs ? ` · ${scDuration(report.durationMs)}` : ''}</div>
    <div class="report-narrative">
      ${(report.narrative || []).map((n) => `<p>${scEscape(n)}</p>`).join('')}
    </div>
    <div class="report-stats">
      <div class="report-stat"><div class="report-stat-value">${stats.posture?.postureScore ?? '—'}</div><div class="report-stat-label">Posture / 100</div></div>
      <div class="report-stat"><div class="report-stat-value">${stats.total ?? 0}</div><div class="report-stat-label">Issues confirmed</div></div>
      <div class="report-stat"><div class="report-stat-value">${report.checks ?? 0}</div><div class="report-stat-label">Checks performed</div></div>
      <div class="report-stat"><div class="report-stat-value">${by.critical || 0}</div><div class="report-stat-label">Critical issues</div></div>
    </div>
    <div class="report-coverage">
      <h4>Check coverage — ${report.coverage ? `${report.coverage.passed + report.coverage.issue} of ${report.coverage.total} checks completed` : ''}</h4>
      <div class="coverage-grid">
        ${(report.checkResults || []).map((c) => `
          <div class="coverage-item">
            <span class="coverage-status ${scEscape(c.status)}">${scEscape(c.status)}</span>
            <span>${scEscape(c.title)}</span>
            ${c.note ? `<span class="coverage-note" title="${scEscape(c.note)}">${scEscape(c.note)}</span>` : ''}
          </div>`).join('')}
      </div>
    </div>
    <div class="report-findings">
      <h4>Issues & fixes (priority order)</h4>
      ${(report.findings || []).length === 0
        ? '<div class="mini-empty">No issues were confirmed in this scan.</div>'
        : (report.findings || []).map((f) => `
          <div class="mini-item" style="align-items:flex-start;">
            ${scBadge(f.severity).outerHTML}
            <div style="flex:1;min-width:0;">
              <div class="mini-item-title" style="white-space:normal;">${scEscape(f.title)}</div>
              <div style="font-size:12px;color:var(--text-2);margin-top:4px;line-height:1.6;">${scEscape(f.summary || '')}</div>
              ${f.fix ? `<div style="font-size:12px;color:var(--success);margin-top:4px;line-height:1.6;">Fix: ${scEscape(f.fix)}</div>` : ''}
            </div>
          </div>`).join('')}
    </div>`;
};

// ---- View lifecycle ----

window.onViewChanged = ((original) => (view) => {
  original?.(view);
  if (view === 'scans') {
    renderLauncher();
    refreshJobs();
    refreshPlanPreview();
  }
})(window.onViewChanged);

updateEstimate();
refreshJobs();
refreshPlanPreview();
