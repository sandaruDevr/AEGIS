// AEGIS Control Center — application infrastructure
// WebSocket connection, settings, model selector, toasts, view router.
// Scan lifecycle UI lives in scan-center.js; overview views in dashboard.js.

const MSG = {
  PANEL_GET_MODELS: 'PANEL_GET_MODELS',
  PANEL_SET_MODEL: 'PANEL_SET_MODEL',
  PANEL_SET_API_KEY: 'PANEL_SET_API_KEY',
  PANEL_GET_SETTINGS: 'PANEL_GET_SETTINGS',
  PANEL_SET_PROVIDER: 'PANEL_SET_PROVIDER',
  PANEL_SET_SYSTEM_PROMPT: 'PANEL_SET_SYSTEM_PROMPT',
  BG_CHAT_ERROR: 'BG_CHAT_ERROR',
  BG_MODELS_LIST: 'BG_MODELS_LIST',
  BG_SETTINGS: 'BG_SETTINGS',
  BG_SESSION_COST: 'BG_SESSION_COST',
  SCAN_JOBS: 'SCAN_JOBS',
  SCAN_JOB: 'SCAN_JOB',
  SCAN_PROGRESS: 'SCAN_PROGRESS',
  SCAN_ACTIVITY: 'SCAN_ACTIVITY',
  SCAN_FINDING: 'SCAN_FINDING',
};

// ---- WebSocket Connection ----
let ws = null;
let wsConnected = false;

function connectWS() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${location.host}/ws`);

  ws.onopen = () => {
    wsConnected = true;
    updateConnStatus(true);
    sendMsg({ type: MSG.PANEL_GET_SETTINGS });
    sendMsg({ type: MSG.PANEL_GET_MODELS });
  };

  ws.onclose = () => {
    wsConnected = false;
    updateConnStatus(false);
    setTimeout(connectWS, 2000);
  };

  ws.onerror = () => {};

  ws.onmessage = (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      return;
    }
    handleMessage(msg);
  };
}

function sendMsg(msg) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(msg));
  }
}

// ---- State ----
let allModels = [];
let selectedProvider = 'openrouter';
let selectedModelId = null;

// ---- DOM Elements ----
const sessionCostEl = document.getElementById('session-cost');
const sessionTokensEl = document.getElementById('session-tokens');
const sessionCacheEl = document.getElementById('session-cache');
const settingsModal = document.getElementById('settings-modal');
const btnCloseSettings = document.getElementById('btn-close-settings');
const btnSaveSettings = document.getElementById('btn-save-settings');
const connStatusEl = document.getElementById('conn-status');
const toastContainer = document.getElementById('toast-container');
const btnSettings = document.getElementById('btn-settings');

// ---- Toast Notifications ----
function showToast(message, type = 'info', duration = 4000) {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('removing');
    setTimeout(() => toast.remove(), 300);
  }, duration);
}
window.showToast = showToast;

// ---- Connection Status ----
function updateConnStatus(connected) {
  if (connected) {
    connStatusEl.classList.remove('disconnected');
    connStatusEl.classList.add('connected');
    connStatusEl.querySelector('.label').textContent = 'Connected';
  } else {
    connStatusEl.classList.remove('connected');
    connStatusEl.classList.add('disconnected');
    connStatusEl.querySelector('.label').textContent = 'Reconnecting…';
  }
}

// ---- Session Cost / Tokens ----
function updateSessionCost(cost, inputTokens, outputTokens, cachedTokens) {
  if (sessionCostEl) sessionCostEl.textContent = `$${(cost || 0).toFixed(4)}`;
  if (sessionTokensEl) sessionTokensEl.textContent = `↑${(inputTokens || 0).toLocaleString()} ↓${(outputTokens || 0).toLocaleString()}`;
  if (sessionCacheEl) {
    if (cachedTokens > 0 && inputTokens > 0) {
      const pct = Math.round((cachedTokens / inputTokens) * 100);
      sessionCacheEl.textContent = `⚡ ${pct}%`;
      sessionCacheEl.classList.remove('hidden');
    } else {
      sessionCacheEl.classList.add('hidden');
    }
  }
}

// ---- Message Handling ----
function handleMessage(msg) {
  switch (msg.type) {
    case MSG.BG_SETTINGS:
      applySettings(msg.settings);
      break;

    case MSG.BG_MODELS_LIST:
      if (msg.error) {
        showToast(`Failed to load models: ${msg.error}`, 'error');
      } else {
        allModels = msg.models || [];
        renderModelList(allModels);
      }
      break;

    case MSG.BG_SESSION_COST:
      updateSessionCost(msg.cost, msg.inputTokens, msg.outputTokens, msg.cachedTokens);
      break;

    case MSG.BG_CHAT_ERROR:
      showToast(msg.error || 'An unexpected error occurred', 'error', 6000);
      break;

    case 'NAVIGATION_ERROR':
      showToast(`Failed to load URL: ${msg.error}`, 'error');
      break;

    // Scan lifecycle — handled by scan-center.js
    case MSG.SCAN_JOBS:
    case MSG.SCAN_JOB:
    case MSG.SCAN_PROGRESS:
    case MSG.SCAN_ACTIVITY:
    case MSG.SCAN_FINDING:
      if (typeof window.handleScanEvent === 'function') {
        window.handleScanEvent(msg);
      }
      break;
  }
}

// ---- Settings ----
function applySettings(settings) {
  if (!settings) return;

  selectedProvider = settings.provider || 'openrouter';
  document.querySelectorAll('.provider-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.provider === selectedProvider);
  });
  document.getElementById('setting-group-openrouter-key').classList.toggle('hidden', selectedProvider !== 'openrouter');
  document.getElementById('setting-openai-key-group').classList.toggle('hidden', selectedProvider !== 'openai');

  document.getElementById('setting-api-key').value = settings.apiKey || '';
  document.getElementById('setting-openai-key').value = settings.openaiApiKey || '';
  document.getElementById('setting-temperature').value = settings.temperature ?? 0.7;
  document.getElementById('temp-value').textContent = settings.temperature ?? 0.7;
  document.getElementById('setting-system-prompt').value = settings.systemPrompt || '';

  if (settings.selectedModel) {
    selectedModelId = settings.selectedModel;
    const labelEl = document.getElementById('model-selected-label');
    labelEl.textContent = settings.selectedModel;
    labelEl.classList.remove('placeholder');
  }

  if (settings.sessionCost !== undefined && settings.sessionCost !== null) {
    updateSessionCost(settings.sessionCost, settings.sessionInputTokens, settings.sessionOutputTokens, settings.sessionCachedTokens);
  }

  document.getElementById('setting-input-price').value = settings.customInputPrice ?? '';
  document.getElementById('setting-output-price').value = settings.customOutputPrice ?? '';
}

function saveSettings() {
  const apiKey = document.getElementById('setting-api-key').value.trim();
  const openaiApiKey = document.getElementById('setting-openai-key').value.trim();
  const temperature = parseFloat(document.getElementById('setting-temperature').value);
  const systemPrompt = document.getElementById('setting-system-prompt').value.trim();
  const inputPrice = document.getElementById('setting-input-price').value.trim();
  const outputPrice = document.getElementById('setting-output-price').value.trim();

  // Only send API key if non-empty (prevents overwriting valid key with empty string)
  if (selectedProvider === 'openrouter' && apiKey) {
    sendMsg({ type: MSG.PANEL_SET_API_KEY, apiKey });
  }
  if (selectedProvider === 'openai' && openaiApiKey) {
    sendMsg({ type: MSG.PANEL_SET_API_KEY, apiKey: openaiApiKey });
  }

  sendMsg({ type: MSG.PANEL_SET_SYSTEM_PROMPT, systemPrompt: systemPrompt || null });
  sendMsg({ type: MSG.PANEL_SET_PROVIDER, provider: selectedProvider });

  fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      apiKey: apiKey || undefined,
      openaiApiKey: openaiApiKey || undefined,
      temperature,
      systemPrompt: systemPrompt || null,
      provider: selectedProvider,
      customInputPrice: inputPrice ? parseFloat(inputPrice) : null,
      customOutputPrice: outputPrice ? parseFloat(outputPrice) : null,
    }),
  }).then(() => {
    settingsModal.classList.add('hidden');
    showToast('Settings saved', 'success');
  }).catch(() => {
    showToast('Failed to save settings', 'error');
  });
}

function renderModelList(models) {
  const list = document.getElementById('model-list');
  list.innerHTML = '';

  if (!models || models.length === 0) {
    list.innerHTML = '<div style="padding:16px;text-align:center;color:var(--text-3);font-size:13px;">No models available</div>';
    return;
  }

  models.forEach((model) => {
    const item = document.createElement('div');
    item.className = 'model-item';
    if (model.id === selectedModelId) item.classList.add('selected');
    item.dataset.modelId = model.id;
    item.innerHTML = `
      <div class="model-item-name">${escapeHtml(model.name || model.id)}</div>
      <div class="model-item-id">${escapeHtml(model.id)}</div>
      ${model.contextLength ? `<div class="model-item-ctx">${Math.round(model.contextLength / 1000)}K context</div>` : ''}
    `;
    item.onclick = () => {
      selectedModelId = model.id;
      const labelEl = document.getElementById('model-selected-label');
      labelEl.textContent = model.name || model.id;
      labelEl.classList.remove('placeholder');
      document.getElementById('model-dropdown').classList.add('hidden');
      document.querySelectorAll('.model-item').forEach((mi) => mi.classList.toggle('selected', mi === item));
      sendMsg({ type: MSG.PANEL_SET_MODEL, model: model.id, pricing: model.pricing });
    };
    list.appendChild(item);
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = String(text ?? '');
  return div.innerHTML;
}
window.escapeHtml = escapeHtml;

// ---- Event Listeners ----
btnSettings.addEventListener('click', () => {
  settingsModal.classList.remove('hidden');
  if (allModels.length === 0) {
    sendMsg({ type: MSG.PANEL_GET_MODELS });
  }
});

btnCloseSettings.addEventListener('click', () => settingsModal.classList.add('hidden'));
btnSaveSettings.addEventListener('click', saveSettings);

settingsModal.addEventListener('click', (e) => {
  if (e.target === settingsModal) settingsModal.classList.add('hidden');
});

document.getElementById('setting-temperature').addEventListener('input', (e) => {
  document.getElementById('temp-value').textContent = e.target.value;
});

document.querySelectorAll('.provider-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    selectedProvider = btn.dataset.provider;
    document.querySelectorAll('.provider-btn').forEach((b) => b.classList.toggle('active', b === btn));
    document.getElementById('setting-group-openrouter-key').classList.toggle('hidden', selectedProvider !== 'openrouter');
    document.getElementById('setting-openai-key-group').classList.toggle('hidden', selectedProvider !== 'openai');
  });
});

document.getElementById('model-selected').addEventListener('click', (e) => {
  e.stopPropagation();
  document.getElementById('model-dropdown').classList.toggle('hidden');
});

document.getElementById('model-search').addEventListener('input', (e) => {
  const term = e.target.value.toLowerCase();
  document.querySelectorAll('.model-item').forEach((item) => {
    const text = item.textContent.toLowerCase();
    item.style.display = text.includes(term) ? '' : 'none';
  });
});

document.addEventListener('click', (e) => {
  const selector = document.getElementById('model-selector');
  if (selector && !selector.contains(e.target)) {
    document.getElementById('model-dropdown').classList.add('hidden');
  }
});

// Keyboard: Escape closes modal
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !settingsModal.classList.contains('hidden')) {
    settingsModal.classList.add('hidden');
  }
});

// ---- View Router (AEGIS Control Center) ----
const VIEW_TITLES = {
  dashboard: 'Dashboard',
  websites: 'Websites',
  scans: 'Scan Center',
  vulnerabilities: 'Vulnerabilities',
  mitigation: 'Mitigation Plans',
  attacks: 'Attack Log',
  reports: 'Reports',
  waf: 'WAF Shield',
};

let currentView = null;

function switchView(view) {
  if (!VIEW_TITLES[view] || view === currentView) return;
  currentView = view;

  document.querySelectorAll('.view').forEach((el) => el.classList.add('hidden'));
  const target = document.getElementById(`view-${view}`);
  if (target) target.classList.remove('hidden');

  document.querySelectorAll('.nav-item[data-view]').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.view === view);
  });

  const titleEl = document.getElementById('view-title');
  if (titleEl) titleEl.textContent = VIEW_TITLES[view];

  if (location.hash !== `#/${view}`) {
    history.replaceState(null, '', `#/${view}`);
  }

  if (typeof window.onViewChanged === 'function') {
    window.onViewChanged(view);
  }
}

function navigateTo(view) {
  switchView(view);
}
window.navigateTo = navigateTo;

document.querySelectorAll('.nav-item[data-view]').forEach((btn) => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

document.addEventListener('click', (e) => {
  const link = e.target.closest?.('.panel-link[data-goto]');
  if (link) switchView(link.dataset.goto);
});

window.addEventListener('hashchange', () => {
  const view = location.hash.replace('#/', '') || 'dashboard';
  switchView(view);
});

// ---- Init ----
connectWS();
switchView(location.hash.replace('#/', '') || 'dashboard');
