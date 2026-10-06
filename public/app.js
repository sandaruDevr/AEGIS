// Web UI Application — communicates with server via WebSocket
// Fixed pipelines: models loaded on connect, null-safe cost, no empty key overwrite,
// revert on user messages, connection status, toast notifications, model validation

const MSG = {
  PANEL_SEND_CHAT: 'PANEL_SEND_CHAT',
  PANEL_GET_MODELS: 'PANEL_GET_MODELS',
  PANEL_SET_MODEL: 'PANEL_SET_MODEL',
  PANEL_SET_API_KEY: 'PANEL_SET_API_KEY',
  PANEL_GET_SETTINGS: 'PANEL_GET_SETTINGS',
  PANEL_STOP_GENERATION: 'PANEL_STOP_GENERATION',
  PANEL_CLEAR_CHAT: 'PANEL_CLEAR_CHAT',
  PANEL_REVERT_TO: 'PANEL_REVERT_TO',
  PANEL_SET_PROVIDER: 'PANEL_SET_PROVIDER',
  PANEL_GET_CONVERSATION: 'PANEL_GET_CONVERSATION',
  PANEL_SET_SYSTEM_PROMPT: 'PANEL_SET_SYSTEM_PROMPT',
  PANEL_GET_SESSIONS: 'PANEL_GET_SESSIONS',
  PANEL_CREATE_SESSION: 'PANEL_CREATE_SESSION',
  PANEL_SWITCH_SESSION: 'PANEL_SWITCH_SESSION',
  PANEL_DELETE_SESSION: 'PANEL_DELETE_SESSION',
  PANEL_RENAME_SESSION: 'PANEL_RENAME_SESSION',
  BG_CHAT_CHUNK: 'BG_CHAT_CHUNK',
  BG_CHAT_DONE: 'BG_CHAT_DONE',
  BG_CHAT_ERROR: 'BG_CHAT_ERROR',
  BG_TOOL_START: 'BG_TOOL_START',
  BG_TOOL_RESULT: 'BG_TOOL_RESULT',
  BG_THINKING: 'BG_THINKING',
  BG_MODELS_LIST: 'BG_MODELS_LIST',
  BG_SETTINGS: 'BG_SETTINGS',
  BG_TAB_CONTEXT: 'BG_TAB_CONTEXT',
  BG_SESSION_COST: 'BG_SESSION_COST',
  BG_CONVERSATION_HISTORY: 'BG_CONVERSATION_HISTORY',
  BG_SESSIONS_LIST: 'BG_SESSIONS_LIST',
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
    sendMsg({ type: MSG.PANEL_GET_CONVERSATION });
    sendMsg({ type: MSG.PANEL_GET_SESSIONS });
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
let isGenerating = false;
let currentAssistantEl = null;
let currentAssistantText = '';
let allModels = [];
let selectedProvider = 'openrouter';
let selectedModelId = null;
let userMessageCount = 0;
let sessions = [];
let activeSessionId = null;

// ---- DOM Elements ----
const chatContainer = document.getElementById('chat-container');
const messagesEl = document.getElementById('messages');
const welcomeScreen = document.getElementById('welcome-screen');
const chatInput = document.getElementById('chat-input');
const btnSend = document.getElementById('btn-send');
const btnStop = document.getElementById('btn-stop');
const btnClear = document.getElementById('btn-clear');
const btnSettings = document.getElementById('btn-settings');
const targetUrl = document.getElementById('target-url');
const sessionCostEl = document.getElementById('session-cost');
const sessionTokensEl = document.getElementById('session-tokens');
const sessionCacheEl = document.getElementById('session-cache');
const settingsModal = document.getElementById('settings-modal');
const btnCloseSettings = document.getElementById('btn-close-settings');
const btnSaveSettings = document.getElementById('btn-save-settings');
const connStatusEl = document.getElementById('conn-status');
const toastContainer = document.getElementById('toast-container');
const sessionsListEl = document.getElementById('sessions-list');
const btnNewSession = document.getElementById('btn-new-session');
const btnToggleSidebar = document.getElementById('btn-toggle-sidebar');
const sidebarEl = document.getElementById('sidebar');

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

// ---- Connection Status ----
function updateConnStatus(connected) {
  if (connected) {
    connStatusEl.classList.remove('disconnected');
    connStatusEl.classList.add('connected');
    connStatusEl.querySelector('.label').textContent = 'Connected';
  } else {
    connStatusEl.classList.remove('connected');
    connStatusEl.classList.add('disconnected');
    connStatusEl.querySelector('.label').textContent = 'Disconnected';
  }
}

// ---- Message Handling ----
function handleMessage(msg) {
  switch (msg.type) {
    case MSG.BG_CHAT_CHUNK:
      hideWelcome();
      if (!currentAssistantEl) {
        currentAssistantEl = addMessageEl('assistant', '');
        currentAssistantText = '';
      }
      currentAssistantText += msg.content;
      renderMarkdown(currentAssistantEl, currentAssistantText);
      scrollToBottom();
      break;

    case MSG.BG_TOOL_START:
      hideWelcome();
      if (currentAssistantEl && currentAssistantText) {
        finalizeCurrentAssistant();
      }
      addToolStartEl(msg.toolName, msg.toolArgs, msg.toolCallId);
      break;

    case MSG.BG_TOOL_RESULT:
      addToolResultEl(msg.toolName, msg.toolCallId, msg.result);
      break;

    case MSG.BG_CHAT_DONE:
      finalizeCurrentAssistant();
      setGenerating(false);
      if (msg.warning) {
        showToast(msg.warning, 'info');
      }
      break;

    case MSG.BG_CHAT_ERROR:
      finalizeCurrentAssistant();
      setGenerating(false);
      addMessageEl('error', msg.error || 'Unknown error');
      showToast(msg.error || 'An error occurred', 'error');
      break;

    case MSG.BG_SESSION_COST:
      updateSessionCost(msg.cost, msg.inputTokens, msg.outputTokens, msg.cachedTokens);
      break;

    case MSG.BG_SETTINGS:
      applySettings(msg.settings);
      break;

    case MSG.BG_MODELS_LIST:
      if (msg.error) {
        showToast(`Failed to load models: ${msg.error}`, 'error');
        break;
      }
      if (msg.models) {
        allModels = msg.models;
        renderModelList(msg.models);
      }
      break;

    case MSG.BG_CONVERSATION_HISTORY:
      // Replace (not append) — this fires on connect and on every session switch
      messagesEl.innerHTML = '';
      currentAssistantEl = null;
      currentAssistantText = '';
      userMessageCount = 0;
      if (msg.conversation && msg.conversation.length > 0) {
        hideWelcome();
        msg.conversation.forEach((m) => {
          if (m.role === 'user') addMessageEl('user', m.content);
          else if (m.role === 'assistant') addMessageEl('assistant', m.content);
        });
      } else {
        showWelcome();
      }
      break;

    case MSG.BG_SESSIONS_LIST:
      sessions = msg.sessions || [];
      activeSessionId = msg.activeSessionId || null;
      renderSessions();
      break;

    case 'NAVIGATION_COMPLETE':
      break;

    case 'NAVIGATION_ERROR':
      showToast(`Failed to load URL: ${msg.error}`, 'error');
      break;
  }
}

// ---- Session Cost + Cache Hit Rate (null-safe) ----
function updateSessionCost(cost, inputTokens, outputTokens, cachedTokens) {
  const safeCost = typeof cost === 'number' ? cost : 0;
  sessionCostEl.textContent = `$${safeCost.toFixed(4)}`;

  if (inputTokens !== undefined && outputTokens !== undefined) {
    const fmt = (n) => (n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n));
    sessionTokensEl.textContent = `↑${fmt(inputTokens)} ↓${fmt(outputTokens)}`;
  }

  // Cache hit rate = cached prompt tokens / total prompt tokens
  if (typeof cachedTokens === 'number' && typeof inputTokens === 'number' && inputTokens > 0) {
    const hitPct = Math.round((cachedTokens / inputTokens) * 100);
    sessionCacheEl.textContent = `⚡ ${hitPct}%`;
    sessionCacheEl.classList.remove('hidden');
    sessionCacheEl.classList.toggle('good', hitPct >= 70);
    sessionCacheEl.classList.toggle('warn', hitPct > 0 && hitPct < 50);
  }
}

// ---- Sessions Sidebar ----
function renderSessions() {
  if (!sessionsListEl) return;
  sessionsListEl.innerHTML = '';

  if (!sessions || sessions.length === 0) {
    sessionsListEl.innerHTML = '<div class="sessions-empty">No sessions yet</div>';
    return;
  }

  sessions.forEach((session) => {
    const item = document.createElement('div');
    item.className = 'session-item' + (session.id === activeSessionId ? ' active' : '');
    item.dataset.sessionId = session.id;
    item.title = session.title || 'New session';

    const title = document.createElement('div');
    title.className = 'session-item-title';
    title.textContent = session.title || 'New session';

    const meta = document.createElement('div');
    meta.className = 'session-item-meta';
    meta.textContent = formatSessionTime(session.updatedAt);

    const delBtn = document.createElement('button');
    delBtn.className = 'session-delete';
    delBtn.title = 'Delete session';
    delBtn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
    delBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (confirm(`Delete this session?`)) {
        sendMsg({ type: MSG.PANEL_DELETE_SESSION, sessionId: session.id });
      }
    });

    item.appendChild(title);
    item.appendChild(meta);
    item.appendChild(delBtn);
    item.addEventListener('click', () => {
      if (session.id !== activeSessionId) {
        sendMsg({ type: MSG.PANEL_SWITCH_SESSION, sessionId: session.id });
      }
    });
    sessionsListEl.appendChild(item);
  });
}

function formatSessionTime(ts) {
  if (!ts) return '';
  const diff = Date.now() - ts;
  const mins = Math.floor(diff / 60000);
  if (diff < 0) return 'now';
  if (diff < 60_000) return 'now';
  if (mins < 60) return `${Math.max(1, mins)}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(ts).toLocaleDateString();
}

// ---- UI Helpers ----
function hideWelcome() {
  if (welcomeScreen) welcomeScreen.style.display = 'none';
}

function showWelcome() {
  if (welcomeScreen) welcomeScreen.style.display = '';
}

function scrollToBottom() {
  chatContainer.scrollTop = chatContainer.scrollHeight;
}

function addMessageEl(role, content) {
  const el = document.createElement('div');
  el.className = `message message-${role}`;
  el.setAttribute('data-role', role);

  const avatar = document.createElement('div');
  avatar.className = 'message-avatar';
  if (role === 'user') {
    avatar.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>';
  } else if (role === 'assistant') {
    avatar.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
  } else {
    avatar.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>';
  }

  const body = document.createElement('div');
  body.className = 'message-body';

  const roleLabel = document.createElement('div');
  roleLabel.className = 'message-role';
  roleLabel.textContent = role === 'user' ? 'You' : role === 'assistant' ? 'Agent' : 'System';

  const contentEl = document.createElement('div');
  contentEl.className = 'message-content';

  body.appendChild(roleLabel);
  body.appendChild(contentEl);
  el.appendChild(avatar);
  el.appendChild(body);
  messagesEl.appendChild(el);

  if (content) renderMarkdown(contentEl, content);

  // Add revert button on user messages (not assistant)
  if (role === 'user') {
    const msgIndex = userMessageCount;
    el.dataset.msgIndex = msgIndex;
    userMessageCount++;

    const revertBtn = document.createElement('button');
    revertBtn.className = 'revert-btn';
    revertBtn.title = 'Revert to this message';
    revertBtn.innerHTML = '↩';
    revertBtn.onclick = () => revertToMessage(el, msgIndex, content);
    body.appendChild(revertBtn);
  }

  scrollToBottom();
  return contentEl;
}

function revertToMessage(msgEl, msgIndex, originalContent) {
  if (isGenerating) return;

  const allMessages = Array.from(messagesEl.children);
  const startIndex = allMessages.indexOf(msgEl);
  if (startIndex === -1) return;

  while (messagesEl.children.length > startIndex) {
    messagesEl.removeChild(messagesEl.lastChild);
  }

  userMessageCount = msgIndex;
  sendMsg({ type: MSG.PANEL_REVERT_TO, messageIndex: msgIndex });

  if (messagesEl.children.length === 0) {
    showWelcome();
  }

  chatInput.value = originalContent;
  chatInput.style.height = 'auto';
  chatInput.style.height = Math.min(chatInput.scrollHeight, 140) + 'px';
  chatInput.focus();
}

function finalizeCurrentAssistant() {
  currentAssistantEl = null;
  currentAssistantText = '';
}

// ---- Tool Calls ----
function addToolStartEl(toolName, toolArgs, toolCallId) {
  const el = document.createElement('div');
  el.className = 'tool-call';
  el.dataset.toolCallId = toolCallId || '';

  const header = document.createElement('div');
  header.className = 'tool-header';

  const icon = document.createElement('span');
  icon.className = 'tool-icon';
  icon.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>';

  const name = document.createElement('span');
  name.className = 'tool-name';
  name.textContent = toolName;

  const status = document.createElement('span');
  status.className = 'tool-status running';
  status.textContent = 'running';

  const chevron = document.createElement('span');
  chevron.className = 'tool-chevron';
  chevron.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>';

  header.appendChild(icon);
  header.appendChild(name);
  header.appendChild(status);
  header.appendChild(chevron);

  const body = document.createElement('div');
  body.className = 'tool-body';

  const argsSection = document.createElement('div');
  argsSection.className = 'tool-args';
  argsSection.innerHTML = `<span class="tool-label">Arguments</span><pre>${escapeHtml(JSON.stringify(toolArgs, null, 2))}</pre>`;

  const resultSection = document.createElement('div');
  resultSection.className = 'tool-result-data';
  resultSection.innerHTML = `<span class="tool-label">Result</span><pre class="tool-result-placeholder">Waiting…</pre>`;

  body.appendChild(argsSection);
  body.appendChild(resultSection);

  el.appendChild(header);
  el.appendChild(body);

  header.addEventListener('click', () => {
    el.classList.toggle('expanded');
  });

  messagesEl.appendChild(el);
  scrollToBottom();
}

function addToolResultEl(toolName, toolCallId, result) {
  let toolEl = null;
  if (toolCallId) {
    toolEl = messagesEl.querySelector(`[data-tool-call-id="${toolCallId}"]`);
  }
  if (!toolEl) {
    toolEl = messagesEl.querySelector('.tool-call:last-child');
  }
  if (!toolEl) return;

  const success = result.success !== false;
  const status = toolEl.querySelector('.tool-status');
  if (status) {
    status.className = `tool-status ${success ? 'success' : 'error'}`;
    status.textContent = success ? 'success' : 'error';
  }

  const resultPre = toolEl.querySelector('.tool-result-placeholder');
  if (resultPre) {
    let displayData;
    if (result.results) {
      displayData = result.results;
      if (result.summary) displayData = { ...displayData, _summary: result.summary };
    } else if (result.result !== undefined) {
      displayData = result.result;
    } else {
      displayData = result.error || result;
    }

    const text = typeof displayData === 'string'
      ? displayData
      : JSON.stringify(displayData, null, 2);

    resultPre.textContent = text.length > 5000 ? text.substring(0, 5000) + '\n…[truncated]' : text;
    resultPre.classList.remove('tool-result-placeholder');
  }

  scrollToBottom();
}

// ---- Simple Markdown Renderer ----
function renderMarkdown(el, markdown) {
  if (!markdown) {
    el.innerHTML = '';
    return;
  }

  let html = markdown
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Code blocks
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) =>
    `<pre class="code-block"><code>${code}</code></pre>`
  );

  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');

  // Bold
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

  // Italic
  html = html.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');

  // Headers
  html = html.replace(/^### (.+)$/gm, '<h4>$1</h4>');
  html = html.replace(/^## (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^# (.+)$/gm, '<h2>$1</h2>');

  // Links
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');

  // Lists
  html = html.replace(/^\s*[-*] (.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>[\s\S]*?<\/li>)/g, '<ul>$1</ul>');
  html = html.replace(/<\/ul>\s*<ul>/g, '');

  // Numbered lists
  html = html.replace(/^\s*(\d+)\. (.+)$/gm, '<li>$2</li>');

  // Paragraphs
  html = html
    .split(/\n\n+/)
    .map((block) => {
      const trimmed = block.trim();
      if (!trimmed) return '';
      if (/^<(h[1-6]|ul|ol|pre|li)/.test(trimmed)) return trimmed;
      if (/^<li>/.test(trimmed)) return `<ul>${trimmed}</ul>`;
      return `<p>${trimmed.replace(/\n/g, '<br>')}</p>`;
    })
    .join('\n');

  el.innerHTML = html;
  scrollToBottom();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ---- Actions ----
function setGenerating(generating) {
  isGenerating = generating;
  btnSend.classList.toggle('hidden', generating);
  btnStop.classList.toggle('hidden', !generating);
  chatInput.disabled = generating;
}

function sendMessage() {
  const text = chatInput.value.trim();
  const url = targetUrl.value.trim();
  if ((!text && !url) || isGenerating) return;

  if (!wsConnected) {
    showToast('Not connected to server. Please wait…', 'error');
    return;
  }

  hideWelcome();
  const displayMsg = url && text ? `[Target: ${url}]\n${text}` : url ? `[Target: ${url}] — Full security assessment` : text;
  addMessageEl('user', displayMsg);
  chatInput.value = '';
  chatInput.style.height = 'auto';
  setGenerating(true);

  sendMsg({ type: 'START_SCAN', url, message: text });
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

  // Null-safe session cost
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

// ---- Event Listeners ----
btnSend.addEventListener('click', sendMessage);
btnStop.addEventListener('click', () => sendMsg({ type: MSG.PANEL_STOP_GENERATION }));
btnClear.addEventListener('click', () => {
  messagesEl.innerHTML = '';
  currentAssistantEl = null;
  userMessageCount = 0;
  sendMsg({ type: MSG.PANEL_CLEAR_CHAT });
  showWelcome();
});

btnNewSession.addEventListener('click', () => {
  messagesEl.innerHTML = '';
  currentAssistantEl = null;
  userMessageCount = 0;
  setGenerating(false);
  sendMsg({ type: MSG.PANEL_CREATE_SESSION });
  showWelcome();
  chatInput.focus();
});

btnToggleSidebar.addEventListener('click', () => {
  sidebarEl.classList.toggle('collapsed');
});

chatInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

chatInput.addEventListener('input', () => {
  chatInput.style.height = 'auto';
  chatInput.style.height = Math.min(chatInput.scrollHeight, 140) + 'px';
});

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

// Example prompts
document.querySelectorAll('.example-prompt').forEach((btn) => {
  btn.addEventListener('click', () => {
    chatInput.value = btn.dataset.prompt;
    chatInput.style.height = 'auto';
    chatInput.style.height = Math.min(chatInput.scrollHeight, 140) + 'px';
    chatInput.focus();
  });
});

// Keyboard: Escape closes modal
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !settingsModal.classList.contains('hidden')) {
    settingsModal.classList.add('hidden');
  }
});

// ---- View Router (OneEye360 shell) ----
const VIEW_TITLES = {
  dashboard: 'Dashboard',
  attacks: 'Attack Log',
  findings: 'Findings',
  agent: 'Security Agent',
  reports: 'Monthly Report',
  waf: 'WAF Lab',
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

  // Notify dashboard module so it can refresh data for the visible view.
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

document.querySelectorAll('.panel-link[data-goto]').forEach((btn) => {
  btn.addEventListener('click', () => switchView(btn.dataset.goto));
});

window.addEventListener('hashchange', () => {
  const view = location.hash.replace('#/', '') || 'dashboard';
  switchView(view);
});

// ---- Init ----
connectWS();
switchView(location.hash.replace('#/', '') || 'dashboard');
