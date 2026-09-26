// Side panel - chat UI logic and communication with background service worker

import { MSG, STORAGE_KEYS, PROVIDERS } from '../shared/constants.js';

// ---- DOM Elements ----
const $ = (id) => document.getElementById(id);
const chatContainer = $('chat-container');
const messagesEl = $('messages');
const welcomeScreen = $('welcome-screen');
const chatInput = $('chat-input');
const btnSend = $('btn-send');
const btnStop = $('btn-stop');
const btnClear = $('btn-clear');
const btnSettings = $('btn-settings');
const modelDropdown = $('model-dropdown');
const modelTrigger = $('model-dropdown-trigger');
const modelPanel = $('model-dropdown-panel');
const modelSearch = $('model-search');
const modelList = $('model-list');
const modelSelectedLabel = $('model-selected-label');
const btnRefreshModels = $('btn-refresh-models');
const tabInfo = $('tab-info');
const settingsModal = $('settings-modal');
const btnCloseSettings = $('btn-close-settings');
const btnSaveSettings = $('btn-save-settings');
const settingApiKey = $('setting-api-key');
const settingOpenaiKey = $('setting-openai-key');
const settingTemperature = $('setting-temperature');
const settingSystemPrompt = $('setting-system-prompt');
const tempValue = $('temp-value');
const sessionCostEl = $('session-cost');
const providerBtns = document.querySelectorAll('.provider-btn');
const groupOpenRouterKey = $('setting-group-openrouter-key');
const groupOpenaiKey = $('setting-group-openai-key');

// ---- State ----
let port = null;
let isGenerating = false;
let currentAssistantMessage = null;
let currentToolCallEl = null;
let allModels = [];
let selectedModelId = null;
let currentProvider = PROVIDERS.OPENROUTER;

// ---- Markdown Renderer (minimal) ----
function renderMarkdown(text) {
  if (!text) return '';

  let html = text;

  // Code blocks (```lang\ncode```)
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    return `<pre><code>${escapeHtml(code.trim())}</code></pre>`;
  });

  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

  // Bold
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

  // Italic
  html = html.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');

  // Headers
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');

  // Links
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');

  // Lists
  html = html.replace(/^\s*[-*] (.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>[\s\S]*?<\/li>)/g, '<ul>$1</ul>');
  html = html.replace(/<\/ul>\s*<ul>/g, '');

  // Numbered lists
  html = html.replace(/^\s*(\d+)\. (.+)$/gm, '<li>$2</li>');

  // Paragraphs (split by double newline, skip if already wrapped)
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

  return html;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function escapeJson(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

// ---- Port Communication ----
function connectPort() {
  port = chrome.runtime.connect({ name: 'agent-panel' });

  port.onMessage.addListener((msg) => {
    switch (msg.type) {
      case MSG.BG_CHAT_CHUNK:
        handleChatChunk(msg.content);
        break;
      case MSG.BG_TOOL_START:
        handleToolStart(msg.toolName, msg.toolArgs, msg.toolCallId);
        break;
      case MSG.BG_TOOL_RESULT:
        handleToolResult(msg.toolName, msg.toolCallId, msg.result);
        break;
      case MSG.BG_CHAT_DONE:
        handleChatDone(msg);
        break;
      case MSG.BG_CHAT_ERROR:
        handleChatError(msg.error);
        break;
      case MSG.BG_MODELS_LIST:
        handleModelsList(msg.models, msg.error);
        break;
      case MSG.BG_SETTINGS:
        handleSettings(msg.settings);
        break;
      case MSG.BG_TAB_CONTEXT:
        if (msg.context) {
          tabInfo.textContent = msg.context.title || msg.context.url;
        }
        break;
      case MSG.BG_SESSION_COST:
        updateSessionCost(msg.cost, msg.inputTokens, msg.outputTokens, msg.cachedTokens);
        break;
      case MSG.BG_CONVERSATION_HISTORY:
        renderConversationHistory(msg.conversation);
        break;
    }
  });

  port.onDisconnect.addListener(() => {
    port = null;
    // Reconnect after a short delay
    setTimeout(connectPort, 1000);
  });
}

// ---- Message Rendering ----
let conversationMessageCount = 0;

function addMessage(role, content) {
  if (welcomeScreen) welcomeScreen.style.display = 'none';

  const msgEl = document.createElement('div');
  msgEl.className = `message message-role-${role}`;

  const header = document.createElement('div');
  header.className = 'message-header';
  header.textContent = role === 'user' ? 'You' : role === 'assistant' ? 'Agent' : 'System';

  const body = document.createElement('div');
  body.className = 'message-content';
  body.innerHTML = role === 'user' ? escapeHtml(content).replace(/\n/g, '<br>') : renderMarkdown(content);

  msgEl.appendChild(header);

  // Add revert button for user messages
  if (role === 'user') {
    const msgIndex = conversationMessageCount;
    msgEl.dataset.msgIndex = msgIndex;
    msgEl.dataset.rawContent = content;

    const revertBtn = document.createElement('button');
    revertBtn.className = 'revert-btn';
    revertBtn.title = 'Revert to this message';
    revertBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7v6h6"/><path d="M21 17a9 9 0 0 0-9-9 9 9 0 0 0-6 2.3L3 13"/></svg>';
    revertBtn.addEventListener('click', () => revertToMessage(msgEl, msgIndex, content));

    header.appendChild(revertBtn);
  }

  msgEl.appendChild(body);
  messagesEl.appendChild(msgEl);
  scrollToBottom();

  conversationMessageCount++;
  return body;
}

function renderConversationHistory(conversation) {
  if (!conversation || conversation.length === 0) return;
  if (welcomeScreen) welcomeScreen.style.display = 'none';
  for (const msg of conversation) {
    if (msg.role === 'user' || msg.role === 'assistant') {
      addMessage(msg.role, msg.content || '');
    }
  }
  scrollToBottom();
}

function scrollToBottom() {
  chatContainer.scrollTop = chatContainer.scrollHeight;
}

function revertToMessage(msgEl, msgIndex, originalContent) {
  if (isGenerating) return;

  // Remove this message and all messages after it from the UI
  const allMessages = messagesEl.children;
  const startIndex = Array.from(allMessages).indexOf(msgEl);
  if (startIndex === -1) return;

  // Remove from startIndex onwards
  while (messagesEl.children.length > startIndex) {
    messagesEl.removeChild(messagesEl.lastChild);
  }

  // Update conversation message count
  conversationMessageCount = msgIndex;

  // Show welcome screen if no messages left
  if (messagesEl.children.length === 0 && welcomeScreen) {
    welcomeScreen.style.display = '';
  }

  // Tell background to truncate conversation
  port.postMessage({ type: MSG.PANEL_REVERT_TO, messageIndex: msgIndex });

  // Put original content back in input for editing
  chatInput.value = originalContent;
  autoResizeInput();
  chatInput.focus();
}

// ---- Chat Flow Handlers ----
function handleChatChunk(content) {
  if (!currentAssistantMessage) {
    if (welcomeScreen) welcomeScreen.style.display = 'none';
    const msgEl = document.createElement('div');
    msgEl.className = 'message message-role-assistant';

    const header = document.createElement('div');
    header.className = 'message-header';
    header.textContent = 'Agent';

    const body = document.createElement('div');
    body.className = 'message-content';

    msgEl.appendChild(header);
    msgEl.appendChild(body);
    messagesEl.appendChild(msgEl);

    currentAssistantMessage = {
      el: body,
      rawContent: '',
    };
  }

  currentAssistantMessage.rawContent += content;
  currentAssistantMessage.el.innerHTML = renderMarkdown(currentAssistantMessage.rawContent);
  scrollToBottom();
}

function handleToolStart(toolName, toolArgs, toolCallId) {
  // Finalize any current assistant message
  if (currentAssistantMessage) {
    currentAssistantMessage = null;
  }

  if (welcomeScreen) welcomeScreen.style.display = 'none';

  const toolEl = document.createElement('div');
  toolEl.className = 'tool-call';
  toolEl.dataset.toolCallId = toolCallId;

  const header = document.createElement('div');
  header.className = 'tool-call-header';

  const icon = document.createElement('span');
  icon.className = 'tool-call-icon';
  icon.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>';

  const name = document.createElement('span');
  name.className = 'tool-call-name';
  name.textContent = toolName;

  const status = document.createElement('span');
  status.className = 'tool-call-status running';
  status.textContent = 'running';

  header.appendChild(icon);
  header.appendChild(name);
  header.appendChild(status);

  const body = document.createElement('div');
  body.className = 'tool-call-body';

  const argsSection = document.createElement('div');
  argsSection.className = 'tool-call-args';
  argsSection.innerHTML = `<label>Arguments</label><pre>${escapeHtml(escapeJson(toolArgs))}</pre>`;

  const resultSection = document.createElement('div');
  resultSection.className = 'tool-call-result';
  resultSection.innerHTML = `<label>Result</label><pre class="tool-result-placeholder">Waiting...</pre>`;

  body.appendChild(argsSection);
  body.appendChild(resultSection);

  toolEl.appendChild(header);
  toolEl.appendChild(body);

  header.addEventListener('click', () => {
    body.classList.toggle('expanded');
  });

  messagesEl.appendChild(toolEl);
  currentToolCallEl = toolEl;
  scrollToBottom();
}

function handleToolResult(toolName, toolCallId, result) {
  const toolEl = messagesEl.querySelector(`[data-tool-call-id="${toolCallId}"]`) || currentToolCallEl;
  if (!toolEl) return;

  const status = toolEl.querySelector('.tool-call-status');
  status.className = `tool-call-status ${result.success ? 'success' : 'error'}`;
  status.textContent = result.success ? 'success' : 'error';

  const resultPre = toolEl.querySelector('.tool-result-placeholder');
  if (resultPre) {
    const resultText = result.success
      ? escapeJson(result.result)
      : escapeJson({ error: result.error });
    resultPre.textContent = resultText;
    resultPre.classList.remove('tool-result-placeholder');
  }

  currentToolCallEl = null;
  scrollToBottom();
}

function handleChatDone(msg) {
  if (currentAssistantMessage) {
    currentAssistantMessage = null;
  }

  if (msg.warning) {
    addMessage('assistant', `⚠️ ${msg.warning}`);
  }

  isGenerating = false;
  updateGeneratingUI();
}

function handleChatError(error) {
  if (currentAssistantMessage) {
    currentAssistantMessage = null;
  }

  const errorEl = document.createElement('div');
  errorEl.className = 'error-message';
  errorEl.textContent = error;
  messagesEl.appendChild(errorEl);
  scrollToBottom();

  isGenerating = false;
  updateGeneratingUI();
}

// ---- Models ----
function handleModelsList(models, error) {
  if (error) {
    modelList.innerHTML = `<div class="model-empty">Error: ${error}</div>`;
    return;
  }

  allModels = models || [];
  renderModelList(allModels);

  // Restore selected model
  chrome.storage.local.get(STORAGE_KEYS.SELECTED_MODEL, (data) => {
    if (data[STORAGE_KEYS.SELECTED_MODEL]) {
      selectModel(data[STORAGE_KEYS.SELECTED_MODEL]);
    }
  });
}

function renderModelList(models) {
  modelList.innerHTML = '';
  if (!models.length) {
    modelList.innerHTML = '<div class="model-empty">No models found</div>';
    return;
  }

  for (const model of models) {
    const item = document.createElement('div');
    item.className = 'model-item';
    if (model.id === selectedModelId) item.classList.add('selected');
    item.dataset.modelId = model.id;

    const name = document.createElement('div');
    name.className = 'model-item-name';
    name.textContent = model.name || model.id;

    const id = document.createElement('div');
    id.className = 'model-item-id';
    id.textContent = model.id;

    item.appendChild(name);
    item.appendChild(id);

    if (model.contextLength) {
      const ctx = document.createElement('div');
      ctx.className = 'model-item-context';
      ctx.textContent = `Context: ${(model.contextLength / 1000).toFixed(0)}K tokens`;
      item.appendChild(ctx);
    }

    item.addEventListener('click', () => {
      selectModel(model.id);
      closeDropdown();
    });

    modelList.appendChild(item);
  }
}

function filterModels(query) {
  const q = query.trim().toLowerCase();
  if (!q) {
    renderModelList(allModels);
    return;
  }
  const filtered = allModels.filter(
    (m) =>
      (m.name || '').toLowerCase().includes(q) ||
      m.id.toLowerCase().includes(q)
  );
  renderModelList(filtered);
}

function selectModel(modelId) {
  selectedModelId = modelId;
  const model = allModels.find((m) => m.id === modelId);
  if (model) {
    modelSelectedLabel.textContent = model.name || model.id;
    modelSelectedLabel.classList.remove('placeholder');
  } else {
    modelSelectedLabel.textContent = modelId;
    modelSelectedLabel.classList.remove('placeholder');
  }
  // Update selected highlight
  modelList.querySelectorAll('.model-item').forEach((el) => {
    el.classList.toggle('selected', el.dataset.modelId === modelId);
  });
  port.postMessage({ type: MSG.PANEL_SET_MODEL, model: modelId, pricing: model?.pricing || null });
}

function openDropdown() {
  modelDropdown.classList.add('open');
  modelPanel.classList.remove('hidden');
  modelSearch.value = '';
  renderModelList(allModels);
  setTimeout(() => modelSearch.focus(), 0);
}

function closeDropdown() {
  modelDropdown.classList.remove('open');
  modelPanel.classList.add('hidden');
}

function handleSettings(settings) {
  if (settings.apiKey) settingApiKey.value = settings.apiKey;
  if (settings.openaiApiKey) settingOpenaiKey.value = settings.openaiApiKey;
  if (settings.selectedModel) selectModel(settings.selectedModel);
  settingTemperature.value = settings.temperature ?? 0.7;
  tempValue.textContent = settingTemperature.value;
  if (settings.systemPrompt) settingSystemPrompt.value = settings.systemPrompt;

  // Set provider toggle
  currentProvider = settings.provider || PROVIDERS.OPENROUTER;
  updateProviderUI(currentProvider);

  // Set session cost
  if (settings.sessionCost != null) {
    updateSessionCost(settings.sessionCost, settings.sessionInputTokens, settings.sessionOutputTokens, settings.sessionCachedTokens);
  }
}

function updateProviderUI(provider) {
  currentProvider = provider;
  providerBtns.forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.provider === provider);
  });
  if (provider === PROVIDERS.OPENAI) {
    groupOpenRouterKey.classList.add('hidden');
    groupOpenaiKey.classList.remove('hidden');
  } else {
    groupOpenaiKey.classList.add('hidden');
    groupOpenRouterKey.classList.remove('hidden');
  }
}

function updateSessionCost(cost, inputTokens, outputTokens, cachedTokens) {
  const value = cost || 0;
  if (value < 0.01) {
    sessionCostEl.textContent = `$${value.toFixed(4)}`;
  } else {
    sessionCostEl.textContent = `$${value.toFixed(2)}`;
  }

  // Cache hit rate = cached prompt tokens / total prompt tokens
  const sessionCacheEl = document.getElementById('session-cache');
  if (sessionCacheEl && typeof cachedTokens === 'number' && typeof inputTokens === 'number' && inputTokens > 0) {
    const hitPct = Math.round((cachedTokens / inputTokens) * 100);
    sessionCacheEl.textContent = `⚡ ${hitPct}%`;
    sessionCacheEl.classList.remove('hidden');
    sessionCacheEl.classList.toggle('good', hitPct >= 70);
    sessionCacheEl.classList.toggle('warn', hitPct > 0 && hitPct < 50);
  }
}

// ---- UI State ----
function updateGeneratingUI() {
  if (isGenerating) {
    btnSend.classList.add('hidden');
    btnStop.classList.remove('hidden');
    chatInput.disabled = true;
  } else {
    btnSend.classList.remove('hidden');
    btnStop.classList.add('hidden');
    chatInput.disabled = false;
  }
}

function autoResizeInput() {
  chatInput.style.height = 'auto';
  chatInput.style.height = Math.min(chatInput.scrollHeight, 120) + 'px';
}

// ---- Event Handlers ----
function sendMessage() {
  const text = chatInput.value.trim();
  if (!text || isGenerating) return;

  addMessage('user', text);
  port.postMessage({ type: MSG.PANEL_SEND_CHAT, message: text });

  chatInput.value = '';
  autoResizeInput();
  isGenerating = true;
  updateGeneratingUI();
}

function stopGeneration() {
  port.postMessage({ type: MSG.PANEL_STOP_GENERATION });
  isGenerating = false;
  updateGeneratingUI();
}

function clearChat() {
  messagesEl.innerHTML = '';
  conversationMessageCount = 0;
  if (welcomeScreen) welcomeScreen.style.display = 'flex';
  port.postMessage({ type: MSG.PANEL_CLEAR_CHAT });
}

// Escape closes modal
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !settingsModal.classList.contains('hidden')) {
    settingsModal.classList.add('hidden');
  }
});

// ---- Bind Events ----
btnSend.addEventListener('click', sendMessage);
btnStop.addEventListener('click', stopGeneration);
btnClear.addEventListener('click', clearChat);

chatInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

chatInput.addEventListener('input', autoResizeInput);

modelTrigger.addEventListener('click', (e) => {
  e.stopPropagation();
  if (modelDropdown.classList.contains('open')) {
    closeDropdown();
  } else {
    openDropdown();
  }
});

modelSearch.addEventListener('input', () => {
  filterModels(modelSearch.value);
});

modelSearch.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeDropdown();
  } else if (e.key === 'Enter') {
    const firstItem = modelList.querySelector('.model-item');
    if (firstItem) {
      firstItem.click();
    }
  }
});

document.addEventListener('click', (e) => {
  if (!modelDropdown.contains(e.target)) {
    closeDropdown();
  }
});

btnRefreshModels.addEventListener('click', () => {
  modelSelectedLabel.textContent = 'Loading models...';
  modelSelectedLabel.classList.add('placeholder');
  port.postMessage({ type: MSG.PANEL_GET_MODELS });
});

// Settings modal
btnSettings.addEventListener('click', () => {
  settingsModal.classList.remove('hidden');
  port.postMessage({ type: MSG.PANEL_GET_SETTINGS });
});

btnCloseSettings.addEventListener('click', () => {
  settingsModal.classList.add('hidden');
});

settingsModal.addEventListener('click', (e) => {
  if (e.target === settingsModal) settingsModal.classList.add('hidden');
});

settingTemperature.addEventListener('input', () => {
  tempValue.textContent = settingTemperature.value;
});

btnSaveSettings.addEventListener('click', async () => {
  const apiKey = settingApiKey.value.trim();
  const openaiKey = settingOpenaiKey.value.trim();
  const temperature = parseFloat(settingTemperature.value);
  const systemPrompt = settingSystemPrompt.value.trim();

  // Save OpenRouter key
  if (apiKey) {
    await chrome.storage.local.set({ [STORAGE_KEYS.API_KEY]: apiKey });
    if (currentProvider === PROVIDERS.OPENROUTER) {
      port.postMessage({ type: MSG.PANEL_SET_API_KEY, apiKey });
    }
  }

  // Save OpenAI key
  if (openaiKey) {
    await chrome.storage.local.set({ [STORAGE_KEYS.OPENAI_API_KEY]: openaiKey });
    if (currentProvider === PROVIDERS.OPENAI) {
      port.postMessage({ type: MSG.PANEL_SET_API_KEY, apiKey: openaiKey });
    }
  }

  await chrome.storage.local.set({
    [STORAGE_KEYS.TEMPERATURE]: temperature,
    [STORAGE_KEYS.SYSTEM_PROMPT]: systemPrompt || null,
  });

  port.postMessage({ type: MSG.PANEL_SET_SYSTEM_PROMPT, systemPrompt });

  settingsModal.classList.add('hidden');
});

// Provider toggle
providerBtns.forEach((btn) => {
  btn.addEventListener('click', () => {
    const provider = btn.dataset.provider;
    if (provider === currentProvider) return;
    updateProviderUI(provider);
    port.postMessage({ type: MSG.PANEL_SET_PROVIDER, provider });
    // Clear model selection
    selectedModelId = null;
    modelSelectedLabel.textContent = 'Select a model...';
    modelSelectedLabel.classList.add('placeholder');
  });
});

// Example prompts
document.querySelectorAll('.example-prompt').forEach((btn) => {
  btn.addEventListener('click', () => {
    chatInput.value = btn.dataset.prompt;
    autoResizeInput();
    chatInput.focus();
  });
});

// ---- Initialize ----
connectPort();
port.postMessage({ type: MSG.PANEL_GET_MODELS });
port.postMessage({ type: MSG.PANEL_GET_TAB_CONTEXT });
port.postMessage({ type: MSG.PANEL_GET_CONVERSATION });

// Update tab info periodically
setInterval(() => {
  if (port) {
    port.postMessage({ type: MSG.PANEL_GET_TAB_CONTEXT });
  }
}, 5000);
