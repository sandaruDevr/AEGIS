// Agent loop - core agentic reasoning loop with tool calling
// Implements a ReAct-style loop: think -> act (tool call) -> observe (tool result) -> repeat

import { OpenRouterClient } from './openrouter.js';
import { OpenAIClient } from './openai.js';
import { ToolExecutor } from './tool-executor.js';
import { TOOL_DEFINITIONS } from '../tools/definitions.js';
import { MSG, STORAGE_KEYS, DEFAULT_SYSTEM_PROMPT, PROVIDERS, SAMPLE_CONVERSATION, buildContextualSystemPrompt } from '../shared/constants.js';

const MAX_TOOL_RESULT_CHARS = 6000; // Truncate tool results to minimize token usage

// Context window management for 100% prompt-cache hits:
// - Conversation is append-only (never remove from the middle) so the prefix
//   stays byte-identical across requests and the KV cache grows every turn.
// - Head-trim (oldest first) ONLY when approaching the model's context limit.
//   This causes a single cache miss, after which the new prefix re-caches.
// - No summarizer: summaries rewrite the prefix and destroy the cache.
const MAX_CONTEXT_TOKENS = 800_000; // Hard cap (DeepSeek: 1M window, 200K headroom for output)
const CHARS_PER_TOKEN = 4;
const MAX_CONTEXT_CHARS = MAX_CONTEXT_TOKENS * CHARS_PER_TOKEN;

export class AgentLoop {
  constructor() {
    this.openrouterClient = new OpenRouterClient();
    this.openaiClient = new OpenAIClient();
    this.client = this.openrouterClient;
    this.provider = PROVIDERS.OPENROUTER;
    this.executor = new ToolExecutor();
    this.conversation = [];
    this.systemPrompt = DEFAULT_SYSTEM_PROMPT;
    this.activeSystemPrompt = DEFAULT_SYSTEM_PROMPT;
    this.temperature = 0.7;
    this.abortController = null;
    this.panelPort = null;
    this.sessionCost = 0;
    this.sessionInputTokens = 0;
    this.sessionOutputTokens = 0;
    this.sessionCachedTokens = 0;
    this.modelPricing = null;
    this.initialConversationLength = 0;
    this.sessionId = null;
    this.sessions = [];          // [{id, title, createdAt, updatedAt}]
    this.activeSessionId = null;
    this._initialized = false;
  }

  async init() {
    const stored = await chrome.storage.local.get([
      STORAGE_KEYS.SYSTEM_PROMPT,
      STORAGE_KEYS.TEMPERATURE,
      STORAGE_KEYS.CONVERSATION,
      STORAGE_KEYS.PROVIDER,
      STORAGE_KEYS.SESSION_COST,
      STORAGE_KEYS.SESSION_INPUT_TOKENS,
      STORAGE_KEYS.SESSION_OUTPUT_TOKENS,
      STORAGE_KEYS.SESSION_CACHED_TOKENS,
      STORAGE_KEYS.CUSTOM_INPUT_PRICE,
      STORAGE_KEYS.CUSTOM_OUTPUT_PRICE,
      STORAGE_KEYS.INITIAL_CONVERSATION,
      STORAGE_KEYS.SESSIONS_INDEX,
      STORAGE_KEYS.ACTIVE_SESSION_ID,
    ]);
    this.provider = stored[STORAGE_KEYS.PROVIDER] || PROVIDERS.OPENROUTER;
    this.systemPrompt = stored[STORAGE_KEYS.SYSTEM_PROMPT] || DEFAULT_SYSTEM_PROMPT;
    this.temperature = stored[STORAGE_KEYS.TEMPERATURE] ?? 0.7;
    this.sessionCost = stored[STORAGE_KEYS.SESSION_COST] || 0;
    this.sessionInputTokens = stored[STORAGE_KEYS.SESSION_INPUT_TOKENS] || 0;
    this.sessionOutputTokens = stored[STORAGE_KEYS.SESSION_OUTPUT_TOKENS] || 0;
    this.sessionCachedTokens = stored[STORAGE_KEYS.SESSION_CACHED_TOKENS] || 0;
    this.sessionId = this._generateSessionId();
    // Load custom pricing if set (overrides model-list pricing)
    const customIn = stored[STORAGE_KEYS.CUSTOM_INPUT_PRICE];
    const customOut = stored[STORAGE_KEYS.CUSTOM_OUTPUT_PRICE];
    if (customIn != null || customOut != null) {
      this.modelPricing = {
        prompt: customIn != null ? String(customIn / 1000) : '0',
        completion: customOut != null ? String(customOut / 1000) : '0',
      };
    }
    if (stored[STORAGE_KEYS.CONVERSATION]) {
      this.conversation = stored[STORAGE_KEYS.CONVERSATION];
      this.initialConversationLength = this.conversation.filter(m => m._initial).length;
      // If stored conversation has no _initial messages (saved before feature), prepend sample
      if (this.initialConversationLength === 0) {
        const initialData = stored[STORAGE_KEYS.INITIAL_CONVERSATION];
        const sample = (initialData && Array.isArray(initialData) && initialData.length > 0)
          ? initialData : SAMPLE_CONVERSATION;
        const initialMsgs = [];
        for (const turn of sample) {
          if (turn.user) initialMsgs.push({ role: 'user', content: turn.user, _initial: true });
          if (turn.you) initialMsgs.push({ role: 'assistant', content: turn.you, _initial: true });
        }
        this.conversation = [...initialMsgs, ...this.conversation];
        this.initialConversationLength = initialMsgs.length;
        this._saveConversation();
      }
      // Rebuild active system prompt from initial messages
      const initialTurns = this._extractInitialTurns();
      this.activeSystemPrompt = initialTurns.length > 0
        ? buildContextualSystemPrompt(this.systemPrompt, initialTurns)
        : this.systemPrompt;
    } else {
      const initialData = stored[STORAGE_KEYS.INITIAL_CONVERSATION];
      if (initialData && Array.isArray(initialData) && initialData.length > 0) {
        this.loadInitialConversation(initialData);
      } else {
        this.loadInitialConversation(SAMPLE_CONVERSATION);
      }
    }
    await this._initSessions(stored);
    await this._switchProvider(this.provider);
    this._initialized = true;
  }

  async ensureInitialized() {
    if (!this._initialized) {
      await this.init();
    }
  }

  async _switchProvider(provider) {
    this.provider = provider;
    if (provider === PROVIDERS.OPENAI) {
      this.client = this.openaiClient;
    } else {
      this.client = this.openrouterClient;
    }
    await this.client.init();
    await chrome.storage.local.set({ [STORAGE_KEYS.PROVIDER]: provider });
    this.modelPricing = null;
  }

  setModelPricing(pricing) {
    this.modelPricing = pricing;
  }

  setSystemPrompt(prompt) {
    this.systemPrompt = prompt || DEFAULT_SYSTEM_PROMPT;
    const initialTurns = this._extractInitialTurns();
    this.activeSystemPrompt = initialTurns.length > 0
      ? buildContextualSystemPrompt(this.systemPrompt, initialTurns)
      : this.systemPrompt;
  }

  _calculateCost(usage) {
    if (!usage || !this.modelPricing) return 0;
    const promptTokens = usage.prompt_tokens || 0;
    const completionTokens = usage.completion_tokens || 0;
    const promptCost = parseFloat(this.modelPricing.prompt || 0) * promptTokens;
    const completionCost = parseFloat(this.modelPricing.completion || 0) * completionTokens;
    return promptCost + completionCost;
  }

  _addCost(cost, usage) {
    if (cost <= 0 && !usage) return;
    this.sessionCost += cost;
    if (usage) {
      this.sessionInputTokens += usage.prompt_tokens || 0;
      this.sessionOutputTokens += usage.completion_tokens || 0;
      this.sessionCachedTokens += usage.prompt_tokens_details?.cached_tokens || 0;
    }
    chrome.storage.local.set({
      [STORAGE_KEYS.SESSION_COST]: this.sessionCost,
      [STORAGE_KEYS.SESSION_INPUT_TOKENS]: this.sessionInputTokens,
      [STORAGE_KEYS.SESSION_OUTPUT_TOKENS]: this.sessionOutputTokens,
      [STORAGE_KEYS.SESSION_CACHED_TOKENS]: this.sessionCachedTokens,
    });
    this._sendToPanel(MSG.BG_SESSION_COST, {
      cost: this.sessionCost,
      inputTokens: this.sessionInputTokens,
      outputTokens: this.sessionOutputTokens,
      cachedTokens: this.sessionCachedTokens,
    });
  }

  setPanelPort(port) {
    this.panelPort = port;
  }

  _sendToPanel(type, data) {
    if (this.panelPort) {
      try {
        this.panelPort.postMessage({ type, ...data });
      } catch (e) {
        // Port may be disconnected
      }
    }
  }

  async _getActiveTabId() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0]?.id || null;
  }

  async _saveConversation() {
    // Persist the full conversation — truncating here would silently shrink
    // the prompt prefix after a restart and cause a cache miss.
    await chrome.storage.local.set({ [STORAGE_KEYS.CONVERSATION]: this.conversation });
    // Also persist under the active session key (multi-session support)
    if (this.activeSessionId) {
      await this._persistActiveSession();
      this._touchSession(this.activeSessionId);
    }
  }

  // ---- Multi-Session Management ----
  // Each session stores its own conversation + token/cost stats + its own
  // OpenRouter routing session_id, so switching back to a session restores
  // the exact prompt prefix (KV cache still hits) and sticky routing.

  _sessionDataKey(id) {
    return `${STORAGE_KEYS.SESSION_DATA_PREFIX}${id}`;
  }

  async _initSessions(stored) {
    this.sessions = stored[STORAGE_KEYS.SESSIONS_INDEX] || [];
    const activeId = stored[STORAGE_KEYS.ACTIVE_SESSION_ID];

    if (this.sessions.length === 0) {
      // First run (or pre-sessions install): wrap the current conversation
      // as the first session so nothing is lost.
      const session = {
        id: this._generateSessionId(),
        title: this._deriveSessionTitle(this.conversation),
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
      this.sessions = [session];
      this.activeSessionId = session.id;
      await this._persistSessionsIndex();
      await this._persistActiveSession();
      await chrome.storage.local.set({ [STORAGE_KEYS.ACTIVE_SESSION_ID]: this.activeSessionId });
      return;
    }

    // Load the active session (fall back to the most recently updated)
    let target = this.sessions.find(s => s.id === activeId);
    if (!target) target = this.sessions.slice().sort((a, b) => b.updatedAt - a.updatedAt)[0];
    await this._loadSessionData(target.id);
  }

  _deriveSessionTitle(conversation) {
    const firstUser = conversation.find(m => m.role === 'user' && !m._initial);
    const text = (firstUser?.content || '').replace(/\s+/g, ' ').trim();
    return text ? (text.length > 40 ? `${text.slice(0, 40)}…` : text) : 'New session';
  }

  async _persistSessionsIndex() {
    await chrome.storage.local.set({ [STORAGE_KEYS.SESSIONS_INDEX]: this.sessions });
  }

  async _persistActiveSession() {
    await chrome.storage.local.set({
      [this._sessionDataKey(this.activeSessionId)]: {
        conversation: this.conversation,
        initialConversationLength: this.initialConversationLength,
        sessionCost: this.sessionCost,
        sessionInputTokens: this.sessionInputTokens,
        sessionOutputTokens: this.sessionOutputTokens,
        sessionCachedTokens: this.sessionCachedTokens,
        openrouterSessionId: this.sessionId,
      },
    });
  }

  async _loadSessionData(id) {
    const key = this._sessionDataKey(id);
    const stored = await chrome.storage.local.get([key]);
    const data = stored[key];
    this.activeSessionId = id;
    await chrome.storage.local.set({ [STORAGE_KEYS.ACTIVE_SESSION_ID]: id });

    if (data && Array.isArray(data.conversation)) {
      this.conversation = data.conversation;
      this.initialConversationLength = this.conversation.filter(m => m._initial).length;
      this.sessionCost = data.sessionCost || 0;
      this.sessionInputTokens = data.sessionInputTokens || 0;
      this.sessionOutputTokens = data.sessionOutputTokens || 0;
      this.sessionCachedTokens = data.sessionCachedTokens || 0;
      // Reuse the stored routing session id so the provider-side KV cache
      // prefix and sticky routing survive session switches.
      this.sessionId = data.openrouterSessionId || this._generateSessionId();
    } else {
      // Empty session
      this.conversation = [];
      this.initialConversationLength = 0;
      this.sessionCost = 0;
      this.sessionInputTokens = 0;
      this.sessionOutputTokens = 0;
      this.sessionCachedTokens = 0;
      this.sessionId = this._generateSessionId();
      await this._persistActiveSession();
    }

    // Rebuild active system prompt from this session's initial messages
    const initialTurns = this._extractInitialTurns();
    this.activeSystemPrompt = initialTurns.length > 0
      ? buildContextualSystemPrompt(this.systemPrompt, initialTurns)
      : this.systemPrompt;
  }

  listSessions() {
    return {
      sessions: this.sessions.slice().sort((a, b) => b.updatedAt - a.updatedAt),
      activeSessionId: this.activeSessionId,
    };
  }

  async createSession(title) {
    await this._saveConversation(); // flush current session first
    const session = {
      id: this._generateSessionId(),
      title: title || 'New session',
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    this.sessions.push(session);
    await this._persistSessionsIndex();

    // Reset in-memory state for the fresh session
    this.activeSessionId = session.id;
    await chrome.storage.local.set({ [STORAGE_KEYS.ACTIVE_SESSION_ID]: session.id });
    this.conversation = [];
    this.initialConversationLength = 0;
    this.activeSystemPrompt = this.systemPrompt;
    this.sessionId = this._generateSessionId();
    this.sessionCost = 0;
    this.sessionInputTokens = 0;
    this.sessionOutputTokens = 0;
    this.sessionCachedTokens = 0;
    await this._persistActiveSession();
    return session;
  }

  async switchSession(id) {
    if (!this.sessions.some(s => s.id === id)) {
      throw new Error(`Session ${id} not found`);
    }
    if (this.abortController) this.stop();
    // Save the session we're leaving
    if (this.activeSessionId) {
      await this._persistActiveSession();
      this._touchSession(this.activeSessionId);
    }
    await this._loadSessionData(id);
    return this.getConversationForPanel();
  }

  async deleteSession(id) {
    const wasActive = id === this.activeSessionId;
    this.sessions = this.sessions.filter(s => s.id !== id);
    await chrome.storage.local.remove(this._sessionDataKey(id));

    if (this.sessions.length === 0) {
      // Detach before creating the replacement so createSession's flush
      // doesn't re-persist the just-deleted session's data.
      this.activeSessionId = null;
      await this.createSession();
    } else if (wasActive) {
      const next = this.sessions.slice().sort((a, b) => b.updatedAt - a.updatedAt)[0];
      await this._loadSessionData(next.id);
    }
    await this._persistSessionsIndex();
    await chrome.storage.local.set({ [STORAGE_KEYS.ACTIVE_SESSION_ID]: this.activeSessionId });
    return this.getConversationForPanel();
  }

  async renameSession(id, title) {
    const session = this.sessions.find(s => s.id === id);
    if (session && title) {
      session.title = String(title).trim().slice(0, 80);
      session.renamed = true;
      await this._persistSessionsIndex();
    }
  }

  _touchSession(id) {
    const session = this.sessions.find(s => s.id === id);
    if (!session) return;
    session.updatedAt = Date.now();
    // Auto-title from the first user message until renamed/explicitly titled
    if (!session.renamed) {
      const title = this._deriveSessionTitle(this.conversation);
      if (title && title !== 'New session') session.title = title;
    }
    this._persistSessionsIndex();
  }

  _truncateToolResult(result) {
    let json = JSON.stringify(result);
    if (json.length <= MAX_TOOL_RESULT_CHARS) return json;

    // For tool results with large stdout/stderr, summarize intelligently
    if (result && typeof result === 'object') {
      const summarized = this._summarizeToolResult(result);
      const summarizedJson = JSON.stringify(summarized);
      if (summarizedJson.length <= MAX_TOOL_RESULT_CHARS) return summarizedJson;
      json = summarizedJson;
    }

    // Last resort: truncate middle, preserve start and end
    const keep = Math.floor(MAX_TOOL_RESULT_CHARS / 2);
    return json.substring(0, keep)
      + `\n... [TRUNCATED: ${json.length} chars -> ${keep}+${keep}] ...\n`
      + json.substring(json.length - keep);
  }

  _summarizeToolResult(result) {
    if (!result || typeof result !== 'object') return result;
    const summarized = { ...result };

    // Truncate long string fields (stdout, stderr, content, html, etc.)
    const FIELDS = ['stdout', 'stderr', 'content', 'html', 'text', 'result', 'outerHTML', 'innerHTML'];
    for (const field of FIELDS) {
      if (typeof summarized[field] === 'string' && summarized[field].length > 2000) {
        const val = summarized[field];
        summarized[field] = val.substring(0, 1500)
          + `\n... [${val.length} chars total, truncated] ...\n`
          + val.substring(val.length - 500);
      }
    }

    // Truncate arrays of objects (e.g., query_selector_all results, form fields)
    for (const key of Object.keys(summarized)) {
      if (Array.isArray(summarized[key]) && summarized[key].length > 20) {
        summarized[key] = summarized[key].slice(0, 20);
        summarized[`_${key}_truncated`] = true;
        summarized[`_${key}_total`] = result[key].length;
      }
    }

    return summarized;
  }

  _conversationChars() {
    return this.conversation.reduce((sum, msg) => {
      return sum + (typeof msg.content === 'string' ? msg.content.length : 0)
        + (msg.tool_calls ? JSON.stringify(msg.tool_calls).length : 0);
    }, 0);
  }

  _generateSessionId() {
    // crypto.randomUUID() is available in service workers and Node >= 19
    if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
    return `sess-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  }

  // Head-trim oldest non-initial messages when the conversation exceeds the
  // context cap. Never removes from the middle — messages are append-only, so
  // the prompt prefix stays byte-identical across requests and the provider's
  // KV cache hits on every turn. Trimming the head causes exactly one cache
  // miss, after which the new prefix re-caches.
  _enforceContextLimit() {
    let totalChars = this._conversationChars();
    if (totalChars <= MAX_CONTEXT_CHARS) return;

    let removed = 0;
    while (totalChars > MAX_CONTEXT_CHARS && this.conversation.length > this.initialConversationLength + 2) {
      const removedMsg = this.conversation.splice(this.initialConversationLength, 1)[0];
      totalChars -= (typeof removedMsg.content === 'string' ? removedMsg.content.length : 0)
        + (removedMsg.tool_calls ? JSON.stringify(removedMsg.tool_calls).length : 0);
      removed++;
    }
    if (removed > 0) {
      console.log(`[Agent] Context cap (${MAX_CONTEXT_TOKENS} tokens) reached — head-trimmed ${removed} oldest message(s); cache re-warms on next request`);
    }
  }

  async _getTabContext() {
    const tabId = await this._getActiveTabId();
    if (!tabId) return null;

    try {
      const tab = await chrome.tabs.get(tabId);
      return {
        url: tab.url,
        title: tab.title,
      };
    } catch {
      return null;
    }
  }

  stop() {
    if (this.abortController) {
      this.abortController.abort();
    }
  }

  loadInitialConversation(sampleData) {
    if (!Array.isArray(sampleData) || sampleData.length === 0) return;
    this.conversation = [];
    for (const turn of sampleData) {
      if (turn.user) {
        this.conversation.push({ role: 'user', content: turn.user, _initial: true });
      }
      if (turn.you) {
        this.conversation.push({ role: 'assistant', content: turn.you, _initial: true });
      }
    }
    this.initialConversationLength = this.conversation.length;
    this.activeSystemPrompt = buildContextualSystemPrompt(this.systemPrompt, sampleData);
    this._saveConversation();
  }

  _extractInitialTurns() {
    const initialMsgs = this.conversation.filter(m => m._initial);
    const turns = [];
    let turnNum = 0;
    let currentTurn = null;
    for (const msg of initialMsgs) {
      if (msg.role === 'user') {
        if (currentTurn) turns.push(currentTurn);
        turnNum++;
        currentTurn = { turn: turnNum, user: msg.content, you: '' };
      } else if (msg.role === 'assistant' && currentTurn) {
        currentTurn.you = msg.content;
      }
    }
    if (currentTurn) turns.push(currentTurn);
    return turns;
  }

  getConversationForPanel() {
    return this.conversation.map((msg) => ({
      role: msg.role,
      content: msg.content,
    }));
  }

  clearConversation() {
    this.conversation = [];
    this.initialConversationLength = 0;
    this.activeSystemPrompt = this.systemPrompt;
    this.sessionId = this._generateSessionId();
    this.sessionCost = 0;
    this.sessionInputTokens = 0;
    this.sessionOutputTokens = 0;
    this.sessionCachedTokens = 0;
    chrome.storage.local.remove(STORAGE_KEYS.CONVERSATION);
    chrome.storage.local.set({
      [STORAGE_KEYS.SESSION_COST]: 0,
      [STORAGE_KEYS.SESSION_INPUT_TOKENS]: 0,
      [STORAGE_KEYS.SESSION_OUTPUT_TOKENS]: 0,
      [STORAGE_KEYS.SESSION_CACHED_TOKENS]: 0,
    });
    // Clear the active session's stored data too
    if (this.activeSessionId) {
      this._persistActiveSession();
      this._touchSession(this.activeSessionId);
    }
    this._sendToPanel(MSG.BG_SESSION_COST, { cost: 0, inputTokens: 0, outputTokens: 0, cachedTokens: 0 });
  }

  async revertTo(messageIndex) {
    // Never revert below the initial conversation
    const minIndex = this.initialConversationLength;
    const targetIndex = Math.max(messageIndex, minIndex);
    this.conversation = this.conversation.slice(0, targetIndex);
    await this._saveConversation();
  }

  async run(userMessage) {
    if (!this.client.hasApiKey()) {
      const providerName = this.provider === PROVIDERS.OPENAI ? 'OpenAI' : 'OpenRouter';
      this._sendToPanel(MSG.BG_CHAT_ERROR, {
        error: `No ${providerName} API key set. Click the settings icon to add your API key.`,
      });
      return;
    }

    // Set active tab for tool execution
    const tabId = await this._getActiveTabId();
    this.executor.setTabId(tabId);

    // Inject current page context into the user message
    const tabContext = await this._getTabContext();
    let contextMessage = userMessage;
    if (tabContext) {
      contextMessage = `[Current Page Context]\nURL: ${tabContext.url}\nTitle: ${tabContext.title}\n\n[User Request]\n${userMessage}`;
    }

    // Add user message to conversation
    this.conversation.push({ role: 'user', content: contextMessage });

    this.abortController = new AbortController();
    const runSessionId = this.activeSessionId;

    console.log(`[Agent] Starting run with provider=${this.provider}, model=${this.client.selectedModel || 'default'}`);
    try {
      await this._agentLoop();
    } catch (err) {
      console.error(`[Agent] Error: ${err.message}`);
      if (err.name === 'AbortError') {
        this._sendToPanel(MSG.BG_CHAT_DONE, { stopped: true });
      } else {
        this._sendToPanel(MSG.BG_CHAT_ERROR, { error: err.message });
      }
    } finally {
      this.abortController = null;
      // Guard against session switch race: if the user switched sessions while
      // this run was aborting, the in-memory conversation now belongs to the
      // other session — persisting it here would copy it into the wrong one.
      if (this.activeSessionId === runSessionId) {
        await this._saveConversation();
      }
    }
  }

  async _agentLoop() {
    // No tool-round limit: the loop runs until the model stops calling tools,
    // errors, or the user aborts (stop()). Context cap is enforced each round.
    let round = 0;
    while (true) {
      round++;
      console.log(`[Agent] Round ${round}, conversation length=${this.conversation.length}`);
      // Enforce context cap before each round (head-trim only when over limit)
      this._enforceContextLimit();

      const messages = [
        { role: 'system', content: this.activeSystemPrompt },
        ...this.conversation.map(msg => {
          const clean = { role: msg.role, content: msg.content };
          if (msg.tool_calls) clean.tool_calls = msg.tool_calls;
          if (msg.tool_call_id) clean.tool_call_id = msg.tool_call_id;
          return clean;
        }),
      ];

      let assistantMessage = {
        role: 'assistant',
        content: '',
        tool_calls: [],
      };

      let contentBuffer = '';
      let toolCallsBuffer = [];
      let finishReason = null;

      // Stream the response
      const stream = this.client.chatStream({
        messages,
        tools: TOOL_DEFINITIONS,
        temperature: this.temperature,
        sessionId: this.sessionId,
        signal: this.abortController.signal,
      });

      for await (const chunk of stream) {
        if (chunk.content) {
          contentBuffer += chunk.content;
          this._sendToPanel(MSG.BG_CHAT_CHUNK, { content: chunk.content });
        }

        if (chunk.toolCalls) {
          for (const tc of chunk.toolCalls) {
            const idx = tc.index ?? 0;
            if (!toolCallsBuffer[idx]) {
              toolCallsBuffer[idx] = {
                id: tc.id || `call_${round}_${idx}`,
                type: 'function',
                function: { name: '', arguments: '' },
              };
            }
            if (tc.function?.name) {
              toolCallsBuffer[idx].function.name += tc.function.name;
            }
            if (tc.function?.arguments) {
              toolCallsBuffer[idx].function.arguments += tc.function.arguments;
            }
          }
        }

        if (chunk.finishReason) {
          finishReason = chunk.finishReason;
        }

        if (chunk.usage) {
          const cost = this._calculateCost(chunk.usage);
          this._addCost(cost, chunk.usage);
        }
      }

      // Finalize assistant message
      const finalizedToolCalls = toolCallsBuffer.filter(Boolean);
      assistantMessage.content = contentBuffer || null;
      if (finalizedToolCalls.length > 0) {
        assistantMessage.tool_calls = finalizedToolCalls;
      } else {
        delete assistantMessage.tool_calls;
      }

      // Add assistant message to conversation
      this.conversation.push(assistantMessage);

      // If no tool calls, we're done
      if (!finalizedToolCalls.length) {
        console.log(`[Agent] Completed after round ${round + 1} (finishReason=${finishReason})`);
        this._sendToPanel(MSG.BG_CHAT_DONE, { stopped: false });
        return;
      }

      // Execute tool calls
      console.log(`[Agent] ${finalizedToolCalls.length} tool call(s) in round ${round + 1}`);
      for (const toolCall of toolCallsBuffer.filter(Boolean)) {
        const toolName = toolCall.function.name;
        let toolArgs = {};

        try {
          toolArgs = JSON.parse(toolCall.function.arguments || '{}');
        } catch {
          toolArgs = {};
        }

        // Unwrap universal execute_tool call -> extract real tool name + params
        let realToolName = toolName;
        let realToolArgs = toolArgs;
        if (toolName === 'execute_tool') {
          realToolName = toolArgs.tool_name || '';
          realToolArgs = toolArgs.parameters || {};
          if (!realToolName) {
            const result = { success: false, error: 'No tool_name provided in execute_tool call.' };
            this.conversation.push({
              role: 'tool',
              tool_call_id: toolCall.id,
              content: JSON.stringify(result),
            });
            continue;
          }
        }

        console.log(`[Agent] Tool: ${realToolName}`, JSON.stringify(realToolArgs).substring(0, 200));
        this._sendToPanel(MSG.BG_TOOL_START, {
          toolName: realToolName,
          toolArgs: realToolArgs,
          toolCallId: toolCall.id,
        });

        const result = await this.executor.executeTool(realToolName, realToolArgs);
        console.log(`[Agent] Tool ${realToolName} result: ${result.success ? 'success' : 'error'}`);

        this._sendToPanel(MSG.BG_TOOL_RESULT, {
          toolName: realToolName,
          toolCallId: toolCall.id,
          result,
        });

        // Add tool result to conversation (truncated to prevent context overflow)
        let toolContent;
        if (realToolName === 'execute_workflow') {
          toolContent = result.success ? result.results : { error: result.error };
          if (result.summary) toolContent = { ...toolContent, _summary: result.summary };
        } else {
          toolContent = result.success ? result.result : { error: result.error };
        }
        const truncatedContent = this._truncateToolResult(toolContent);
        this.conversation.push({
          role: 'tool',
          tool_call_id: toolCall.id,
          content: truncatedContent,
        });

        // Anti-detection: random jitter between tool calls (500ms-2s)
        const jitter = 500 + Math.floor(Math.random() * 1500);
        await new Promise(r => setTimeout(r, jitter));
      }

      // Strip large content params from write_file/edit_file tool calls AFTER execution
      // to save tokens in history without affecting actual tool execution
      for (const tc of finalizedToolCalls) {
        if (tc.function?.arguments) {
          try {
            const args = JSON.parse(tc.function.arguments);
            if ((args.tool_name === 'write_file' || (args.tool_name === 'execute_tool' && args.parameters?.tool_name === 'write_file')) && args.parameters?.content) {
              const contentLen = args.parameters.content.length;
              if (contentLen > 200) {
                args.parameters.content = `[${contentLen} chars written to file — omitted from history]`;
                tc.function.arguments = JSON.stringify(args);
              }
            }
            if ((args.tool_name === 'edit_file' || (args.tool_name === 'execute_tool' && args.parameters?.tool_name === 'edit_file')) && args.parameters?.new_string) {
              const newStrLen = args.parameters.new_string.length;
              if (newStrLen > 200) {
                args.parameters.new_string = `[${newStrLen} chars — omitted from history]`;
                tc.function.arguments = JSON.stringify(args);
              }
            }
            // Strip large script code from workflow nodes in history
            if (args.workflow?.nodes) {
              for (const node of args.workflow.nodes) {
                if (node.tool === 'script' && node.params?.code && node.params.code.length > 200) {
                  const codeLen = node.params.code.length;
                  node.params.code = `[${codeLen} chars of script code — omitted from history]`;
                }
              }
              tc.function.arguments = JSON.stringify(args);
            }
          } catch {}
        }
      }

      // Enforce context cap if tool results pushed it over the limit
      this._enforceContextLimit();

      // Continue the loop for the next round (LLM will process tool results)
    }
  }
}
