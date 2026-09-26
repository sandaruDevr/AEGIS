// OpenRouter API client - handles model listing, chat completions with tool calling, and streaming
// Cache strategy: session_id sticky routing + DeepSeek provider pinning + usage tracking

import { STORAGE_KEYS } from '../shared/constants.js';

const OPENROUTER_BASE = 'https://openrouter.ai/api/v1';
const MODELS_CACHE_KEY = 'openrouter_models_cache';
const MODELS_CACHE_TTL = 1000 * 60 * 60; // 1 hour

export class OpenRouterClient {
  constructor() {
    this.apiKey = null;
    this.selectedModel = null;
  }

  async init() {
    const stored = await chrome.storage.local.get([
      STORAGE_KEYS.API_KEY,
      STORAGE_KEYS.SELECTED_MODEL,
    ]);
    this.apiKey = stored[STORAGE_KEYS.API_KEY] || null;
    this.selectedModel = stored[STORAGE_KEYS.SELECTED_MODEL] || null;
  }

  setApiKey(key) {
    this.apiKey = key;
    return chrome.storage.local.set({ [STORAGE_KEYS.API_KEY]: key });
  }

  setSelectedModel(model) {
    this.selectedModel = model;
    return chrome.storage.local.set({ [STORAGE_KEYS.SELECTED_MODEL]: model });
  }

  hasApiKey() {
    return !!this.apiKey;
  }

  async fetchModels() {
    // Check cache first
    const cached = await chrome.storage.local.get(MODELS_CACHE_KEY);
    if (cached[MODELS_CACHE_KEY]) {
      const { timestamp, models } = cached[MODELS_CACHE_KEY];
      if (Date.now() - timestamp < MODELS_CACHE_TTL) {
        return models;
      }
    }

    const response = await fetch(`${OPENROUTER_BASE}/models`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch models: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    const models = (data.data || []).map((m) => ({
      id: m.id,
      name: m.name || m.id,
      contextLength: m.context_length,
      pricing: m.pricing,
      description: m.description,
    }));

    // Cache the results
    await chrome.storage.local.set({
      [MODELS_CACHE_KEY]: { timestamp: Date.now(), models },
    });

    return models;
  }

  async *chatStream({ messages, tools, temperature, signal, sessionId }) {
    if (!this.apiKey) {
      throw new Error('No API key set. Please set your OpenRouter API key in settings.');
    }

    const model = this.selectedModel || 'openai/gpt-4o-mini';

    const body = {
      model,
      messages,
      stream: true,
      stream_options: { include_usage: true },
      temperature: temperature ?? 0.7,
    };

    // Sticky routing: keeps requests on the same provider node so the
    // provider-side KV prompt cache stays warm (DeepSeek: up to ~1h idle TTL).
    if (sessionId) {
      body.session_id = sessionId;
    }

    // Pin deepseek/* models to the DeepSeek provider — prompt cache is
    // provider-local, so routing to a different provider invalidates it.
    if (model.startsWith('deepseek/')) {
      body.provider = { order: ['DeepSeek'], allow_fallbacks: false };
    }

    if (tools && tools.length > 0) {
      body.tools = tools;
      body.tool_choice = 'auto';
    }

    const response = await fetch(`${OPENROUTER_BASE}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
        'HTTP-Referer': 'chrome-extension://agentic-ai-web-assistant',
        'X-Title': 'Agentic AI Web Assistant',
        ...(sessionId ? { 'X-Session-ID': sessionId } : {}),
      },
      body: JSON.stringify(body),
      signal,
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorMsg = `API Error ${response.status}`;
      try {
        const errorJson = JSON.parse(errorText);
        errorMsg = errorJson.error?.message || errorMsg;
      } catch {
        errorMsg = errorText || errorMsg;
      }
      throw new Error(errorMsg);
    }

    if (!response.body) {
      throw new Error('No response body received from API.');
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || !trimmed.startsWith('data: ')) continue;

          const data = trimmed.slice(6);
          if (data === '[DONE]') {
            return;
          }

          try {
            const parsed = JSON.parse(data);
            const choice = parsed.choices?.[0];
            if (!choice && !parsed.usage) continue;

            const delta = choice?.delta;
            if (!delta && !parsed.usage) continue;

            // Log prompt-cache metrics from the final usage chunk
            if (parsed.usage) {
              const cached = parsed.usage.prompt_tokens_details?.cached_tokens || 0;
              const prompt = parsed.usage.prompt_tokens || 0;
              if (prompt > 0) {
                const pct = ((cached / prompt) * 100).toFixed(1);
                console.log(`[OpenRouter] prompt=${prompt} cached=${cached} (${pct}%) ${cached > 0 ? 'HIT' : 'MISS'}`);
              }
            }

            yield {
              content: delta?.content || '',
              toolCalls: delta?.tool_calls || null,
              finishReason: choice?.finish_reason || null,
              usage: parsed.usage || null,
            };
          } catch (e) {
            // Skip malformed JSON chunks
            continue;
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  }
}
