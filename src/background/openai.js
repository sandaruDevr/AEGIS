// OpenAI API client - handles model listing, chat completions with tool calling, and streaming

import { STORAGE_KEYS } from '../shared/constants.js';

const OPENAI_BASE = 'https://api.openai.com/v1';
const MODELS_CACHE_KEY = 'openai_models_cache';
const MODELS_CACHE_TTL = 1000 * 60 * 60; // 1 hour

// Approximate pricing per 1K tokens (in USD) for common OpenAI models
// Updated periodically from OpenAI pricing page
const OPENAI_PRICING = {
  'gpt-4o': { prompt: 0.0025, completion: 0.01 },
  'gpt-4o-mini': { prompt: 0.00015, completion: 0.0006 },
  'gpt-4-turbo': { prompt: 0.01, completion: 0.03 },
  'gpt-4': { prompt: 0.03, completion: 0.06 },
  'gpt-3.5-turbo': { prompt: 0.0005, completion: 0.0015 },
  'o1': { prompt: 0.015, completion: 0.06 },
  'o1-mini': { prompt: 0.003, completion: 0.012 },
  'o1-pro': { prompt: 0.15, completion: 0.6 },
  'o3': { prompt: 0.01, completion: 0.04 },
  'o3-mini': { prompt: 0.0011, completion: 0.0044 },
  'o4-mini': { prompt: 0.0011, completion: 0.0044 },
  'gpt-4.1': { prompt: 0.002, completion: 0.008 },
  'gpt-4.1-mini': { prompt: 0.0004, completion: 0.0016 },
  'gpt-4.1-nano': { prompt: 0.0001, completion: 0.0004 },
  'gpt-4o-realtime-preview': { prompt: 0.005, completion: 0.02 },
};

export class OpenAIClient {
  constructor() {
    this.apiKey = null;
    this.selectedModel = null;
  }

  async init() {
    const stored = await chrome.storage.local.get([
      STORAGE_KEYS.OPENAI_API_KEY,
      STORAGE_KEYS.SELECTED_MODEL,
    ]);
    this.apiKey = stored[STORAGE_KEYS.OPENAI_API_KEY] || null;
    this.selectedModel = stored[STORAGE_KEYS.SELECTED_MODEL] || null;
  }

  setApiKey(key) {
    this.apiKey = key;
    return chrome.storage.local.set({ [STORAGE_KEYS.OPENAI_API_KEY]: key });
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

    if (!this.apiKey) {
      throw new Error('No OpenAI API key set. Please set your API key in settings.');
    }

    const response = await fetch(`${OPENAI_BASE}/models`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
      },
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Failed to fetch OpenAI models: ${response.status} ${errText}`);
    }

    const data = await response.json();
    // Filter to chat-capable models and map to common format
    const models = (data.data || [])
      .filter((m) => {
        const id = m.id.toLowerCase();
        return id.includes('gpt') || id.includes('o1') || id.includes('o3') || id.includes('o4');
      })
      .map((m) => {
        const pricing = OPENAI_PRICING[m.id] || { prompt: 0, completion: 0 };
        return {
          id: m.id,
          name: m.id,
          contextLength: m.context_window || null,
          pricing: {
            prompt: String(pricing.prompt / 1000), // per token
            completion: String(pricing.completion / 1000),
          },
          description: null,
        };
      })
      .sort((a, b) => a.id.localeCompare(b.id));

    await chrome.storage.local.set({
      [MODELS_CACHE_KEY]: { timestamp: Date.now(), models },
    });

    return models;
  }

  async *chatStream({ messages, tools, temperature, signal }) {
    if (!this.apiKey) {
      throw new Error('No API key set. Please set your OpenAI API key in settings.');
    }

    const body = {
      model: this.selectedModel || 'gpt-4o-mini',
      messages,
      stream: true,
      stream_options: { include_usage: true },
    };

    if (tools && tools.length > 0) {
      body.tools = tools;
      body.tool_choice = 'auto';
      // Reasoning models (e.g. gpt-5.6-luna) require reasoning_effort=none for function tools
      body.reasoning_effort = 'none';
    } else {
      // temperature only supported on non-reasoning calls
      body.temperature = temperature ?? 0.7;
    }

    const response = await fetch(`${OPENAI_BASE}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
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
            const usage = parsed.usage || null;

            if (!choice && !usage) continue;

            const delta = choice?.delta;
            if (!delta && !usage) continue;

            yield {
              content: delta?.content || '',
              toolCalls: delta?.tool_calls || null,
              finishReason: choice?.finish_reason || null,
              usage: usage,
            };
          } catch {
            continue;
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  }
}
