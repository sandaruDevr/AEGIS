// Background service worker - entry point for the extension
// Handles messaging between side panel and agent loop

import { AgentLoop } from './agent-loop.js';
import { MSG, STORAGE_KEYS, PROVIDERS } from '../shared/constants.js';

const agent = new AgentLoop();

// Initialize on startup
chrome.runtime.onInstalled.addListener(async () => {
  await agent.init();
  if (chrome.sidePanel?.setPanelBehavior) {
    await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
  }
});

chrome.runtime.onStartup.addListener(async () => {
  await agent.init();
});

// Handle action click - open side panel
chrome.action.onClicked.addListener((tab) => {
  if (chrome.sidePanel?.open) {
    chrome.sidePanel.open({ tabId: tab.id });
  }
});

// Handle connections from side panel
chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'agent-panel') {
    agent.setPanelPort(port);
    agent.ensureInitialized();

    port.onMessage.addListener(async (msg) => {
      await agent.ensureInitialized();
      switch (msg.type) {
        case MSG.PANEL_SEND_CHAT:
          await agent.run(msg.message);
          break;

        case MSG.PANEL_STOP_GENERATION:
          agent.stop();
          break;

        case MSG.PANEL_CLEAR_CHAT:
          agent.clearConversation();
          break;

        case MSG.PANEL_REVERT_TO:
          await agent.revertTo(msg.messageIndex);
          break;

        case MSG.PANEL_GET_MODELS:
          try {
            await agent.client.init();
            const models = await agent.client.fetchModels();
            port.postMessage({ type: MSG.BG_MODELS_LIST, models });
          } catch (err) {
            port.postMessage({ type: MSG.BG_MODELS_LIST, error: err.message });
          }
          break;

        case MSG.PANEL_SET_PROVIDER:
          await agent._switchProvider(msg.provider);
          await agent.client.setSelectedModel(null);
          try {
            const models = await agent.client.fetchModels();
            port.postMessage({ type: MSG.BG_MODELS_LIST, models });
          } catch (err) {
            port.postMessage({ type: MSG.BG_MODELS_LIST, error: err.message });
          }
          break;

        case MSG.PANEL_SET_MODEL:
          await agent.client.setSelectedModel(msg.model);
          if (msg.pricing) {
            agent.setModelPricing(msg.pricing);
          }
          break;

        case MSG.PANEL_SET_API_KEY:
          await agent.client.setApiKey(msg.apiKey);
          break;

        case MSG.PANEL_SET_SYSTEM_PROMPT:
          agent.setSystemPrompt(msg.systemPrompt);
          break;

        case MSG.PANEL_GET_SETTINGS:
          await agent.client.init();
          const stored = await chrome.storage.local.get([
            STORAGE_KEYS.API_KEY,
            STORAGE_KEYS.OPENAI_API_KEY,
            STORAGE_KEYS.SELECTED_MODEL,
            STORAGE_KEYS.TEMPERATURE,
            STORAGE_KEYS.SYSTEM_PROMPT,
            STORAGE_KEYS.PROVIDER,
            STORAGE_KEYS.SESSION_COST,
          ]);
          port.postMessage({
            type: MSG.BG_SETTINGS,
            settings: {
              apiKey: stored[STORAGE_KEYS.API_KEY] || '',
              openaiApiKey: stored[STORAGE_KEYS.OPENAI_API_KEY] || '',
              selectedModel: stored[STORAGE_KEYS.SELECTED_MODEL] || '',
              temperature: stored[STORAGE_KEYS.TEMPERATURE] ?? 0.7,
              systemPrompt: stored[STORAGE_KEYS.SYSTEM_PROMPT] || '',
              hasApiKey: !!stored[STORAGE_KEYS.API_KEY],
              provider: stored[STORAGE_KEYS.PROVIDER] || PROVIDERS.OPENROUTER,
              sessionCost: stored[STORAGE_KEYS.SESSION_COST] || 0,
            },
          });
          // Also send current session cost + cache stats
          port.postMessage({
            type: MSG.BG_SESSION_COST,
            cost: agent.sessionCost,
            inputTokens: agent.sessionInputTokens,
            outputTokens: agent.sessionOutputTokens,
            cachedTokens: agent.sessionCachedTokens,
          });
          break;

        case MSG.PANEL_GET_CONVERSATION:
          port.postMessage({
            type: MSG.BG_CONVERSATION_HISTORY,
            conversation: agent.getConversationForPanel(),
          });
          break;

        case MSG.PANEL_GET_TAB_CONTEXT:
          const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
          if (tabs[0]) {
            port.postMessage({
              type: MSG.BG_TAB_CONTEXT,
              context: { url: tabs[0].url, title: tabs[0].title },
            });
          }
          break;
      }
    });

    port.onDisconnect.addListener(() => {
      agent.setPanelPort(null);
    });
  }
});

// Handle content script messages
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === MSG.CS_PAGE_READY && sender.tab) {
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === 'CAPTURE_SCREENSHOT' && sender.tab) {
    chrome.tabs.captureVisibleTab(sender.tab.windowId, { format: 'png' })
      .then((dataUrl) => {
        sendResponse({ success: true, result: dataUrl });
      })
      .catch((err) => {
        sendResponse({ success: false, error: err.message });
      });
    return true; // Keep channel open for async
  }

  return true;
});
