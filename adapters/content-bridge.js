// Content Bridge - bridges content-script.js to Playwright page.evaluate
// Reads the original content-script.js (unchanged) and wraps it with a fake
// chrome object so the IIFE runs cleanly in Playwright's page context.

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Read the original content script source (unchanged file)
const contentScriptPath = join(__dirname, '..', 'src', 'content', 'content-script.js');
const contentScriptSource = readFileSync(contentScriptPath, 'utf-8');

// Build a wrapper that:
// 1. Provides a fake `chrome` object so the IIFE doesn't crash
// 2. Runs the original IIFE (which defines toolHandlers internally)
// 3. Injects `window.__AGENT_TOOLS__ = toolHandlers;` before the IIFE closes
function prepareScript() {
  // Find the IIFE closing `})();` at the end
  const iifeCloseIdx = contentScriptSource.lastIndexOf('})();');
  if (iifeCloseIdx === -1) {
    throw new Error('Could not find IIFE closing in content-script.js');
  }

  // Insert the exposure line right before the IIFE's closing `})();`
  const beforeClose = contentScriptSource.substring(0, iifeCloseIdx);
  const afterClose = contentScriptSource.substring(iifeCloseIdx);
  const modifiedSource = beforeClose + '\n  window.__AGENT_TOOLS__ = toolHandlers;\n' + afterClose;

  // Wrap with a fake chrome object so chrome.runtime references don't throw
  // Force-merge: many sites define window.chrome without runtime.onMessage
  const wrappedScript = `
    const _fakeChrome = {
      runtime: {
        sendMessage: () => {},
        onMessage: { addListener: () => {} },
        lastError: null,
      },
    };
    try {
      if (!window.chrome) window.chrome = {};
      if (!window.chrome.runtime) window.chrome.runtime = {};
      if (!window.chrome.runtime.sendMessage) window.chrome.runtime.sendMessage = _fakeChrome.runtime.sendMessage;
      if (!window.chrome.runtime.onMessage) window.chrome.runtime.onMessage = _fakeChrome.runtime.onMessage;
      if (window.chrome.runtime.lastError === undefined) window.chrome.runtime.lastError = null;
    } catch(e) {}
    ${modifiedSource}
  `;

  return wrappedScript;
}

const _preparedScript = prepareScript();

// Inject the tool handlers into a Playwright page
export async function injectTools(page) {
  const alreadyInjected = await page.evaluate(() => !!window.__AGENT_TOOLS__).catch(() => false);
  if (alreadyInjected) return;

  // Clear the guard flag so the IIFE runs fully even if a previous attempt failed
  await page.evaluate(() => { window.__AGENT_CONTENT_SCRIPT_LOADED__ = false; }).catch(() => {});

  // Use page.evaluate — addScriptTag can be blocked by page CSP
  // The init script added in browser-pool also helps ensure the script runs
  let lastError = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await page.evaluate(_preparedScript);
      
      // Verify injection succeeded
      const verified = await page.evaluate(() => !!window.__AGENT_TOOLS__).catch(() => false);
      if (verified) return;
      
      // Tools not set — reset guard and retry
      await page.evaluate(() => { window.__AGENT_CONTENT_SCRIPT_LOADED__ = false; }).catch(() => {});
      console.warn(`[ContentBridge] Injection attempt ${attempt}: script ran but __AGENT_TOOLS__ not set, retrying...`);
    } catch (err) {
      lastError = err;
      console.warn(`[ContentBridge] Injection attempt ${attempt} failed: ${err.message}`);
    }
    // Small delay before retry
    if (attempt < 3) await new Promise(r => setTimeout(r, 200));
  }

  throw new Error(`Failed to inject content script after 3 attempts: ${lastError?.message || '__AGENT_TOOLS__ not set'}`);
}

// Execute a content script tool in the Playwright page
export async function executeToolInPage(page, toolName, args) {
  try {
    await injectTools(page);
  } catch (injectErr) {
    console.error(`[ContentBridge] injectTools failed for ${toolName}: ${injectErr.message}`);
    return { success: false, error: `Content script injection failed: ${injectErr.message}` };
  }

  try {
    const result = await page.evaluate(({ toolName, args }) => {
      const handler = window.__AGENT_TOOLS__[toolName];
      if (!handler) {
        return { success: false, error: `Unknown tool: ${toolName}` };
      }
      try {
        const result = handler(args || {});
        if (result instanceof Promise) {
          return result;
        }
        return result;
      } catch (err) {
        return { success: false, error: err.message };
      }
    }, { toolName, args });

    return result;
  } catch (evalErr) {
    console.error(`[ContentBridge] page.evaluate failed for ${toolName}: ${evalErr.message}`);
    return { success: false, error: `Page evaluation failed: ${evalErr.message}` };
  }
}
