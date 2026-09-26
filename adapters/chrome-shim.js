// Chrome API Shim - provides chrome.* API surface in Node.js
// This allows agent-loop.js, openrouter.js, openai.js, and tool-executor.js
// to work unchanged in a Node.js server environment.
//
// Supported APIs:
// - chrome.storage.local.get/set/remove (in-memory + file persistence)
// - chrome.tabs.query/get (Playwright browser pool)
// - chrome.tabs.sendMessage (content bridge via Playwright)
// - chrome.scripting.executeScript (Playwright page.evaluate)
// - chrome.runtime.connectNative (child_process for WSL2)
// - chrome.cookies.getAll (Playwright context cookies)
// - chrome.downloads.download (fs.writeFile)
// - chrome.tabs.captureVisibleTab (Playwright screenshot)
// - chrome.runtime.lastError (error tracking)

import { writeFileSync, readFileSync, existsSync, mkdirSync, unlinkSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { exec as execCb, spawn } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(execCb);
const __dirname = dirname(fileURLToPath(import.meta.url));

// ---- Storage Layer ----
const STORAGE_FILE = join(__dirname, '..', 'data', 'storage.json');
const _memoryStore = {};

function _loadStorage() {
  try {
    if (existsSync(STORAGE_FILE)) {
      const data = readFileSync(STORAGE_FILE, 'utf-8');
      Object.assign(_memoryStore, JSON.parse(data));
    }
  } catch {
    // Start fresh
  }
}

function _persistStorage() {
  try {
    const dir = join(STORAGE_FILE, '..');
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(STORAGE_FILE, JSON.stringify(_memoryStore, null, 2));
  } catch {
    // Non-critical
  }
}

_loadStorage();

// ---- Dynamic imports for browser pool and content bridge ----
let _browserPool = null;
let _contentBridge = null;

async function _getBrowserPool() {
  if (!_browserPool) {
    _browserPool = await import('./browser-pool.js');
  }
  return _browserPool;
}

async function _getContentBridge() {
  if (!_contentBridge) {
    _contentBridge = await import('./content-bridge.js');
  }
  return _contentBridge;
}

// ---- Error tracking ----
let _lastError = null;

// ---- Chrome Storage Shim ----
const chromeStorageLocal = {
  async get(keys) {
    if (keys === null || keys === undefined) {
      return { ..._memoryStore };
    }
    if (typeof keys === 'string') {
      return { [keys]: _memoryStore[keys] };
    }
    if (Array.isArray(keys)) {
      const result = {};
      for (const key of keys) {
        if (key in _memoryStore) result[key] = _memoryStore[key];
      }
      return result;
    }
    if (typeof keys === 'object') {
      const result = {};
      for (const key of Object.keys(keys)) {
        if (key in _memoryStore) {
          result[key] = _memoryStore[key];
        } else {
          result[key] = keys[key]; // Return default value
        }
      }
      return result;
    }
    return {};
  },

  async set(items) {
    Object.assign(_memoryStore, items);
    _persistStorage();
  },

  async remove(keys) {
    if (typeof keys === 'string') {
      delete _memoryStore[keys];
    } else if (Array.isArray(keys)) {
      for (const key of keys) delete _memoryStore[key];
    }
    _persistStorage();
  },
};

// ---- Chrome Tabs Shim ----
const chromeTabs = {
  async query(queryInfo) {
    const pool = await _getBrowserPool();
    const activeId = pool.getActivePageId();
    if (!activeId) return [];
    const info = await pool.getPageInfo(activeId);
    return info ? [info] : [];
  },

  async get(tabId) {
    const pool = await _getBrowserPool();
    return await pool.getPageInfo(tabId);
  },

  async sendMessage(tabId, message) {
    const pool = await _getBrowserPool();
    const bridge = await _getContentBridge();
    const entry = pool.getPage(tabId);
    if (!entry) {
      _lastError = { message: `Tab ${tabId} not found` };
      throw new Error(`Tab ${tabId} not found`);
    }
    // Handle BG_EXEC_TOOL messages
    if (message.type === 'BG_EXEC_TOOL') {
      return await bridge.executeToolInPage(entry.page, message.tool, message.args);
    }
    return { ok: true };
  },

  async captureVisibleTab(windowId, options) {
    const pool = await _getBrowserPool();
    const dataUrl = await pool.captureScreenshot();
    return dataUrl;
  },
};

// ---- Chrome Scripting Shim ----
const chromeScripting = {
  async executeScript({ target, func, args, files, world }) {
    const pool = await _getBrowserPool();
    const entry = pool.getPage(target.tabId);
    if (!entry) {
      _lastError = { message: `Tab ${target.tabId} not found` };
      throw new Error(`Tab ${target.tabId} not found`);
    }

    if (files && files.length > 0) {
      // Inject content script file
      const bridge = await _getContentBridge();
      await bridge.injectTools(entry.page);
      return [{ result: null }];
    }

    if (func) {
      // Execute function in page context
      const serializedFunc = func.toString();
      const result = await entry.page.evaluate(
        ({ serializedFunc, args }) => {
          const fn = eval('(' + serializedFunc + ')');
          return fn(...(args || []));
        },
        { serializedFunc, args: args || [] }
      );
      return [{ result }];
    }

    return [];
  },
};

// ---- Chrome Runtime Shim ----
function connectNative(hostName) {
  let _msgCallback = null;
  let _disconnectCallback = null;
  let _process = null;
  let _resolved = false;
  let _timeoutHandle = null;

  const port = {
    onMessage: {
      addListener(cb) { _msgCallback = cb; },
    },
    onDisconnect: {
      addListener(cb) { _disconnectCallback = cb; },
    },
    postMessage(msg) {
      if (hostName === 'python_bridge') {
        _handlePythonBridge(msg);
        return;
      }

      // Default: WSL2 bridge
      const { command, timeout = 30000 } = msg;
      console.log(`[WSL] Executing: ${command.substring(0, 150)}`);

      _timeoutHandle = setTimeout(() => {
        if (!_resolved) {
          _resolved = true;
          try { port.disconnect(); } catch {}
          if (_msgCallback) {
            _msgCallback({ error: `Command timed out after ${timeout}ms.` });
          }
        }
      }, timeout);

      // Use spawn instead of exec to avoid command escaping issues
      // Pass command directly to bash -c without shell interpolation
      const wslProcess = spawn('wsl.exe', ['--', 'bash', '-c', command], {
        timeout: Math.min(timeout, 120000),
        env: { ...process.env },
        windowsHide: true,
      });

      let stdout = '';
      let stderr = '';

      wslProcess.stdout.on('data', (data) => { stdout += data.toString(); });
      wslProcess.stderr.on('data', (data) => { stderr += data.toString(); });

      wslProcess.on('close', (exitCode) => {
        if (!_resolved) {
          _resolved = true;
          clearTimeout(_timeoutHandle);
          console.log(`[WSL] Completed: exitCode=${exitCode}, stdout=${stdout.length}b, stderr=${stderr.length}b`);
          if (_msgCallback) {
            _msgCallback({ stdout, stderr, exitCode });
          }
        }
      });

      wslProcess.on('error', (err) => {
        if (!_resolved) {
          _resolved = true;
          clearTimeout(_timeoutHandle);
          if (_msgCallback) {
            _msgCallback({
              stdout: '',
              stderr: err.message,
              exitCode: 1,
            });
          }
        }
      });
    },
    disconnect() {
      _resolved = true;
      if (_timeoutHandle) clearTimeout(_timeoutHandle);
      if (_disconnectCallback) {
        _disconnectCallback();
      }
    },
  };

  function _handlePythonBridge(msg) {
    const { filename, sessionDir, args = [], timeout = 30000 } = msg;
    console.log(`[Python] Executing: ${filename} in ${sessionDir}`);

    _timeoutHandle = setTimeout(() => {
      if (!_resolved) {
        _resolved = true;
        try { port.disconnect(); } catch {}
        if (_msgCallback) {
          _msgCallback({ error: `Python execution timed out after ${timeout}ms.` });
        }
      }
    }, timeout);

    // Resolve the file path from session dir
    const filePath = join(sessionDir, filename);
    if (!existsSync(filePath)) {
      if (_msgCallback) {
        _msgCallback({ error: `File not found: ${filename}` });
      }
      return;
    }

    // Find python executable
    const pythonCmd = process.env.PYTHON_PATH || 'python';

    const pyArgs = [filePath, ...(args || [])];
    const pyProcess = spawn(pythonCmd, pyArgs, {
      cwd: sessionDir,
      env: { ...process.env },
      timeout: Math.min(timeout, 120000),
    });

    let stdout = '';
    let stderr = '';

    pyProcess.stdout.on('data', (data) => { stdout += data.toString(); });
    pyProcess.stderr.on('data', (data) => { stderr += data.toString(); });

    pyProcess.on('close', (exitCode) => {
      if (!_resolved) {
        _resolved = true;
        clearTimeout(_timeoutHandle);
        if (_msgCallback) {
          if (exitCode !== 0 && !stdout && stderr) {
            _msgCallback({ stdout: '', stderr, exitCode });
          } else {
            _msgCallback({ stdout, stderr, exitCode });
          }
        }
      }
    });

    pyProcess.on('error', (err) => {
      if (!_resolved) {
        _resolved = true;
        clearTimeout(_timeoutHandle);
        if (_msgCallback) {
          _msgCallback({ error: `Python execution failed: ${err.message}. Ensure Python is installed and in PATH.` });
        }
      }
    });
  }

  return port;
}

const chromeRuntime = {
  connectNative,
  lastError: null, // Will be dynamically accessed
  onInstalled: { addListener() {} },
  onStartup: { addListener() {} },
  onConnect: { addListener() {} },
  onMessage: { addListener() {} },
  sendMessage() {},
};

// ---- Chrome Cookies Shim ----
const chromeCookies = {
  async getAll({ domain } = {}) {
    const pool = await _getBrowserPool();
    return await pool.getCookies(domain);
  },
};

// ---- Chrome Downloads Shim ----
const chromeDownloads = {
  async download({ url, filename, content }) {
    try {
      const downloadsDir = join(__dirname, '..', 'data', 'downloads');
      if (!existsSync(downloadsDir)) mkdirSync(downloadsDir, { recursive: true });

      const filePath = join(downloadsDir, filename);

      if (url && url.startsWith('data:')) {
        // Data URL - decode and write
        const base64Match = url.match(/^data:[^;]+;base64,(.+)$/);
        if (base64Match) {
          writeFileSync(filePath, Buffer.from(base64Match[1], 'base64'));
        } else {
          const textMatch = url.match(/^data:[^;]+,(.+)$/);
          if (textMatch) {
            writeFileSync(filePath, decodeURIComponent(textMatch[1]));
          }
        }
      } else if (content) {
        writeFileSync(filePath, content);
      }

      return { id: Date.now() };
    } catch (err) {
      _lastError = { message: err.message };
      throw err;
    }
  },
};

// ---- Chrome Side Panel Shim (no-op) ----
const chromeSidePanel = {
  setPanelBehavior() { return Promise.resolve(); },
  open() { return Promise.resolve(); },
};

// ---- Chrome Action Shim (no-op) ----
const chromeAction = {
  onClicked: { addListener() {} },
};

// ---- Build Chrome Global ----
const chrome = {
  storage: { local: chromeStorageLocal },
  tabs: chromeTabs,
  scripting: chromeScripting,
  runtime: chromeRuntime,
  cookies: chromeCookies,
  downloads: chromeDownloads,
  sidePanel: chromeSidePanel,
  action: chromeAction,
};

// Make lastError a getter that returns the current error
Object.defineProperty(chrome.runtime, 'lastError', {
  get() { return _lastError; },
  set(v) { _lastError = v; },
});

// Install as global
globalThis.chrome = chrome;

export { chrome };
