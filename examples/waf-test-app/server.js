// AEGIS WAF — demo target app for testing the shield end-to-end.
//
// A tiny Express site protected by the AEGIS WAF middleware. Point the
// shield at it, then fire real payloads (SQLi, XSS, traversal, command
// injection) at the routes below and watch the decisions land in the
// WAF Shield console.
//
// Run:  node examples/waf-test-app/server.js
// Env:  AEGIS_WAF_URL    WAF edge endpoint (default http://localhost:3000/api/waf/edge)
//       AEGIS_WAF_TOKEN  install token from the WAF Shield console
//       PORT                 port for this site (default 4000)

import express from 'express';

const WAF_URL = process.env.AEGIS_WAF_URL || 'http://localhost:3000/api/waf/edge';
const WAF_TOKEN = process.env.AEGIS_WAF_TOKEN || 'wafinst_ip_qi5ZsT-E0inXUQ4NIgR7V9RK_c3GF';
const PORT = parseInt(process.env.PORT, 10) || 4000;

const app = express();

// Parse bodies BEFORE the WAF middleware so it can inspect them.
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---- AEGIS WAF middleware (fail-open) ----
// Add BEFORE your routes. Fail-open: if the WAF is unreachable, traffic
// passes — protection never takes your site down.
async function AEGISWaf(req, res, next) {
  try {
    const r = await fetch(WAF_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${WAF_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        method: req.method,
        path: req.path,
        query: req.originalUrl.split('?')[1] || '',
        headers: req.headers,
        body: typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? ''),
      }),
    });
    if (r.status === 403) {
      return res.status(403).send('Request blocked by AEGIS WAF');
    }
  } catch {
    // WAF unreachable — fail open, never take the site down.
  }
  next();
}

app.use(AEGISWaf);

// ---- Routes (intentionally reflective — a realistic target for the scanner) ----

app.get('/', (req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Acme Store — WAF test target</title>
  <style>
    :root { color-scheme: light dark; }
    * { box-sizing: border-box; }
    body { margin: 0; font: 15px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #0f1115; color: #e6e8eb; }
    .wrap { max-width: 720px; margin: 0 auto; padding: 40px 20px; }
    h1 { font-size: 22px; margin: 0 0 4px; }
    p.sub { color: #9aa3ad; margin: 0 0 28px; }
    .card { background: #171a21; border: 1px solid #262b34; border-radius: 12px; padding: 20px; margin-bottom: 16px; }
    h2 { font-size: 14px; text-transform: uppercase; letter-spacing: .06em; color: #9aa3ad; margin: 0 0 14px; }
    label { display: block; font-size: 13px; color: #c3c9d1; margin-bottom: 6px; }
    input { width: 100%; padding: 10px 12px; background: #0f1115; border: 1px solid #2c333d; border-radius: 8px; color: #e6e8eb; font-size: 14px; margin-bottom: 12px; }
    button { padding: 10px 18px; background: #3b82f6; border: 0; border-radius: 8px; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; }
    button:hover { background: #2f6fd6; }
    .links a { color: #6ea8fe; text-decoration: none; margin-right: 16px; font-size: 13px; }
    .links a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Acme Store</h1>
    <p class="sub">A small demo site protected by the AEGIS WAF. Try a payload and watch the shield decide.</p>

    <div class="card">
      <h2>Search products</h2>
      <form method="get" action="/search">
        <label for="q">Search</label>
        <input id="q" name="q" placeholder="e.g. wireless headphones" autocomplete="off">
        <button type="submit">Search</button>
      </form>
    </div>

    <div class="card">
      <h2>Sign in</h2>
      <form method="post" action="/login">
        <label for="username">Username</label>
        <input id="username" name="username" autocomplete="off">
        <label for="password">Password</label>
        <input id="password" name="password" type="password">
        <button type="submit">Sign in</button>
      </form>
    </div>

    <div class="links">
      <a href="/api/products">/api/products</a>
      <a href="/health">/health</a>
    </div>
  </div>
</body>
</html>`);
});

app.get('/search', (req, res) => {
  const q = String(req.query.q ?? '');
  // Reflected on purpose — this is a test target, not production code.
  res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Search</title></head>
<body style="font:15px system-ui;background:#0f1115;color:#e6e8eb;padding:40px">
  <h1 style="font-size:20px">Results for: ${q}</h1>
  <p style="color:#9aa3ad">No products matched your search.</p>
  <p><a href="/" style="color:#6ea8fe">Back</a></p>
</body></html>`);
});

app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  // Always "fails" — the point is to let the WAF inspect the submitted body.
  res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head>
<body style="font:15px system-ui;background:#0f1115;color:#e6e8eb;padding:40px">
  <h1 style="font-size:20px">Sign in failed</h1>
  <p style="color:#9aa3ad">Invalid credentials for "${String(username)}".</p>
  <p><a href="/" style="color:#6ea8fe">Back</a></p>
</body></html>`);
});

app.get('/api/products', (req, res) => {
  res.json({
    products: [
      { id: 1, name: 'Wireless Headphones', price: 129.0 },
      { id: 2, name: 'Mechanical Keyboard', price: 89.5 },
      { id: 3, name: 'USB-C Hub', price: 45.0 },
    ],
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', protected: true });
});

// ---- Startup ----

async function selfCheck() {
  try {
    const r = await fetch(WAF_URL, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${WAF_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'GET', path: '/health', query: '', headers: {}, body: '' }),
    });
    if (r.status === 401) {
      console.warn('  ! Install token rejected (401) — generate one in the WAF Shield console.');
    } else {
      const d = await r.json().catch(() => ({}));
      console.log(`  WAF reachable — self-check verdict: ${d.action || r.status}`);
    }
  } catch {
    console.warn('  ! WAF unreachable — this site will run unprotected (fail-open).');
  }
}

app.listen(PORT, async () => {
  console.log('');
  console.log('  Acme Store — AEGIS WAF test target');
  console.log(`  Site:  http://localhost:${PORT}`);
  console.log(`  WAF:   ${WAF_URL}`);
  console.log(`  Token: ${WAF_TOKEN.slice(0, 12)}…`);
  await selfCheck();
  console.log('');
});
