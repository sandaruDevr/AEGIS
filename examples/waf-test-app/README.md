# AEGIS WAF — test target app

A tiny Express site protected by the AEGIS WAF middleware. Use it to prove
the shield works end-to-end: real payloads hit the site, the WAF decides, and
every decision shows up in the **WAF Shield** console (live monitor + analytics).

## Run

The platform server must be running first (`npm start` → http://localhost:3000).

```bash
node examples/waf-test-app/server.js
```

The site starts on http://localhost:4000 and prints a self-check line telling
you whether the WAF is reachable and the token is accepted.

## Configure

| Env var | Default | Purpose |
|---------|---------|---------|
| ` AEGIS_WAF_URL` | `http://localhost:3000/api/waf/edge` | WAF edge endpoint |
| ` AEGIS_WAF_TOKEN` | demo token | Install token for this site |
| `PORT` | `4000` | Port for the test site |

Generate a fresh token in the console: **WAF Shield → Install the shield →
pick the website → Generate install token**, then copy the Express snippet or
set ` AEGIS_WAF_TOKEN` to that token.

## Try it

Open http://localhost:4000 and use the forms, or fire payloads directly:

```bash
# Benign — passes
curl "http://localhost:4000/search?q=headphones"

# SQL injection — blocked in Enforce mode
curl "http://localhost:4000/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--"

# Path traversal
curl "http://localhost:4000/search?q=../../../../etc/passwd"

# Command injection (POST body)
curl -X POST http://localhost:4000/login -d "username=admin;cat /etc/passwd&password=x"
```

A blocked request returns **403 `Request blocked by AEGIS WAF`**. In
**Monitor** mode nothing is blocked — attacks are logged as *held for review*
so you can tune first, then switch to **Enforce**.

## Automated test

`scripts/test_waf.py` runs the whole path end-to-end (edge auth, benign pass,
attack blocking in Enforce, held-for-review in Monitor, config round-trip,
decision log, and this app through the middleware):

```bash
python scripts/test_waf.py
```

It restores the original WAF mode when it finishes. Pass `--token wafinst_...`
(or set ` AEGIS_WAF_TOKEN`) to use an existing install; otherwise it
provisions a temporary test website and token and removes them afterwards.

## How it works

The middleware forwards each request's method, path, query, headers and body to
the WAF edge endpoint and blocks on a `403`. It is **fail-open**: if the WAF is
unreachable, traffic passes — protection never takes the site down.
