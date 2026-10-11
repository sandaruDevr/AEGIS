#!/usr/bin/env python3
"""End-to-end test for the AEGIS WAF.

Exercises the real request path, not just unit logic:

  1. Edge endpoint auth        — invalid token rejected (401)
  2. Benign traffic            — allowed (200)
  3. Attack blocking (enforce) — each tier-1 payload returns 403
  4. Held for review (monitor) — same payloads pass but are logged as triage
  5. Operating-config API      — mode round-trip, restored afterwards
  6. Decision log              — the test decisions are recorded
  7. Demo target app           — full path through the Express middleware
                                 (skipped if the app is not running)

Usage:
    python scripts/test_waf.py
    python scripts/test_waf.py --base-url http://localhost:3000 --token wafinst_...
    python scripts/test_waf.py --app-url http://localhost:4000

Env:
AEGIS_WAF_TOKEN   install token for the edge tests. If unset, the script
                          provisions a dedicated "WAF Test Target" website and
                          token, then removes them when it finishes.
    AUTH_TOKEN            platform API token, only if the server requires one.

Exit code is 0 when every test passes, 1 otherwise.
"""

import argparse
import os
import sys

import requests

# Deterministic tier-1 payloads — each matches a built-in signature, so the
# expected verdict does not depend on anomaly scoring or the AI triage tier.
ATTACKS = [
    {"name": "sqli", "method": "GET", "path": "/search",
     "query": "q=1 UNION SELECT username,password FROM users--"},
    {"name": "sqli (url-encoded)", "method": "GET", "path": "/search",
     "query": "q=1%20UNION%20SELECT%20username,password%20FROM%20users--"},
    {"name": "sqli (double-encoded)", "method": "GET", "path": "/search",
     "query": "q=1%2520UNION%2520SELECT%2520username,password%2520FROM%2520users--"},
    {"name": "xss", "method": "GET", "path": "/search",
     "query": "q=<script>alert('xss')</script>"},
    {"name": "path_traversal", "method": "GET", "path": "/search",
     "query": "q=../../../../etc/passwd"},
    {"name": "command_injection", "method": "GET", "path": "/search",
     "query": "q=;cat /etc/passwd"},
    {"name": "ssrf", "method": "GET", "path": "/api/fetch",
     "query": "url=http://169.254.169.254/latest/meta-data/"},
    {"name": "template_injection", "method": "GET", "path": "/search",
     "query": "q={{7*7}}"},
    {"name": "xxe", "method": "POST", "path": "/api/parse",
     "body": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'},
]

BENIGN = {"method": "GET", "path": "/search", "query": "q=wireless+headphones"}

TEST_ASSET_NAME = "WAF Test Target"


class Report:
    """Collects pass/fail results and prints a summary."""

    def __init__(self):
        self.results = []

    def check(self, name, passed, detail=""):
        self.results.append((name, bool(passed), detail))
        mark = "PASS" if passed else "FAIL"
        line = f" [{mark}] {name}"
        if detail:
            line += f"  — {detail}"
        print(line)
        return passed

    def skip(self, name, detail=""):
        line = f" [SKIP] {name}"
        if detail:
            line += f"  — {detail}"
        print(line)

    @property
    def failed(self):
        return [r for r in self.results if not r[1]]

    def summary(self):
        total = len(self.results)
        passed = total - len(self.failed)
        print("-" * 64)
        print(f" {passed} passed, {len(self.failed)} failed, {total} total")
        return len(self.failed) == 0


def edge_request(base_url, token, req):
    """POST one request to the WAF edge endpoint. Returns (status, json)."""
    payload = {
        "method": req.get("method", "GET"),
        "path": req.get("path", "/"),
        "query": req.get("query", ""),
        "headers": req.get("headers", {}),
        "body": req.get("body", ""),
    }
    r = requests.post(
        f"{base_url}/api/waf/edge",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        timeout=15,
    )
    try:
        data = r.json()
    except ValueError:
        data = {}
    return r.status_code, data


def get_config(base_url, auth):
    return requests.get(f"{base_url}/api/waf/config", headers=auth, timeout=10).json()


def set_mode(base_url, auth, mode):
    r = requests.put(f"{base_url}/api/waf/config", headers=auth, json={"mode": mode}, timeout=10)
    r.raise_for_status()
    return r.json()


def provision_token(base_url, auth):
    """Create a dedicated test website + install token. Returns (token, asset_id)."""
    assets = requests.get(f"{base_url}/api/assets", headers=auth, timeout=10).json().get("assets", [])
    asset = next((a for a in assets if a.get("name") == TEST_ASSET_NAME), None)
    if asset is None:
        r = requests.post(
            f"{base_url}/api/assets", headers=auth,
            json={"name": TEST_ASSET_NAME, "url": "http://localhost:4000"}, timeout=10,
        )
        r.raise_for_status()
        body = r.json()
        asset = body.get("asset", body)
    r = requests.post(
        f"{base_url}/api/waf/installs", headers=auth,
        json={"assetId": asset["id"]}, timeout=10,
    )
    r.raise_for_status()
    return r.json()["install"]["token"], asset["id"]


def cleanup(base_url, auth, token, asset_id):
    try:
        requests.delete(f"{base_url}/api/waf/installs/{token}", headers=auth, timeout=10)
    except requests.RequestException:
        pass
    try:
        requests.delete(f"{base_url}/api/assets/{asset_id}", headers=auth, timeout=10)
    except requests.RequestException:
        pass


def app_reachable(app_url):
    try:
        r = requests.get(f"{app_url}/health", timeout=5)
        return r.status_code == 200
    except requests.RequestException:
        return False


def main():
    parser = argparse.ArgumentParser(description="End-to-end test for the AEGIS WAF.")
    parser.add_argument("--base-url", default=os.getenv("AEGIS_BASE_URL", "http://localhost:3000"),
                        help="platform server URL (default http://localhost:3000)")
    parser.add_argument("--app-url", default=os.getenv("AEGIS_APP_URL", "http://localhost:4000"),
                        help="demo target app URL (default http://localhost:4000)")
    parser.add_argument("--token", default=os.getenv("AEGIS_WAF_TOKEN", ""),
                        help="install token for the edge tests (else auto-provisioned)")
    parser.add_argument("--no-app", action="store_true", help="skip the demo target app tests")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    app_url = args.app_url.rstrip("/")
    auth = {}
    if os.getenv("AUTH_TOKEN"):
        auth["Authorization"] = f"Bearer {os.getenv('AUTH_TOKEN')}"

    report = Report()
    print("=" * 64)
    print("AEGIS WAF — end-to-end test")
    print("=" * 64)
    print(f" Server: {base_url}")
    print(f" App:    {app_url}")
    print("-" * 64)

    # --- Server reachable -------------------------------------------------
    try:
        requests.get(f"{base_url}/api/waf/config", headers=auth, timeout=5).raise_for_status()
    except requests.RequestException as exc:
        report.check("server reachable", False, str(exc))
        print("\n Is the platform server running?  npm start")
        return 1
    report.check("server reachable", True)

    # --- Token: provided or provisioned ----------------------------------
    token = args.token
    asset_id = None
    provisioned = False
    if not token:
        try:
            token, asset_id = provision_token(base_url, auth)
            provisioned = True
            print(f" [INFO] provisioned a test token for '{TEST_ASSET_NAME}' ({asset_id})")
        except requests.RequestException as exc:
            report.check("install token available", False, f"could not provision: {exc}")
            return 1
    else:
        print(f" [INFO] using provided token {token[:12]}…")

    original_mode = None
    try:
        original_mode = get_config(base_url, auth).get("mode", "monitor")

        # --- Edge auth ----------------------------------------------------
        status, _ = edge_request(base_url, "wafinst_not_a_real_token", BENIGN)
        report.check("edge rejects invalid token (401)", status == 401, f"got {status}")

        # --- Enforce: benign passes, attacks blocked ----------------------
        set_mode(base_url, auth, "enforce")
        print(" [INFO] mode -> enforce")

        status, data = edge_request(base_url, token, BENIGN)
        report.check("benign request allowed (200)", status == 200 and data.get("action") == "allow",
                     f"got {status} {data.get('action')}")

        for atk in ATTACKS:
            status, data = edge_request(base_url, token, atk)
            ok = status == 403 and data.get("action") == "block"
            report.check(f"{atk['name']} blocked in enforce (403)", ok,
                         f"got {status} {data.get('action')} ({data.get('attackType')})")

        # --- Monitor: attacks held, not blocked ---------------------------
        set_mode(base_url, auth, "monitor")
        print(" [INFO] mode -> monitor")

        for atk in ATTACKS:
            status, data = edge_request(base_url, token, atk)
            ok = status == 200 and data.get("action") == "triage"
            report.check(f"{atk['name']} held for review in monitor (200)", ok,
                         f"got {status} {data.get('action')}")

        # --- Decision log -------------------------------------------------
        decisions = requests.get(f"{base_url}/api/waf/decisions", headers=auth,
                                 params={"limit": 200}, timeout=10).json()
        items = decisions.get("items", [])
        report.check("decision log records the test traffic", len(items) > 0,
                     f"{len(items)} decisions")

        # --- Demo target app (full path through the middleware) -----------
        if args.no_app:
            report.skip("demo target app tests", "disabled (--no-app)")
        elif not app_reachable(app_url):
            report.skip("demo target app tests", "app not running (npm run waf-test-app)")
        else:
            set_mode(base_url, auth, "enforce")
            r = requests.get(f"{app_url}/search", params={"q": "wireless headphones"}, timeout=10)
            report.check("app: benign request passes (200)", r.status_code == 200,
                         f"got {r.status_code}")

            r = requests.get(f"{app_url}/search",
                             params={"q": "1 UNION SELECT username,password FROM users--"}, timeout=10)
            blocked = r.status_code == 403 and "blocked" in r.text.lower()
            report.check("app: sqli blocked by WAF (403)", blocked, f"got {r.status_code}")

            r = requests.post(f"{app_url}/login",
                              data={"username": "admin;cat /etc/passwd", "password": "x"}, timeout=10)
            blocked = r.status_code == 403 and "blocked" in r.text.lower()
            report.check("app: command injection blocked (403)", blocked, f"got {r.status_code}")

    finally:
        # Always restore the operator's original mode and clean up.
        if original_mode:
            try:
                set_mode(base_url, auth, original_mode)
                print(f" [INFO] mode restored -> {original_mode}")
            except requests.RequestException:
                print(f" [WARN] could not restore mode to {original_mode}")
        if provisioned:
            cleanup(base_url, auth, token, asset_id)
            print(" [INFO] test token and website removed")

    print("=" * 64)
    ok = report.summary()
    print("=" * 64)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
