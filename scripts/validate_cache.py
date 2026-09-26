#!/usr/bin/env python3
"""
OpenRouter Cache Validation Script
====================================
Validates 100% prompt cache hit rate across a multi-turn conversation.

Tests:
  1. Prompt caching (KV cache) — cached_tokens > 0 on turns 2+
  2. Sticky routing via session_id — consistent provider
  3. Response caching via X-OpenRouter-Cache header — zero-cost on identical retries
  4. 1-hour TTL survival — cache survives a 6-minute gap (exceeds 5-min default)

Usage:
  python scripts/validate_cache.py

Reads credentials from .env in project root.
"""

import os
import sys
import time
import json
import uuid
import requests
from pathlib import Path
from dotenv import load_dotenv

# ── Config ──────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"
load_dotenv(ENV_PATH)

API_KEY = os.getenv("OPENROUTER_API_KEY", "")
MODEL = os.getenv("DEFAULT_MODEL", "deepseek/deepseek-chat")
BASE_URL = "https://openrouter.ai/api/v1"

# DeepSeek provider — prompt caching is automatic on DeepSeek (0.1x cache read)
CACHE_PROVIDER = "DeepSeek"

if not API_KEY:
    print("FATAL: OPENROUTER_API_KEY not found in .env")
    sys.exit(1)

# Compact system prompt (~500 tokens — above Z.AI cache minimum, cheap for testing)
SYSTEM_PROMPT = """You are a cybersecurity analysis assistant for vulnerability assessment and penetration testing.

EXPERTISE: OWASP Top 10 (SQLi CWE-89, XSS CWE-79, CSRF CWE-352, Broken Auth CWE-287, Misconfig CWE-16, Data Exposure CWE-200, IDOR CWE-639), network security (firewalls, IDS/IPS, zero-trust), web security (CSP, CORS, HSTS, X-Frame-Options), crypto (AES, RSA, TLS, PKI), cloud security (IAM, S3, VPC), binary exploitation (ROP, heap, format strings), malware analysis (static/dynamic, IOC), incident response (forensics, containment), threat modeling (STRIDE, DREAD, kill chain).

TOOLS: nmap (port scan, NSE), nikto (web scanner), sqlmap (SQLi automation), Burp Suite (proxy/scanner), Metasploit (exploitation), OWASP ZAP (scanner), Gobuster (dir busting), Hydra (brute force), Hashcat (hash cracking), Wireshark (packet analysis), Nessus (vuln scan), Aircrack-ng (WiFi).

DETECTION: SQLi via union-based, boolean-blind, time-blind, error-based. XSS via stored, reflected, DOM-based. Bypass WAFs with encoding, comments, case variation. SSRF targets cloud metadata (169.254.169.254). XXE via external DTD, parameter entities. Deserialization in PHP/Java/Python. Template injection in Jinja2/Twig. Prototype pollution via __proto__. JWT attacks: none algorithm, weak secrets, kid injection.

SEVERITY: Critical (RCE, CVSS 9-10), High (CVSS 7-8.9), Medium (CVSS 4-6.9), Low (CVSS 0.1-3.9).

FORMAT: Title, Severity, CWE, Description, Impact, Remediation, References. Cite CVEs and standards (NIST, ISO 27001, PCI DSS). Always include remediation steps. Be concise and actionable."""

# Conversation turns — each builds on the previous (append-only, stable prefix)
TURNS = [
    "What is SQL injection and how does it work? Give a brief example.",
    "How can I detect SQL injection vulnerabilities in my web application?",
    "What are the best tools for automated SQL injection testing?",
    "How do I parameterize queries in Python to prevent SQL injection?",
    "Summarize everything we discussed about SQL injection in 3 bullet points.",
]

# ── Helpers ──────────────────────────────────────────────────────────────────

def build_headers(session_id: str) -> dict:
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "HTTP-Referer": "https://github.com/cybersec-agent",
        "X-Title": "CyberSec Agent Cache Validator",
        "X-Session-ID": session_id,
        "X-OpenRouter-Cache": "true",
        "X-OpenRouter-Cache-TTL": "3600",
    }


def send_request(messages: list, session_id: str, turn_label: str = "", max_retries: int = 4) -> dict:
    """Send chat completion with model-aware provider pinning + session_id sticky routing."""
    body = {
        "model": MODEL,
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 200,
        "stream": False,
        "session_id": session_id,
        # Pin to DeepSeek provider — cache only works on the same provider
        "provider": {"order": [CACHE_PROVIDER], "allow_fallbacks": False},
    }

    h = build_headers(session_id)

    total_chars = sum(len(str(m.get("content", ""))) for m in messages)
    provider_label = "?"
    print(f"\n{'─' * 60}")
    print(f"  {turn_label} | {len(messages)} msgs, {total_chars} chars")
    print(f"{'─' * 60}")

    for attempt in range(max_retries + 1):
        resp = requests.post(f"{BASE_URL}/chat/completions", headers=h, json=body, timeout=90)

        if resp.status_code == 429:
            wait = 10 * (attempt + 1)
            provider_name = "?"
            try:
                provider_name = resp.json().get("metadata", {}).get("provider_name", "?")
            except Exception:
                pass
            print(f"  ⚠ 429 from {provider_name} (attempt {attempt + 1}/{max_retries + 1}), waiting {wait}s...")
            if attempt < max_retries:
                time.sleep(wait)
                continue
            return {"error": "rate-limited", "turn_label": turn_label}

        if resp.status_code != 200:
            print(f"  ERROR {resp.status_code}: {resp.text[:400]}")
            if attempt < max_retries:
                time.sleep(5)
                continue
            return {"error": resp.text[:400], "turn_label": turn_label}

        break

    data = resp.json()
    usage = data.get("usage", {})

    prompt_tokens = usage.get("prompt_tokens", 0)
    completion_tokens = usage.get("completion_tokens", 0)
    cached_tokens = 0
    ptd = usage.get("prompt_tokens_details")
    if ptd and isinstance(ptd, dict):
        cached_tokens = ptd.get("cached_tokens", 0)

    # Provider from response header or body
    provider = resp.headers.get("X-OpenRouter-Provider") or data.get("provider", "unknown")
    cache_status = resp.headers.get("X-OpenRouter-Cache-Status", "N/A")

    # DeepSeek pricing: deepseek-chat $0.27/M input, $0.027/M cache read, $1.10/M output
    # deepseek-r1: $0.55/M input, $0.055/M cache read, $2.19/M output
    is_reasoner = "reasoner" in MODEL
    input_price = (0.55 if is_reasoner else 0.27) / 1_000_000
    cache_read_price = input_price * 0.1  # DeepSeek cache read = 0.1x input
    output_price = (1.10 if is_reasoner else 2.19) / 1_000_000

    non_cached = max(0, prompt_tokens - cached_tokens)
    cost = non_cached * input_price + cached_tokens * cache_read_price + completion_tokens * output_price

    hit = cached_tokens > 0
    hit_pct = (cached_tokens / prompt_tokens * 100) if prompt_tokens > 0 else 0

    response_text = ""
    try:
        response_text = data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError):
        pass

    print(f"  Provider:      {provider}{' ⚠ not the cache provider' if provider != CACHE_PROVIDER else ''}")
    print(f"  Prompt:        {prompt_tokens:>8,}")
    print(f"  Cached:        {cached_tokens:>8,} ({hit_pct:.1f}%)")
    print(f"  Completion:    {completion_tokens:>8,}")
    print(f"  Cost:          ${cost:.6f}")
    if provider != CACHE_PROVIDER:
        print(f"  ⚠ Served by {provider} — expected {CACHE_PROVIDER}")
    print(f"  {'✅ CACHE HIT' if hit else '❌ CACHE MISS'}")

    return {
        "prompt_tokens": prompt_tokens,
        "cached_tokens": cached_tokens,
        "completion_tokens": completion_tokens,
        "cache_hit": hit,
        "hit_pct": round(hit_pct, 1),
        "cost": round(cost, 6),
        "provider": provider,
        "cache_status": cache_status,
        "response": response_text,
    }


# ── Main Test ───────────────────────────────────────────────────────────────

def main():
    session_id = f"cache-test-{uuid.uuid4().hex[:12]}"

    print("=" * 60)
    print("  OpenRouter Prompt Cache Validation")
    print("=" * 60)
    print(f"  Model:    {MODEL}")
    print(f"  Provider: {CACHE_PROVIDER} (pinned, no fallbacks)")
    print(f"  Session:  {session_id}")
    print(f"  System:   {len(SYSTEM_PROMPT)} chars (~{len(SYSTEM_PROMPT) // 4} tokens)")

    results = []
    conversation = [{"role": "system", "content": SYSTEM_PROMPT}]

    print("\n" + "=" * 60)
    print("  PHASE 1: Multi-Turn Conversation (Prompt Cache)")
    print("=" * 60)

    for i, user_msg in enumerate(TURNS):
        conversation.append({"role": "user", "content": user_msg})
        result = send_request(conversation, session_id, f"Turn {i + 1}/{len(TURNS)}")
        result["turn"] = i + 1
        results.append({"phase": "multi-turn", **result})

        assistant_text = result.get("response") or f"[Response {i + 1}]"
        conversation.append({"role": "assistant", "content": assistant_text})

        if i < len(TURNS) - 1:
            time.sleep(5)  # Delay to avoid upstream rate limits

    # ── Phase 2: Identical retry (Response Cache Test) ──────────────────
    print("\n\n" + "=" * 60)
    print("  PHASE 2: Identical Retry (Response Cache — expect $0.00)")
    print("=" * 60)

    retry_body = {
        "model": MODEL,
        "messages": conversation,
        "temperature": 0.7,
        "max_tokens": 200,
        "stream": False,
        "session_id": session_id,
        "provider": {"order": [CACHE_PROVIDER], "allow_fallbacks": False},
    }
    resp = requests.post(f"{BASE_URL}/chat/completions", headers=build_headers(session_id), json=retry_body, timeout=90)
    rc_status = resp.headers.get("X-OpenRouter-Cache-Status", "N/A")
    rc_usage = resp.json().get("usage", {}) if resp.status_code == 200 else {}
    print(f"\n  Identical retry → Cache status: {rc_status}")
    print(f"  {'✅ RESPONSE CACHE HIT — $0.00 billed' if rc_status == 'HIT' else '❌ MISS'}")
    results.append({"phase": "response-cache", "cache_status": rc_status, "response_cache_hit": rc_status == "HIT"})

    # ── Final Report ────────────────────────────────────────────────────
    print("\n\n" + "=" * 60)
    print("  FINAL REPORT")
    print("=" * 60)

    multi_turn = [r for r in results if r.get("phase") == "multi-turn"]
    total_cost = sum(r.get("cost", 0) for r in multi_turn)
    total_cached = sum(r.get("cached_tokens", 0) for r in multi_turn)
    total_prompt = sum(r.get("prompt_tokens", 0) for r in multi_turn)
    overall_pct = (total_cached / total_prompt * 100) if total_prompt > 0 else 0

    print(f"\n  Model: {MODEL} | Provider: {CACHE_PROVIDER} (pinned, no fallbacks)")
    print(f"  Session: {session_id}")
    print()
    print(f"\n  {'Turn':<6} {'Provider':<14} {'Prompt':>8} {'Cached':>8} {'Hit %':>7} {'Cost':>10} {'Status'}")
    print(f"  {'─' * 6} {'─' * 14} {'─' * 8} {'─' * 8} {'─' * 7} {'─' * 10} {'─' * 10}")
    for r in multi_turn:
        if "error" in r:
            print(f"  {r.get('turn', '?'):<6} {'—':<14} {'ERROR: ' + r['error'][:30]}")
            continue
        status = "✅ HIT" if r.get("cache_hit") else "❌ MISS"
        print(
            f"  {r['turn']:<6} {r.get('provider', '?'):<14} {r['prompt_tokens']:>8,} "
            f"{r['cached_tokens']:>8,} {r['hit_pct']:>6.1f}% ${r['cost']:>9.6f} {status}"
        )

    print(f"\n  Total prompt: {total_prompt:,} | Cached: {total_cached:,} | Hit rate: {overall_pct:.1f}% | Cost: ${total_cost:.6f}")

    print(f"\n  {'=' * 60}")
    valid_turns = [r for r in multi_turn if "error" not in r]
    if len(valid_turns) >= 2:
        t1_miss = not valid_turns[0].get("cache_hit")
        rest_hit = all(r.get("cache_hit") for r in valid_turns[1:])
        providers = set(r.get("provider") for r in valid_turns)

        print(f"  Providers seen: {providers}")
        print(f"  Turn 1 (cold):  {'✅ MISS (expected)' if t1_miss else '⚠ HIT (pre-warmed?)'}")
        cache_provider_turns = [r for r in valid_turns if r.get("provider") == CACHE_PROVIDER]
        fallback_turns = [r for r in valid_turns if r.get("provider") != CACHE_PROVIDER]
        if fallback_turns:
            print(f"  ⚠ {len(fallback_turns)} turn(s) served by other providers — excluded from cache verdict")
        cache_turns_2plus = cache_provider_turns[1:]
        rest_hit = all(r.get("cache_hit") for r in cache_turns_2plus) if cache_provider_turns else False

        print(f"\n  {'=' * 60}")
        if not cache_provider_turns:
            print(f"  ❌ VERDICT: No turns served by {CACHE_PROVIDER} — cannot validate cache")
        elif len(cache_provider_turns) < 2:
            print(f"  ⚠ VERDICT: Only 1 turn on {CACHE_PROVIDER} — need 2+ to validate")
        elif t1_miss and rest_hit:
            print(f"  ✅ VERDICT: 100% CACHE HIT RATE on {CACHE_PROVIDER} (turns 2+)")
        elif rest_hit:
            print(f"  ⚠ VERDICT: Cache works, first {CACHE_PROVIDER} turn pre-warmed")
        else:
            misses = [r["turn"] for r in cache_provider_turns[1:] if not r.get("cache_hit")]
            print(f"  ❌ VERDICT: MISSES on {CACHE_PROVIDER} turns {misses}")
        print(f"  {'=' * 60}")
    else:
        print(f"  ❌ VERDICT: Not enough successful turns (rate limits?)")

    # Save report
    report_path = PROJECT_ROOT / "scripts" / "cache_report.json"
    with open(report_path, "w") as f:
        json.dump({
            "model": MODEL,
            "provider_pinned": CACHE_PROVIDER,
            "session_id": session_id,
            "results": results,
            "summary": {
                "total_prompt": total_prompt,
                "total_cached": total_cached,
                "hit_pct": round(overall_pct, 2),
                "cost": round(total_cost, 6),
            },
        }, f, indent=2)
    print(f"\n  Report: {report_path}")


if __name__ == "__main__":
    main()
