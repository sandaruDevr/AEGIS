#!/usr/bin/env python3
"""
OpenRouter Prompt Cache Validation — z-ai/glm-5.3-flash via Novita
====================================================================
Tests prompt caching on Novita (instead of Z.AI) for GLM 5.3 Flash.

Novita quantizes cached_tokens to 128-token blocks:
  cached = floor(stable_prefix / 128) * 128

Usage:
  python scripts/validate_cache_glm_novita.py
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
load_dotenv(PROJECT_ROOT / ".env")

API_KEY = os.getenv("OPENROUTER_API_KEY", "")
MODEL = "z-ai/glm-5.3-flash"
BASE_URL = "https://openrouter.ai/api/v1"
PRIMARY_PROVIDER = "Novita"   # Under test: does Novita cache GLM?
FALLBACK_PROVIDER = "Z.AI"    # Known-caching fallback if Novita rate-limits

if not API_KEY:
    print("FATAL: OPENROUTER_API_KEY not found in .env")
    sys.exit(1)

# Same compact system prompt (~393 tokens) as the main validator
SYSTEM_PROMPT = """You are a cybersecurity analysis assistant for vulnerability assessment and penetration testing.

EXPERTISE: OWASP Top 10 (SQLi CWE-89, XSS CWE-79, CSRF CWE-352, Broken Auth CWE-287, Misconfig CWE-16, Data Exposure CWE-200, IDOR CWE-639), network security (firewalls, IDS/IPS, zero-trust), web security (CSP, CORS, HSTS, X-Frame-Options), crypto (AES, RSA, TLS, PKI), cloud security (IAM, S3, VPC), binary exploitation (ROP, heap, format strings), malware analysis (static/dynamic, IOC), incident response (forensics, containment), threat modeling (STRIDE, DREAD, kill chain).

TOOLS: nmap (port scan, NSE), nikto (web scanner), sqlmap (SQLi automation), Burp Suite (proxy/scanner), Metasploit (exploitation), OWASP ZAP (scanner), Gobuster (dir busting), Hydra (brute force), Hashcat (hash cracking), Wireshark (packet analysis), Nessus (vuln scan), Aircrack-ng (WiFi).

DETECTION: SQLi via union-based, boolean-blind, time-blind, error-based. XSS via stored, reflected, DOM-based. Bypass WAFs with encoding, comments, case variation. SSRF targets cloud metadata (169.254.169.254). XXE via external DTD, parameter entities. Deserialization in PHP/Java/Python. Template injection in Jinja2/Twig. Prototype pollution via __proto__. JWT attacks: none algorithm, weak secrets, kid injection.

SEVERITY: Critical (RCE, CVSS 9-10), High (CVSS 7-8.9), Medium (CVSS 4-6.9), Low (CVSS 0.1-3.9).

FORMAT: Title, Severity, CWE, Description, Impact, Remediation, References. Cite CVEs and standards (NIST, ISO 27001, PCI DSS). Always include remediation steps. Be concise and actionable."""

TURNS = [
    "What is SQL injection? Brief example.",
    "How do I detect SQL injection vulnerabilities?",
    "Best tools for automated SQLi testing?",
    "How to parameterize queries in Python?",
    "Summarize SQL injection in 3 bullets.",
]


def build_headers(session_id: str) -> dict:
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "HTTP-Referer": "https://github.com/cybersec-agent",
        "X-Title": "GLM-Novita Cache Validator",
        "X-Session-ID": session_id,
        "X-OpenRouter-Cache": "true",
        "X-OpenRouter-Cache-TTL": "3600",
    }


def send_request(messages: list, session_id: str, turn_label: str = "", max_retries: int = 4) -> dict:
    """Send chat completion pinned to Novita with session_id sticky routing."""
    body = {
        "model": MODEL,
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 200,
        "stream": False,
        "session_id": session_id,
        "provider": {
            "order": [PRIMARY_PROVIDER, FALLBACK_PROVIDER],
            "allow_fallbacks": False,
        },
    }
    h = build_headers(session_id)

    total_chars = sum(len(str(m.get("content", ""))) for m in messages)
    print(f"\n{'─' * 60}")
    print(f"  {turn_label} | {len(messages)} msgs, {total_chars} chars")
    print(f"{'─' * 60}")

    for attempt in range(max_retries + 1):
        resp = requests.post(f"{BASE_URL}/chat/completions", headers=h, json=body, timeout=90)

        if resp.status_code == 429:
            wait = 10 * (attempt + 1)
            pname = "?"
            try:
                pname = resp.json().get("metadata", {}).get("provider_name", "?")
            except Exception:
                pass
            print(f"  ⚠ 429 from {pname} (attempt {attempt + 1}/{max_retries + 1}), waiting {wait}s...")
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

    provider = resp.headers.get("X-OpenRouter-Provider") or data.get("provider", "unknown")

    # GLM-5.3-flash pricing: $0.075/M input, $0.015/M cache read, $0.25/M output
    non_cached = max(0, prompt_tokens - cached_tokens)
    cost = non_cached * 0.075 / 1e6 + cached_tokens * 0.015 / 1e6 + completion_tokens * 0.25 / 1e6

    hit = cached_tokens > 0
    hit_pct = (cached_tokens / prompt_tokens * 100) if prompt_tokens > 0 else 0

    response_text = ""
    try:
        response_text = data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError):
        pass

    blocks = cached_tokens / 128
    print(f"  Provider:      {provider}")
    print(f"  Prompt:        {prompt_tokens:>8,}")
    print(f"  Cached:        {cached_tokens:>8,} ({hit_pct:.1f}%)  = {blocks:.2f} blocks of 128")
    print(f"  Completion:    {completion_tokens:>8,}")
    print(f"  Cost:          ${cost:.6f}")
    print(f"  {'✅ CACHE HIT' if hit else '❌ CACHE MISS'}")

    return {
        "prompt_tokens": prompt_tokens,
        "cached_tokens": cached_tokens,
        "completion_tokens": completion_tokens,
        "cache_hit": hit,
        "hit_pct": round(hit_pct, 1),
        "cost": round(cost, 6),
        "provider": provider,
        "response": response_text,
    }


def main():
    session_id = f"glm-novita-{uuid.uuid4().hex[:12]}"

    print("=" * 60)
    print("  GLM 5.3 Flash — Novita Prompt Cache Test")
    print("=" * 60)
    print(f"  Model:    {MODEL}")
    print(f"  Provider: {PRIMARY_PROVIDER} (primary) → {FALLBACK_PROVIDER} (fallback)")
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
            time.sleep(5)

    # ── Final Report ────────────────────────────────────────────────────
    print("\n\n" + "=" * 60)
    print("  FINAL REPORT")
    print("=" * 60)

    multi_turn = [r for r in results if r.get("phase") == "multi-turn"]
    total_cost = sum(r.get("cost", 0) for r in multi_turn)
    total_cached = sum(r.get("cached_tokens", 0) for r in multi_turn)
    total_prompt = sum(r.get("prompt_tokens", 0) for r in multi_turn)
    overall_pct = (total_cached / total_prompt * 100) if total_prompt > 0 else 0

    print(f"\n  Model: {MODEL} | Provider: {PRIMARY_PROVIDER}")
    print(f"  Session: {session_id}")
    print()
    print(f"  {'Turn':<6} {'Provider':<10} {'Prompt':>8} {'Cached':>8} {'Blocks':>7} {'Hit %':>7} {'Status'}")
    print(f"  {'─' * 6} {'─' * 10} {'─' * 8} {'─' * 8} {'─' * 7} {'─' * 7} {'─' * 10}")
    for r in multi_turn:
        if "error" in r:
            print(f"  {r.get('turn', '?'):<6} {'—':<10} {'ERROR: ' + r['error'][:30]}")
            continue
        status = "✅ HIT" if r.get("cache_hit") else "❌ MISS"
        blocks = f"{r['cached_tokens'] / 128:.2f}"
        print(
            f"  {r['turn']:<6} {r.get('provider', '?'):<10} {r['prompt_tokens']:>8,} "
            f"{r['cached_tokens']:>8,} {blocks:>7} {r['hit_pct']:>6.1f}% ${r['cost']:>9.6f} {status}"
        )

    print(f"\n  Total prompt: {total_prompt:,} | Cached: {total_cached:,} | Hit rate: {overall_pct:.1f}% | Cost: ${total_cost:.6f}")

    print(f"\n  {'=' * 60}")
    valid_turns = [r for r in multi_turn if "error" not in r]
    primary_turns = [r for r in valid_turns if r.get("provider") == PRIMARY_PROVIDER]
    if len(primary_turns) >= 2:
        rest_hit = all(r.get("cache_hit") for r in primary_turns[1:])
        if rest_hit:
            print(f"  ✅ VERDICT: Novita caches GLM 5.3 Flash — 100% hit rate (turns 2+)")
        else:
            misses = [r["turn"] for r in primary_turns[1:] if not r.get("cache_hit")]
            print(f"  ❌ VERDICT: MISSES on Novita turns {misses}")
    elif len(primary_turns) == 1:
        print(f"  ⚠ VERDICT: Only 1 turn on {PRIMARY_PROVIDER} — need 2+ to validate")
    else:
        print(f"  ❌ VERDICT: No turns served by {PRIMARY_PROVIDER}")
    print(f"  {'=' * 60}")

    # Save report
    report_path = PROJECT_ROOT / "scripts" / "cache_report_glm_novita.json"
    with open(report_path, "w") as f:
        json.dump({
            "model": MODEL,
            "primary_provider": PRIMARY_PROVIDER,
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
