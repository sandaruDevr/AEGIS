"""Test deepseek/deepseek-v4-flash-0731 pinned to DeepSeek official (tag: deepseek)."""
import os, time, uuid, requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
API_KEY = os.getenv("OPENROUTER_API_KEY")
URL = "https://openrouter.ai/api/v1/chat/completions"
SESSION = f"ds-official-{uuid.uuid4().hex[:8]}"

SYSTEM = "You are a security assistant. " * 40  # ~500 tokens

def send(messages, label):
    body = {
        "model": "deepseek/deepseek-v4-flash-0731",
        "messages": messages,
        "max_tokens": 100,
        "stream": False,
        "session_id": SESSION,
        "provider": {"order": ["deepseek"], "allow_fallbacks": False},
    }
    h = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "X-Session-ID": SESSION,
        "X-OpenRouter-Cache": "true",
        "X-OpenRouter-Cache-TTL": "3600",
    }
    for attempt in range(4):
        r = requests.post(URL, headers=h, json=body, timeout=90)
        if r.status_code == 429:
            wait = 15 * (attempt + 1)
            print(f"{label:<12} 429 (attempt {attempt+1}/4), waiting {wait}s...")
            time.sleep(wait)
            continue
        break
    if r.status_code != 200:
        print(f"{label:<12} ERROR {r.status_code}: {r.text[:200]}")
        return None
    u = r.json().get("usage", {})
    provider = r.headers.get("X-OpenRouter-Provider") or r.json().get("provider", "?")
    cached = (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
    pt = u.get("prompt_tokens", 0)
    blocks = f"{cached/64:.2f}" if cached else "0"
    print(f"{label:<12} provider={provider:<10} prompt={pt:>5} cached={cached:>5} ({cached/64:.2f} blocks of 64, {cached/128:.2f} of 128)")
    return {"prompt": pt, "cached": cached}

conv = [{"role": "system", "content": SYSTEM}]
print(f"Session: {SESSION} | Model: deepseek/deepseek-v4-flash-0731 | Provider: deepseek (official)\n")

for i, q in enumerate([
    "What is SQL injection? Brief example.",
    "How do I detect SQL injection vulnerabilities?",
    "Best tools for automated SQLi testing?",
    "How to parameterize queries in Python?",
]):
    conv.append({"role": "user", "content": q})
    res = send(conv, f"Turn {i+1}")
    if res is None:
        break
    conv.append({"role": "assistant", "content": f"[Answer {i+1} about SQL injection topic]"})
    time.sleep(3)
