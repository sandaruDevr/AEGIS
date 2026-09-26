"""Test GLM 5.3 Flash caching on GMICloud (tag: gmicloud/fp8)."""
import os, time, uuid, requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
API_KEY = os.getenv("OPENROUTER_API_KEY")
URL = "https://openrouter.ai/api/v1/chat/completions"
SESSION = f"gmicloud-{uuid.uuid4().hex[:8]}"

SYSTEM = "You are a security assistant. " * 40  # ~500 tokens

def send(messages, label):
    body = {
        "model": "z-ai/glm-5.3-flash",
        "messages": messages,
        "max_tokens": 100,
        "stream": False,
        "session_id": SESSION,
        "provider": {"order": ["gmicloud/fp8"], "allow_fallbacks": False},
    }
    h = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "X-Session-ID": SESSION,
        "X-OpenRouter-Cache": "true",
        "X-OpenRouter-Cache-TTL": "3600",
    }
    for attempt in range(5):
        r = requests.post(URL, headers=h, json=body, timeout=90)
        if r.status_code == 429:
            wait = 15 * (attempt + 1)
            print(f"{label:<30} 429 (attempt {attempt+1}/5), waiting {wait}s...")
            time.sleep(wait)
            continue
        break
    if r.status_code != 200:
        print(f"{label:<30} ERROR {r.status_code}: {r.text[:150]}")
        return None
    u = r.json().get("usage", {})
    provider = r.headers.get("X-OpenRouter-Provider") or r.json().get("provider", "?")
    cached = (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
    pt = u.get("prompt_tokens", 0)
    print(f"{label:<30} provider={provider:<10} prompt={pt:>5} cached={cached:>5} ({cached/128:.2f} blocks)")
    return {"prompt": pt, "cached": cached}

conv = [{"role": "system", "content": SYSTEM}]
print(f"Session: {SESSION} | Model: z-ai/glm-5.3-flash | Provider: gmicloud/fp8\n")

for i, q in enumerate([
    "What is SQL injection? Brief example.",
    "How do I detect SQL injection vulnerabilities?",
    "Best tools for automated SQLi testing?",
    "How to parameterize queries in Python?",
]):
    conv = conv if False else conv
    conv = conv  # keep reference
    conversation = conv
    conversation.append({"role": "user", "content": q})
    res = send(conversation, f"Turn {i+1}")
    if res is None:
        break
    conversation.append({"role": "assistant", "content": f"[Response {i+1}: SQL injection topic answer {i+1}]"})
    time.sleep(3)
