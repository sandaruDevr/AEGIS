"""Verify 512-token cache block hypothesis: cached_tokens should be quantized to 512."""
import os, time, uuid, requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
API_KEY = os.getenv("OPENROUTER_API_KEY")
MODEL = os.getenv("DEFAULT_MODEL", "deepseek/deepseek-v4-flash-0731")
URL = "https://openrouter.ai/api/v1/chat/completions"
SESSION = f"blocktest-{uuid.uuid4().hex[:8]}"

# ~600-token filler to push past the 1024-token block boundary
FILLER = ("Detailed security checklist item. " * 60)  # ~1000 chars ~ 250 tokens each

def send(messages, label):
    body = {
        "model": MODEL,
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 10,
        "stream": False,
        "session_id": SESSION,
        "provider": {"order": ["Novita"], "allow_fallbacks": False},
    }
    h = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "X-Session-ID": SESSION,
        "X-OpenRouter-Cache": "true",
        "X-OpenRouter-Cache-TTL": "3600",
    }
    r = requests.post(URL, headers=h, json=body, timeout=90)
    if r.status_code != 200:
        print(f"{label}: ERROR {r.status_code} {r.text[:200]}")
        return None
    u = r.json().get("usage", {})
    pt = u.get("prompt_tokens", 0)
    ct = (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
    print(f"{label:<28} prompt={pt:>6,}  cached={ct:>6,}  ({ct/512:.2f} blocks of 512)")
    return ct

# Turn 1: system + short user
t1 = [
    {"role": "system", "content": "You are a security assistant. " * 40},  # ~500 tokens
    {"role": "user", "content": "Hi"},
]
print(f"Session: {SESSION} | Model: {MODEL}\n")
send(t1, "Turn 1 (cold, ~600 tok)")

# Turn 2: same prefix + short exchange -> expect cached = 512 (1 complete block)
t2 = t1 + [
    {"role": "assistant", "content": "Hello! How can I help?"},
    {"role": "user", "content": "What is XSS?"},
]
time.sleep(2)
send(t2, "Turn 2 (~640 tok)")

# Turn 3: same prefix + LONG user msg (~600 tok) -> total ~1200 tok
t3 = t2 + [
    {"role": "assistant", "content": "XSS is cross-site scripting, injecting malicious scripts."},
    {"role": "user", "content": FILLER * 2 + " Now briefly define CSRF."},
]
time.sleep(2)
send(t3, "Turn 3 (long msg, ~1200 tok)")

# Turn 4: same prefix + short msg -> cached should now be 1024 if block hypothesis holds
t4 = t3 + [
    {"role": "assistant", "content": "CSRF is cross-site request forgery."},
    {"role": "user", "content": "Thanks. One more: what is SSRF?"},
]
time.sleep(2)
send(t4, "Turn 4 (short, expect 1024 cached)")
