"""Test routing GLM to Novita via tag (novita/fp8) — does it enable caching?"""
import os, time, uuid, requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
API_KEY = os.getenv("OPENROUTER_API_KEY")
URL = "https://openrouter.ai/api/v1/chat/completions"
SESSION = f"tagtest-{uuid.uuid4().hex[:8]}"

SYSTEM = "You are a security assistant. " * 40  # ~500 tokens

def send(model, provider_order, label):
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": "What is XSS? One sentence."},
        ],
        "max_tokens": 50,
        "stream": False,
        "session_id": SESSION,
    }
    if provider_order:
        body["provider"] = {"order": provider_order, "allow_fallbacks": False}
    h = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "X-Session-ID": SESSION,
        "X-OpenRouter-Cache": "true",
    }
    r = requests.post(URL, headers=h, json=body, timeout=90)
    if r.status_code != 200:
        print(f"{label:<40} ERROR {r.status_code}: {r.text[:150]}")
        return
    u = r.json().get("usage", {})
    provider = r.headers.get("X-OpenRouter-Provider") or r.json().get("provider", "?")
    cached = (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
    print(f"{label:<40} provider={provider:<12} prompt={u.get('prompt_tokens', 0):>5} cached={cached}")

# Test 1: tag in provider.order
send("z-ai/glm-5.3-flash", ["novita/fp8"], "A: order=[novita/fp8]")
time.sleep(2)
# Test 2: tag in model slug
send("z-ai/glm-5.3-flash:novita/fp8", None, "B: model=:novita/fp8")
time.sleep(2)
# Test 3: plain Novita (baseline, known no-cache)
send("z-ai/glm-5.3-flash", ["Novita"], "C: order=[Novita] (baseline)")
