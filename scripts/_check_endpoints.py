import requests, os
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
key = os.getenv("OPENROUTER_API_KEY")

r = requests.get(
    "https://openrouter.ai/api/v1/models/deepseek/deepseek-v4-flash-0731/endpoints",
    headers={"Authorization": f"Bearer {key}"},
)
d = r.json()
for ep in d.get("data", {}).get("endpoints", []):
    p = ep.get("pricing", {})
    print(f"{ep.get('provider_name'):<15} input={p.get('prompt')} cache_read={p.get('prompt_cache_read')}")
