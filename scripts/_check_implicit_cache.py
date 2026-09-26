import requests, os
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
key = os.getenv("OPENROUTER_API_KEY")

for model in ["z-ai/glm-5.3-flash", "deepseek/deepseek-v4-flash-0731"]:
    r = requests.get(
        f"https://openrouter.ai/api/v1/models/{model}/endpoints",
        headers={"Authorization": f"Bearer {key}"},
    )
    eps = r.json().get("data", {}).get("endpoints", [])
    print(f"\n=== {model} ===")
    for ep in eps:
        name = ep.get("provider_name", "?")
        cache_flag = ep.get("supports_implicit_caching")
        cache_price = ep.get("pricing", {}).get("input_cache_read")
        # Only show providers we've tested or that have cache pricing
        if cache_flag or (cache_price and cache_price != "0"):
            print(f"  {name:<15} tag={ep.get('tag', '?'):<18} implicit_cache={cache_flag} cache_read_price={cache_price}")
