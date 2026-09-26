import requests, os, json
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
key = os.getenv("OPENROUTER_API_KEY")

r = requests.get(
    "https://openrouter.ai/api/v1/models/z-ai/glm-5.3-flash/endpoints",
    headers={"Authorization": f"Bearer {key}"},
)
d = r.json()
eps = d.get("data", {}).get("endpoints", [])
print(f"Total endpoints: {len(eps)}\n")
for ep in eps:
    name = ep.get("provider_name", "?")
    if name.lower() in ("novita", "z.ai", "zai"):
        print(f"=== {name} ===")
        print(json.dumps(ep, indent=2)[:1200])
        print()
