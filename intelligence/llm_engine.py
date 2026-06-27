import json
import requests

from intelligence.reasoning_engine import build_prompt

URL = "http://127.0.0.1:11434/api/generate"
MODEL = "lumir:latest"

def analyze(context):

    r = requests.post(
        URL,
        json={
            "model": MODEL,
            "prompt": build_prompt(context),
            "stream": False,
            "format": "json"
        },
        timeout=300
    )

    r.raise_for_status()

    data = r.json()

    print(data["response"])
    return json.loads(data["response"])
