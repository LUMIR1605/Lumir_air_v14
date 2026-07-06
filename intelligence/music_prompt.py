import requests

URL = "http://127.0.0.1:11434/api/generate"
MODEL = "lumir:latest"

def generate(topic):
    prompt = f"""
You are an expert music producer.

Write a professional Suno AI v5.5 prompt in English.

Theme:
{topic}

The prompt must include:
- genre
- BPM
- mood
- atmosphere
- instruments
- vocal style
- production quality
- song structure
- emotional progression

Return ONLY the Suno prompt.
"""

    r = requests.post(
        URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        },
        timeout=300,
    )

    r.raise_for_status()
    return r.json()["response"]
