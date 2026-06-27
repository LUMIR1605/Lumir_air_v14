import json
from pathlib import Path

FILE = Path("data/history.json")

def load():
    if FILE.exists():
        return json.loads(FILE.read_text())
    return {}

def save(data):
    FILE.write_text(json.dumps(data, indent=2))
