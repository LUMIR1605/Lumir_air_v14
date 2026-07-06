import json
from pathlib import Path

FILE = Path("data/music_queue.json")

def load():
    if FILE.exists():
        return json.loads(FILE.read_text())
    return []

def save(queue):
    FILE.write_text(json.dumps(queue, indent=2))

def add(source, title, artist="", url=""):
    queue = load()

    item = {
        "source": source,
        "title": title,
        "artist": artist,
        "url": url,
        "status": "waiting"
    }

    if item not in queue:
        queue.append(item)
        save(queue)

    return queue
