import json
from pathlib import Path

QUEUE = Path("data/music_queue.json")

def load():
    if QUEUE.exists():
        return json.loads(QUEUE.read_text())
    return []

def save(data):
    QUEUE.write_text(json.dumps(data, indent=2))

def next_track():
    queue = load()

    for track in queue:
        if track["status"] == "waiting":
            track["status"] = "processing"
            save(queue)
            return track

    return None

if __name__ == "__main__":
    track = next_track()

    if track:
        print("🎵 Analiza:")
        print(track["title"])
        print(track["artist"])
    else:
        print("Brak utworów.")
