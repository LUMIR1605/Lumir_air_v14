import json
from core import config
from core.logger import error

QUEUE_FILE = None

def _get_queue_file():
    """Get music queue file path lazily"""
    global QUEUE_FILE
    if QUEUE_FILE is None:
        QUEUE_FILE = config.get_data() / "music_queue.json"
    return QUEUE_FILE

def load():
    """Load music queue from JSON file"""
    file_path = _get_queue_file()
    if file_path.exists():
        try:
            return json.loads(file_path.read_text())
        except (json.JSONDecodeError, OSError):
            return []
    return []

def save(data):
    """Save music queue to JSON file"""
    file_path = _get_queue_file()
    try:
        file_path.write_text(json.dumps(data, indent=2))
    except OSError as e:
        error(f"Failed to save music queue: {e}")

def next_track():
    """Get next track from queue with waiting status"""
    queue = load()
    
    for track in queue:
        if track.get("status") == "waiting":
            track["status"] = "processing"
            save(queue)
            return track
    
    return None

if __name__ == "__main__":
    track = next_track()
    
    if track:
        print("🎵 Analiza:")
        print(track.get("title", ""))
        print(track.get("artist", ""))
    else:
        print("Brak utworów.")
