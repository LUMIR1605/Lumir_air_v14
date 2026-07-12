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

def save(queue):
    """Save music queue to JSON file"""
    file_path = _get_queue_file()
    try:
        file_path.write_text(json.dumps(queue, indent=2))
    except OSError as e:
        error(f"Failed to save music queue: {e}")

def add(source, title, artist="", url=""):
    """Add item to music queue"""
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
