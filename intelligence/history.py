import json
from core import config
from core.logger import error

FILE = None

def _get_file_path():
    """Get history file path lazily"""
    global FILE
    if FILE is None:
        FILE = config.get_data() / "history.json"
    return FILE

def load():
    """Load history from JSON file"""
    file_path = _get_file_path()
    if file_path.exists():
        try:
            return json.loads(file_path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}

def save(data):
    """Save history to JSON file"""
    file_path = _get_file_path()
    try:
        file_path.write_text(json.dumps(data, indent=2))
    except OSError as e:
        error(f"Failed to save history: {e}")
