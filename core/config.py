from pathlib import Path

APP_NAME = "LUMIR AIR"
VERSION = "14.1.0"

ROOT = Path.home() / "lumir_air_v14"
LOCAL_ROOT = Path.cwd() / ".lumir"

DOWNLOADS = Path.home() / "storage" / "downloads" / "LUMIR"

REPORTS = DOWNLOADS
DATA = ROOT / "data"
CACHE = ROOT / "cache"
LOGS = ROOT / "logs"

TIMEOUT = 20
MAX_RETRIES = 3
RETRY_BACKOFF = 2
RETRY_DELAY = 1

ENABLE_LLM = False
OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3"
OLLAMA_TIMEOUT = 60
OLLAMA_MAX_RETRIES = 2
YOUTUBE_API_KEY = ""

HEADERS = {
    "User-Agent": "LUMIR AIR 14",
    "Accept": "application/json"
}

def _ensure_writable(directory, fallback):
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".write_test"
        probe.write_text("", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return directory
    except OSError:
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

def init_paths():
    for directory in (DOWNLOADS, REPORTS, DATA, CACHE, LOGS):
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

def get_reports():
    return _ensure_writable(REPORTS, LOCAL_ROOT / "reports")

def get_data():
    return _ensure_writable(DATA, LOCAL_ROOT / "data")

def calculate_backoff(attempt):
    return RETRY_DELAY * (RETRY_BACKOFF ** attempt)

init_paths()
