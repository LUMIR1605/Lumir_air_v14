from pathlib import Path

APP_NAME = "LUMIR AIR"
VERSION = "14.1.0"

ROOT = Path.home() / "lumir_air_v14"

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

def init_paths():
    for directory in (DOWNLOADS, REPORTS, DATA, CACHE, LOGS):
        directory.mkdir(parents=True, exist_ok=True)

def get_reports():
    init_paths()
    return REPORTS

def get_data():
    init_paths()
    return DATA

def calculate_backoff(attempt):
    return RETRY_DELAY * (RETRY_BACKOFF ** attempt)

init_paths()
