from pathlib import Path

APP_NAME = "LUMIR AIR"
VERSION = "14.1.0"

ROOT = Path.home() / "lumir_air_v14"

DOWNLOADS = Path.home() / "storage" / "downloads" / "LUMIR"

REPORTS = DOWNLOADS
CACHE = ROOT / "cache"
LOGS = ROOT / "logs"

TIMEOUT = 20
MAX_RETRIES = 3
RETRY_BACKOFF = 2

HEADERS = {
    "User-Agent": "LUMIR AIR 14",
    "Accept": "application/json"
}

def init_paths():
    for directory in (DOWNLOADS, REPORTS, CACHE, LOGS):
        directory.mkdir(parents=True, exist_ok=True)

def get_reports():
    init_paths()
    return REPORTS

init_paths()
