"""Local report storage. Never relies on Documents or OneDrive."""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path


def reports_directory() -> Path:
    profile = Path(os.environ.get("USERPROFILE", str(Path.home())))
    return profile / "Lumir SHIELD" / "Reports"


def ensure_reports_directory() -> Path:
    directory = reports_directory()
    directory.mkdir(parents=True, exist_ok=True)
    probe = directory / ".lumir-write-check"
    probe.write_text("ok", encoding="utf-8")
    probe.unlink()
    return directory


def report_paths(scan_type: str, target: str) -> dict[str, Path]:
    directory = ensure_reports_directory()
    safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("_") or "scan"
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = f"Lumir_SHIELD_{scan_type}_{safe_target}_{timestamp}"
    return {"json": directory / f"{stem}.json", "html": directory / f"{stem}.html", "pdf": directory / f"{stem}.pdf"}
