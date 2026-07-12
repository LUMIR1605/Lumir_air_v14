from datetime import datetime
from core import config
from core.logger import ok

def save(text: str):
    """Save report to reports directory"""
    reports_dir = config.get_reports()
    name = f"radar_{datetime.now():%Y-%m-%d_%H-%M}.md"
    path = reports_dir / name
    path.write_text(text, encoding="utf-8")
    ok(f"Raport zapisany: {path}")
    return path
