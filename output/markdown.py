from pathlib import Path
from datetime import datetime

OUT = Path("/storage/emulated/0/Download/LUMIR")
OUT.mkdir(parents=True, exist_ok=True)

def save(text: str):
    name = f"radar_{datetime.now():%Y-%m-%d_%H-%M}.md"
    path = OUT / name
    path.write_text(text, encoding="utf-8")
    print(f"\n📄 Raport zapisany:\n{path}")
    return path
