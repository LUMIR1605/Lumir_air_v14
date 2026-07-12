from pathlib import Path
import json

from core.compat import configure_stdio
from intelligence.llm_engine import analyze

PODCAST = Path.home() / "lumir_knowledge" / "podcast_001.txt"


def main():
    configure_stdio()
    if not PODCAST.exists():
        raise SystemExit(f"Brak pliku: {PODCAST}")

    text = PODCAST.read_text(encoding="utf-8")

    print("🧠 Analiza podcastu...")

    result = analyze(text)
    out = Path("knowledge_engine") / "knowledge.json"

    out.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"✅ Zapisano: {out}")


if __name__ == "__main__":
    main()
