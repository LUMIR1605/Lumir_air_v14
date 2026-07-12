from pathlib import Path

from core.compat import configure_stdio

SRC = Path.home() / "lumir_knowledge" / "podcast_001.txt"
OUT = Path("knowledge_engine/chunks")
SIZE = 12000


def main():
    configure_stdio()
    if not SRC.exists():
        raise SystemExit(f"Brak pliku: {SRC}")

    OUT.mkdir(parents=True, exist_ok=True)
    text = SRC.read_text(encoding="utf-8")

    for i in range(0, len(text), SIZE):
        chunk = text[i:i + SIZE]
        (OUT / f"chunk_{i // SIZE:03}.txt").write_text(chunk, encoding="utf-8")

    print(f"✅ Utworzono {len(list(OUT.glob('*.txt')))} fragmentów.")


if __name__ == "__main__":
    main()
