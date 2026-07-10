from pathlib import Path
import json

from intelligence.llm_engine import analyze

CHUNKS = Path("knowledge_engine/chunks")
OUT = Path("knowledge_engine/results")

OUT.mkdir(exist_ok=True)

for chunk in sorted(CHUNKS.glob("*.txt")):

    print(f"🧠 {chunk.name}")

    text = chunk.read_text(encoding="utf-8")

    result = analyze(text)

    out = OUT / (chunk.stem + ".json")

    out.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

print("✅ Wszystkie fragmenty przeanalizowane.")
