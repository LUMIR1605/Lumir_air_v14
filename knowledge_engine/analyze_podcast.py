from pathlib import Path
from intelligence.llm_engine import analyze
import json

podcast = Path.home() / "lumir_knowledge" / "podcast_001.txt"

text = podcast.read_text(encoding="utf-8")

print("🧠 Analiza podcastu...")

result = analyze(text)

out = Path("knowledge_engine") / "knowledge.json"

out.write_text(
    json.dumps(result, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

print(f"✅ Zapisano: {out}")
