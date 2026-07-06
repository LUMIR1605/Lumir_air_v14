from engine.report import header, section
from output.markdown import save

from sources.github import fetch as github
from sources.hackernews import fetch as hacker
from sources.huggingface import fetch as hugging
from sources.news import fetch as news
from sources.reddit import fetch as reddit

from intelligence.analyze import analyze
from intelligence.trend_engine import analyze as trend_engine
from intelligence.context_builder import build
from intelligence.llm_engine import analyze as llm_analyze
from intelligence.discovery_engine import discover
from intelligence.memory_engine import compare

def main():

    header()
    report = []

    section("🐙 GitHub")
    repos = github(3)
    for r in repos:
        print(f"⭐ {r['full_name']}")
        report.append(f"- GitHub: {r['full_name']}")

    section("📰 Hacker News")
    stories = hacker(3)
    for s in stories:
        print(f"📰 {s['title']}")
        report.append(f"- HN: {s['title']}")

    section("🤗 Hugging Face")
    models = hugging(3)
    for m in models:
        print(f"🤖 {m['id']}")
        report.append(f"- HF: {m['id']}")

    section("🚀 AI News")
    ai = news()
    for n in ai:
        print(f"📰 {n['title']}")
        report.append(f"- AI: {n['title']}")

    section("👽 Reddit")
    posts = reddit(3)
    for p in posts[:6]:
        print(f"💬 r/{p['subreddit']} • {p['title']}")
        report.append(f"- Reddit: {p['title']}")

    context = build(repos, stories, models, ai)

    trends = trend_engine(repos, stories, models, ai)

    section("📈 Trendy dnia")
    for word, score in trends[:10]:
        print(f"{word:<20} {score}")

    try:
        result = llm_analyze(context)
    except Exception as e:
        print(f"⚠ LLM: {e}")
        result = analyze(repos, stories, models)

    discover(result)

    memory = compare(result)

    section("🧠 Pamięć Lumíra")
    print(memory["message"])
    report.append("\n## Pamięć\n" + memory["message"])

    section("💰 Okazja dnia")
    print(result["opportunity"])
    report.append("\n## Okazja dnia\n" + result["opportunity"])

    section("🎬 Pomysł na film")
    print(result.get("video") or "Brak")
    report.append("\n## Pomysł na film\n" + (result.get("video") or "Brak"))

    section("🎵 Prompt Suno")
    print(result.get("suno") or "Brak")
    report.append("\n## Prompt Suno\n" + (result.get("suno") or "Brak"))

    report.append("\n## Context AI\n")
    report.append(context)

    save("\n".join(report))

if __name__ == "__main__":
    main()
