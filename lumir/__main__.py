from core.compat import configure_stdio
from core import config
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

configure_stdio()

def main():
    # Initialize config and directories early
    config.init_paths()
    
    header()
    report = []
    
    section("🐙 GitHub")
    repos = github(3)
    for r in repos:
        print(f"⭐ {r.get('full_name', 'N/A')}")
        report.append(f"- GitHub: {r.get('full_name', 'N/A')}")
    
    section("📰 Hacker News")
    stories = hacker(3)
    for s in stories:
        print(f"📰 {s.get('title', 'N/A')}")
        report.append(f"- HN: {s.get('title', 'N/A')}")
    
    section("🤗 Hugging Face")
    models = hugging(3)
    for m in models:
        print(f"🤖 {m.get('id', 'N/A')}")
        report.append(f"- HF: {m.get('id', 'N/A')}")
    
    section("🚀 AI News")
    ai = news()
    for n in ai:
        print(f"📰 {n.get('title', 'N/A')}")
        report.append(f"- AI: {n.get('title', 'N/A')}")
    
    section("👽 Reddit")
    posts = reddit(3)
    for p in posts[:6]:
        print(f"💬 r/{p.get('subreddit', 'N/A')} • {p.get('title', 'N/A')}")
        report.append(f"- Reddit: {p.get('title', 'N/A')}")
    
    context = build(repos, stories, models, ai)
    
    trends = trend_engine(repos, stories, models, ai)
    
    section("📈 Trendy dnia")
    for word, score in trends[:10]:
        print(f"{word:<20} {score}")
    
    result = {}
    try:
        result = llm_analyze(context)
    except Exception as e:
        print(f"⚠ LLM: {e}")
        result = analyze(repos, stories, models)
    
    discover(result)
    
    memory = compare(result)
    
    section("🧠 Pamięć Lumíra")
    print(memory.get("message", "N/A"))
    report.append("\n## Pamięć\n" + memory.get("message", "N/A"))
    
    section("💰 Okazja dnia")
    opp = result.get("opportunity", "N/A")
    print(opp)
    report.append("\n## Okazja dnia\n" + opp)
    
    section("🎬 Pomysł na film")
    video = result.get("video") or "Brak"
    print(video)
    report.append("\n## Pomysł na film\n" + video)
    
    section("🎵 Prompt Suno")
    suno = result.get("suno") or "Brak"
    print(suno)
    report.append("\n## Prompt Suno\n" + suno)
    
    report.append("\n## Context AI\n")
    report.append(context)
    
    save("\n".join(report))

if __name__ == "__main__":
    main()
