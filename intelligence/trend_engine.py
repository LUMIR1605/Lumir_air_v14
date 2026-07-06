from collections import Counter
import re

STOPWORDS = {
    "the","and","for","with","from","into","using","your","this","that",
    "have","has","new","our","their","they","will","about","more","than",
    "are","you","can","its","open","source","free","github","python",
    "project","projects","list","available","public","apis","books","book",
    "design","primer","foundation","programming"
}

ALIASES = {
    "gpt":"GPT",
    "gpt-5":"GPT",
    "gpt-5.6":"GPT-5.6",
    "agent":"AI Agents",
    "agents":"AI Agents",
    "openai":"OpenAI",
    "anthropic":"Anthropic",
    "google":"Google",
    "gemini":"Gemini",
    "claude":"Claude",
    "medical":"Medical AI",
    "health":"Medical AI",
    "reasoning":"Reasoning",
    "inference":"Inference",
    "chip":"AI Hardware",
    "chips":"AI Hardware",
    "robot":"Robotics",
    "robotics":"Robotics",
    "video":"Video AI",
    "vision":"Vision AI",
}

def words(text):
    """Extract words from text"""
    return re.findall(r"[A-Za-z0-9.+-]{3,}", text.lower())

def analyze(repos, hn, models, news):
    """Analyze trends from collected data"""
    
    # Handle None/empty collections
    repos = repos or []
    hn = hn or []
    models = models or []
    news = news or []
    
    score = Counter()
    
    def feed(text):
        """Feed text into trend counter"""
        for w in words(text):
            if w in STOPWORDS:
                continue
            score[ALIASES.get(w, w.title())] += 1
    
    # Process repository descriptions
    for r in repos:
        feed(r.get("description", ""))
    
    # Hacker News
    for h in hn:
        feed(h.get("title", ""))
    
    # HuggingFace
    for m in models:
        feed(m.get("id", ""))
    
    # AI News
    for n in news:
        feed(n.get("title", ""))
    
    return score.most_common(15)
