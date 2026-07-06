from core.network import get
from core.logger import info, ok, error

SUBS = [
    "ArtificialIntelligence",
    "LocalLLaMA",
    "OpenAI"
]

def fetch(limit=3):
    """Fetch hot posts from Reddit subreddits"""
    info("Pobieram Reddit...")
    
    posts = []
    
    for sub in SUBS:
        try:
            url = f"https://www.reddit.com/r/{sub}/hot.json?limit={limit}"
            
            response = get(
                url,
                headers={"User-Agent": "LUMIR AIR"}
            )
            
            data = response.json()
            
            for item in data.get("data", {}).get("children", []):
                p = item.get("data", {})
                
                posts.append({
                    "subreddit": sub,
                    "title": p.get("title", ""),
                    "score": p.get("score", 0),
                    "url": "https://reddit.com" + p.get("permalink", "")
                })
        
        except Exception as e:
            error(f"Failed to fetch Reddit r/{sub}: {e}")
            continue
    
    ok(f"Pobrano {len(posts)} postów")
    
    return posts
