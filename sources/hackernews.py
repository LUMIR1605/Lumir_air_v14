from core.network import get
from core.logger import info, ok, error

URL = "https://hn.algolia.com/api/v1/search"

def fetch(limit=10):
    """Fetch stories from Hacker News"""
    info("Pobieram Hacker News...")
    
    try:
        response = get(
            URL,
            params={
                "query": "AI",
                "tags": "story",
                "hitsPerPage": limit
            }
        )
        
        data = response.json()
        
        hits = data.get("hits", [])
        
        ok(f"Pobrano {len(hits)} artykułów")
        
        return hits
    
    except Exception as e:
        error(str(e))
        return []
