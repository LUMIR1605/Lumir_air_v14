from core.network import get
from core.logger import info, ok, error

URL = "https://api.github.com/search/repositories"

def fetch(limit=10):
    """Fetch trending Python repositories from GitHub"""
    info("Pobieram GitHub Trending...")
    
    params = {
        "q": "language:Python stars:>1000",
        "sort": "stars",
        "order": "desc",
        "per_page": limit,
    }
    
    try:
        response = get(URL, params=params)
        data = response.json()
        
        repos = data.get("items", [])
        
        ok(f"Pobrano {len(repos)} repozytoriów")
        
        return repos
    
    except Exception as e:
        error(str(e))
        return []
