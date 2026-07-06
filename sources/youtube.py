import json
import requests
from core import config
from core.logger import info, ok, error
from intelligence.music_collector import add

def fetch(query="melodic techno", limit=10):
    """Fetch YouTube videos"""
    info("Pobieram YouTube...")
    
    # Get API key from config
    key = config.YOUTUBE_API_KEY
    if not key:
        error("YouTube API key not set. Set YOUTUBE_API_KEY env var or config/music_api.json")
        return []
    
    try:
        url = (
            "https://www.googleapis.com/youtube/v3/search"
            "?part=snippet"
            f"&q={query.replace(' ','+')}"
            "&type=video"
            f"&maxResults={limit}"
            f"&key={key}"
        )
        
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        for item in data.get("items", []):
            try:
                title = item["snippet"]["title"]
                channel = item["snippet"]["channelTitle"]
                video = item["id"]["videoId"]
                
                add(
                    "youtube",
                    title,
                    channel,
                    f"https://youtu.be/{video}"
                )
                
                ok(f"Found: {title}")
            except KeyError as e:
                error(f"Invalid YouTube item structure: {e}")
                continue
        
        ok(f"Pobrano {len(data.get('items', []))} wyników YouTube")
        return data.get('items', [])
    
    except requests.exceptions.RequestException as e:
        error(f"YouTube API error: {e}")
        return []

if __name__ == "__main__":
    fetch()
