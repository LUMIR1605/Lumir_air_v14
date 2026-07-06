import json
import requests

from intelligence.music_collector import add

def fetch(query="melodic techno", limit=10):

    cfg = json.load(open("config/music_api.json"))
    key = cfg["youtube"]["api_key"]

    url = (
        "https://www.googleapis.com/youtube/v3/search"
        "?part=snippet"
        f"&q={query.replace(' ','+')}"
        "&type=video"
        f"&maxResults={limit}"
        f"&key={key}"
    )

    data = requests.get(url, timeout=30).json()

    for item in data.get("items", []):

        title = item["snippet"]["title"]
        channel = item["snippet"]["channelTitle"]
        video = item["id"]["videoId"]

        add(
            "youtube",
            title,
            channel,
            f"https://youtu.be/{video}"
        )

        print("✅", title)

if __name__ == "__main__":
    fetch()
