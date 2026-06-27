from core.network import get
from core.logger import info, ok

SUBS = [
    "ArtificialIntelligence",
    "LocalLLaMA",
    "OpenAI"
]

def fetch(limit=3):

    info("Pobieram Reddit...")

    posts = []

    for sub in SUBS:

        try:
            url = f"https://www.reddit.com/r/{sub}/hot.json?limit={limit}"

            data = get(
                url,
                headers={"User-Agent": "LUMIR AIR"}
            ).json()

            for item in data["data"]["children"]:

                p = item["data"]

                posts.append({
                    "subreddit": sub,
                    "title": p["title"],
                    "score": p["score"],
                    "url": "https://reddit.com" + p["permalink"]
                })

        except Exception:
            continue

    ok(f"Pobrano {len(posts)} postów")

    return posts
