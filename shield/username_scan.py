import requests
from shield.sherlock_scan import scan as sherlock_scan

SITES = {
    "GitHub": "https://github.com/{}",
    "Reddit": "https://reddit.com/user/{}",
    "GitLab": "https://gitlab.com/{}",
    "HuggingFace": "https://huggingface.co/{}"
}

def scan(username):
    accounts = []

    for name, url in SITES.items():
        try:
            r = requests.get(
                url.format(username),
                timeout=8,
                headers={"User-Agent": "LumirShield/1.0"}
            )

            if r.status_code == 200:
                accounts.append({
                    "site": name,
                    "url": url.format(username),
                    "exists": True
                })

        except Exception:
            pass

    sherlock = sherlock_scan(username)

    return {
        "module": "username_scan",
        "username": username,
        "accounts_found": len(accounts),
        "accounts": accounts,
        "sherlock": sherlock,
        "risk": "medium" if (accounts or sherlock["found"]) else "low",
        "findings": []
    }
