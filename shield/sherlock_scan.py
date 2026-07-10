import subprocess

SITES = [
    "GitHub",
    "Reddit",
    "Instagram",
    "TikTok",
    "LinkedIn"
]

def scan(username):
    cmd = ["sherlock", username]

    for site in SITES:
        cmd += ["--site", site]

    cmd += ["--print-found"]

    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        services = []

        for line in r.stdout.splitlines():
            if "https://" in line:
                services.append(line.strip())

        return {
            "module": "sherlock",
            "checked": len(SITES),
            "found": len(services),
            "services": services,
            "risk": "medium" if services else "low"
        }

    except Exception as e:
        return {
            "module": "sherlock",
            "checked": len(SITES),
            "found": 0,
            "services": [],
            "risk": "unknown",
            "error": str(e)
        }
