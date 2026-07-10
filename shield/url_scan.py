import socket
import requests

HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def scan(url):
    result = {
        "module": "url_scan",
        "url": url,
        "https": url.startswith("https://"),
        "status_code": None,
        "server": "",
        "final_url": "",
        "ip": "",
        "security_headers": {},
        "risk": "low",
        "findings": []
    }

    try:
        r = requests.get(url, timeout=10, allow_redirects=True)

        result["status_code"] = r.status_code
        result["server"] = r.headers.get("Server", "")
        result["final_url"] = r.url

        host = r.url.split("/")[2]
        result["ip"] = socket.gethostbyname(host)

        for h in HEADERS:
            result["security_headers"][h] = h in r.headers

        if not result["https"]:
            result["risk"] = "high"
            result["findings"].append("Brak HTTPS")

        elif r.status_code >= 400:
            result["risk"] = "medium"

    except Exception as e:
        result["risk"] = "high"
        result["findings"].append(str(e))

    return result
