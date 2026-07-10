import socket
import requests
import dns.resolver


def dns_records(domain):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    data = {}

    for record in ["A", "AAAA", "MX", "NS"]:
        try:
            data[record] = [
                str(r).rstrip(".")
                for r in resolver.resolve(domain, record)
            ]
        except Exception:
            data[record] = []

    return data


def scan(domain):
    findings = []

    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return {
            "module": "domain_scan",
            "domain": domain,
            "exists": False,
            "risk": "high",
            "findings": ["Domena nie istnieje lub nie odpowiada."]
        }

    https = False
    status = None
    server = ""

    try:
        r = requests.get(
            f"https://{domain}",
            timeout=8,
            allow_redirects=True
        )
        https = True
        status = r.status_code
        server = r.headers.get("Server", "")
    except Exception:
        pass

    return {
        "module": "domain_scan",
        "domain": domain,
        "exists": True,
        "ip": ip,
        "https": https,
        "status_code": status,
        "server": server,
        "security_headers": {
            "Strict-Transport-Security": "Strict-Transport-Security" in r.headers if https else False,
            "Content-Security-Policy": "Content-Security-Policy" in r.headers if https else False,
            "X-Frame-Options": "X-Frame-Options" in r.headers if https else False,
            "X-Content-Type-Options": "X-Content-Type-Options" in r.headers if https else False,
            "Referrer-Policy": "Referrer-Policy" in r.headers if https else False,
            "Permissions-Policy": "Permissions-Policy" in r.headers if https else False
        },
        "dns": dns_records(domain),
        "risk": "low" if https else "medium",
        "findings": findings
    }
