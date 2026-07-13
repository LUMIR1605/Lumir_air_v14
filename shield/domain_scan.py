"""Local DNS-only domain analysis; web probing requires an approved source."""

import socket

import dns.resolver


def dns_records(domain):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    data = {}
    for record in ["A", "AAAA", "MX", "NS"]:
        try:
            data[record] = [str(item).rstrip(".") for item in resolver.resolve(domain, record)]
        except Exception:
            data[record] = []
    return data


def scan(domain):
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return {"module": "domain_scan", "domain": domain, "exists": False, "risk": "high", "findings": ["Domena nie istnieje lub nie odpowiada."], "scan_status": "error"}
    return {"module": "domain_scan", "domain": domain, "exists": True, "ip": ip, "https": None, "status_code": None, "server": "", "security_headers": {"status": "not_checked"}, "dns": dns_records(domain), "risk": "low", "findings": [], "scan_status": "completed"}
