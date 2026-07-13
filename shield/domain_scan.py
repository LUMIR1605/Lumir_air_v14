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
    records = dns_records(domain)
    checks = [
        {"check_id": "domain_resolution", "status": "passed", "weight": 30, "points_awarded": 30, "evidence": {"ip": ip}},
        {"check_id": "address_records", "status": "passed" if records["A"] or records["AAAA"] else "failed", "weight": 20, "points_awarded": 20 if records["A"] or records["AAAA"] else 0, "evidence": {"A": records["A"], "AAAA": records["AAAA"]}},
        {"check_id": "mx_records", "status": "passed" if records["MX"] else "failed", "weight": 30, "points_awarded": 30 if records["MX"] else 0, "evidence": {"records": records["MX"]}},
        {"check_id": "ns_records", "status": "passed" if records["NS"] else "failed", "weight": 20, "points_awarded": 20 if records["NS"] else 0, "evidence": {"records": records["NS"]}},
    ]
    score = sum(item["points_awarded"] for item in checks)
    return {"module": "domain_scan", "presentation_name": "Domain DNS Availability", "domain": domain, "exists": True, "ip": ip, "https": None, "status_code": None, "server": "", "security_headers": {"status": "not_checked"}, "dns": records, "score_basis": checks, "score": score, "risk": "low" if score >= 90 else "medium" if score >= 70 else "high" if score >= 40 else "critical", "findings": [], "scan_status": "completed"}
