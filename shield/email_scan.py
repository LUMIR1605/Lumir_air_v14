"""Evidence-based e-mail domain security controls."""

import re

import dns.exception
import dns.resolver


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SELECTORS = ("default", "google", "selector1", "selector2")


def _resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.lifetime = 8
    return resolver


def _error_code(error):
    if isinstance(error, dns.resolver.NXDOMAIN): return "DNS_NXDOMAIN"
    if isinstance(error, dns.resolver.NoAnswer): return "DNS_NO_ANSWER"
    if isinstance(error, (dns.resolver.LifetimeTimeout, dns.exception.Timeout)): return "DNS_TIMEOUT"
    if isinstance(error, dns.resolver.NoNameservers): return "DNS_NO_NAMESERVERS"
    return "DNS_UNEXPECTED_ERROR"


def _check(check_id, weight, status, *, points=None, evidence=None, error_code=None, reason=None):
    return {"check_id": check_id, "status": status, "weight": weight, "points_awarded": points, "evidence": evidence or {}, "error_code": error_code, "reason": reason}


def _txt_records(resolver, name):
    try:
        values = ["".join(item.decode() if isinstance(item, bytes) else item for item in answer.strings) for answer in resolver.resolve(name, "TXT")]
        return values, None
    except Exception as error:
        return [], _error_code(error)


def _score(checks):
    resolved = [item for item in checks if item["status"] in {"passed", "failed"}]
    if not resolved:
        return None
    return round(sum(item["points_awarded"] or 0 for item in resolved) / sum(item["weight"] for item in resolved) * 100)


def _risk(score):
    if score is None: return "unknown"
    if score >= 90: return "low"
    if score >= 70: return "medium"
    if score >= 40: return "high"
    return "critical"


def scan(email):
    checks = []
    if not EMAIL_RE.match(email):
        checks.append(_check("email_format", 10, "failed", points=0))
        return {"module": "email_scan", "email": email, "valid_format": False, "domain": "", "mx_records": [], "spf": None, "dmarc": None, "dkim": None, "score_basis": checks, "score": 0, "risk": "critical", "scan_status": "completed", "findings": ["Niepoprawny format adresu e-mail"], "exposure": {"status": "not_checked", "services": []}}
    checks.append(_check("email_format", 10, "passed", points=10))
    domain = email.split("@", 1)[1]
    resolver = _resolver()
    try:
        mx_records = sorted(str(item.exchange).rstrip(".") for item in resolver.resolve(domain, "MX"))
        checks.append(_check("mx_records", 25, "passed", points=25, evidence={"records": mx_records}))
    except Exception as error:
        code = _error_code(error); mx_records = []
        status = "failed" if code in {"DNS_NXDOMAIN", "DNS_NO_ANSWER"} else "error"
        checks.append(_check("mx_records", 25, status, points=0 if status == "failed" else None, evidence={"records": []}, error_code=code))
    txt, txt_error = _txt_records(resolver, domain)
    if txt_error:
        checks.append(_check("spf_record", 20, "error", points=None, evidence={"record": None}, error_code=txt_error))
    else:
        spf = next((item for item in txt if item.lower().startswith("v=spf1")), None)
        checks.append(_check("spf_record", 20, "passed" if spf else "failed", points=20 if spf else 0, evidence={"record": spf}))
    dmarc_txt, dmarc_error = _txt_records(resolver, f"_dmarc.{domain}")
    if dmarc_error:
        status = "failed" if dmarc_error in {"DNS_NXDOMAIN", "DNS_NO_ANSWER"} else "error"
        checks.append(_check("dmarc_record", 30, status, points=0 if status == "failed" else None, evidence={"record": None, "policy": None}, error_code=dmarc_error))
    else:
        record = next((item for item in dmarc_txt if item.lower().startswith("v=dmarc1")), None)
        policy = next((part.split("=", 1)[1].strip().lower() for part in (record or "").split(";") if part.strip().lower().startswith("p=")), None)
        points = {"reject": 30, "quarantine": 20, "none": 8}.get(policy)
        checks.append(_check("dmarc_record", 30, "passed" if points is not None else "failed", points=points or 0, evidence={"record": record, "policy": policy}))
    found = []
    selector_errors = []
    for selector in SELECTORS:
        records, error = _txt_records(resolver, f"{selector}._domainkey.{domain}")
        if records: found.extend(records)
        if error and error not in {"DNS_NXDOMAIN", "DNS_NO_ANSWER"}: selector_errors.append(error)
    if found:
        checks.append(_check("dkim_discovery", 15, "passed", points=15, evidence={"selectors_attempted": list(SELECTORS), "records_found": found}))
    elif selector_errors:
        checks.append(_check("dkim_discovery", 15, "error", points=None, evidence={"selectors_attempted": list(SELECTORS), "records_found": []}, error_code=selector_errors[0]))
    else:
        checks.append(_check("dkim_discovery", 15, "unknown", points=None, evidence={"selectors_attempted": list(SELECTORS), "records_found": []}, reason="DKIM cannot be reliably verified without a known selector"))
    score = _score(checks)
    resolved = sum(item["status"] in {"passed", "failed"} for item in checks)
    status = "completed" if resolved >= 4 else "partial"
    return {"module": "email_scan", "email": email, "valid_format": True, "domain": domain, "mx_records": mx_records, "spf": next((item["evidence"].get("record") for item in checks if item["check_id"] == "spf_record"), None), "dmarc": next((item["evidence"].get("policy") for item in checks if item["check_id"] == "dmarc_record"), None), "dkim": bool(found) if found else None, "score_basis": checks, "score": score if status == "completed" else None, "risk": _risk(score) if status == "completed" else "unknown", "scan_status": status, "findings": [], "exposure": {"status": "not_checked", "services": []}}
