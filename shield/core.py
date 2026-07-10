from shield.email_scan import scan as email_scan
from shield.username_scan import scan as username_scan
from shield.url_scan import scan as url_scan
from shield.domain_scan import scan as domain_scan
from shield.phone_scan import scan as phone_scan
from shield.risk_score import calculate
from shield.report_builder import build

SCANNERS = {
    "email": email_scan,
    "username": username_scan,
    "url": url_scan,
    "domain": domain_scan,
    "phone": phone_scan,
}

def detect_type(value):
    if value.startswith(("http://", "https://")):
        return "url"
    if "@" in value:
        return "email"
    if value.replace("+", "").replace(" ", "").isdigit():
        return "phone"
    if "." in value:
        return "domain"
    return "username"

def analyze(value):
    scan_type = detect_type(value)

    if scan_type not in SCANNERS:
        return {
            "type": scan_type,
            "status": "scanner_not_implemented"
        }

    result = SCANNERS[scan_type](value)
    result["risk_score"] = calculate(result)
    result["scan_type"] = scan_type

    build(result)

    return result
