from shield.multi_scan import run
from shield.report_builder import build

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

    result = run(scan_type, value)
    build(result)
    return result
