from shield.multi_scan import run
from shield.report_builder import build
from shield.input_validation import normalize

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

def analyze(value, *, consent_declared=False, requested_type="auto"):
    legacy_type = detect_type(value)
    if requested_type == "auto" and legacy_type in {"domain", "url"}:
        result = run(legacy_type, value, consent_declared=consent_declared)
        build(result)
        return result
    normalized = normalize(value, requested_type)
    scan_type = normalized.scan_type
    result = run(scan_type, normalized.value, consent_declared=consent_declared)
    build(result)
    return result
