from shield.action_plan import build as build_action_plan
from shield.account_exposure_scan import scan as account_exposure_scan
from shield.ai_advisor import advise
from shield.attack_surface import analyze as attack_surface
from shield.breach_scan import scan as breach_scan
from shield.domain_scan import scan as domain_scan
from shield.email_scan import scan as email_scan
from shield.phone_scan import scan as phone_scan
from shield.truth import PROFILES, assessment, base_report, module_placeholder, normalize_module, source_record


_SERVICE_COUNT_KEYS = (
    "planned_count",
    "attempted_count",
    "checked_count",
    "confirmed_count",
    "probable_count",
    "not_found_count",
    "not_checked_count",
)
_SERVICE_TITLE = "Sprawd\u017a, co internet nadal pami\u0119ta o Tobie"
_SERVICE_EXPLANATION = "Wykryte us\u0142ugi s\u0105 sygna\u0142em technicznym, a nie potwierdzeniem istnienia konta."


def _service_report(module):
    supplied = module.get("services")
    supplied = supplied if isinstance(supplied, dict) else {}
    services = {
        key: value if isinstance(value := supplied.get(key), int) and value >= 0 else 0
        for key in _SERVICE_COUNT_KEYS
    }
    services["confirmed_count"] = 0
    results = supplied.get("results")
    services["results"] = results if isinstance(results, list) else []
    services["title"] = _SERVICE_TITLE
    services["explanation"] = _SERVICE_EXPLANATION
    return services


def run(scan_type, value, consent_declared=False):
    report = base_report(scan_type, value, consent_declared)
    profile = PROFILES[scan_type]
    modules = []

    def add(scanner, target, name, **scanner_kwargs):
        try:
            module = scanner(target, **scanner_kwargs)
        except Exception as error:
            module = module_placeholder(name, "error", f"scanner error: {error}", profile[name])
        module.setdefault("sources", [source_record("local_dns", module.get("scan_status", "completed"), confidence=0.7)])
        modules.append(normalize_module(module, profile[name]))

    if scan_type == "email":
        add(email_scan, value, "email_scan")
        add(breach_scan, value, "breach_scan")
        add(account_exposure_scan, value, "account_exposure_scan", consent_declared=consent_declared)
        add(domain_scan, value.split("@", 1)[1], "domain_scan")
    elif scan_type == "domain":
        add(domain_scan, value, "domain_scan")
        modules.extend([module_placeholder("dns_scan", "not_applicable", "covered by domain_scan", profile["dns_scan"]), module_placeholder("mail_security_scan", "not_applicable", "not applicable without a scanned mailbox", profile["mail_security_scan"]), module_placeholder("web_security_scan", "blocked", "direct web probing is not allowlisted", profile["web_security_scan"])])
    elif scan_type == "phone":
        add(phone_scan, value, "phone_scan")
    elif scan_type == "username":
        modules.append(module_placeholder("username_scan", "blocked", "no approved official account API is configured", profile["username_scan"]))
    elif scan_type == "url":
        modules.extend([module_placeholder("url_scan", "blocked", "direct web probing is not allowlisted", profile["url_scan"]), module_placeholder("domain_scan", "not_applicable", "not independently executed for URL scan", profile["domain_scan"]), module_placeholder("web_security_scan", "blocked", "direct web probing is not allowlisted", profile["web_security_scan"])])

    report["modules"] = modules
    account_exposure = next((module for module in modules if module.get("module") == "account_exposure_scan"), None)
    if account_exposure is not None:
        report["services"] = _service_report(account_exposure)
    report["request_log"] = [entry for module in modules for entry in module.get("request_log", [])]
    report["requests"] = {"attempted_count": len(report["request_log"]), "completed_count": len([entry for entry in report["request_log"] if entry["status"] == "completed"]), "failed_count": len([entry for entry in report["request_log"] if entry["status"] != "completed"]), "log_entries": report["request_log"]}
    if report["request_log"]:
        report["scan_mode"] = "online"
    report.update(assessment(modules, scan_type))
    report["risk_score"] = {"score": report["security_assessment"]["score"], "risk": (report["security_assessment"]["rating"] or "unknown").upper(), "deprecated": True}
    report["risk"] = report["risk_score"]["risk"].lower()
    report["attack_surface"] = attack_surface(report)
    report["advice"] = advise({"risk": report["risk"]})
    report["action_plan"] = build_action_plan(report)
    report["executive_summary"] = [report["security_assessment"]["public_verdict"]]
    return report
