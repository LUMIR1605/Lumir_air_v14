from shield.action_plan import build as build_action_plan
from shield.ai_advisor import advise
from shield.attack_surface import analyze as attack_surface
from shield.breach_scan import scan as breach_scan
from shield.domain_scan import scan as domain_scan
from shield.email_scan import scan as email_scan
from shield.phone_scan import scan as phone_scan
from shield.truth import PROFILES, assessment, base_report, module_placeholder, normalize_module, source_record


def run(scan_type, value):
    report = base_report(scan_type, value)
    profile = PROFILES[scan_type]
    modules = []

    def add(scanner, target, name):
        try:
            module = scanner(target)
        except Exception as error:
            module = module_placeholder(name, "error", f"scanner error: {error}", profile[name])
        module.setdefault("sources", [source_record("local_dns", module.get("scan_status", "completed"), confidence=0.7)])
        modules.append(normalize_module(module, profile[name]))

    if scan_type == "email":
        add(email_scan, value, "email_scan")
        add(breach_scan, value, "breach_scan")
        modules.append(module_placeholder("account_exposure_scan", "blocked", "no approved account exposure source is configured", profile["account_exposure_scan"]))
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
    report.update(assessment(modules, scan_type))
    report["risk_score"] = {"score": report["security_assessment"]["score"], "risk": (report["security_assessment"]["rating"] or "unknown").upper()}
    report["risk"] = report["risk_score"]["risk"].lower()
    report["attack_surface"] = attack_surface(report)
    report["advice"] = advise({"risk": report["risk"]})
    report["action_plan"] = build_action_plan(report)
    report["executive_summary"] = [report["security_assessment"]["public_verdict"]]
    return report
