from shield.email_scan import scan as email_scan
from shield.username_scan import scan as username_scan
from shield.phone_scan import scan as phone_scan
from shield.domain_scan import scan as domain_scan
from shield.url_scan import scan as url_scan
from shield.breach_scan import scan as breach_scan
from shield.ai_advisor import advise
from shield.action_plan import build as build_action_plan
from shield.executive_summary import build as build_summary
from shield.attack_surface import analyze as attack_surface
from shield.risk_score import calculate
from shield.risk_fusion import fuse
from shield.coverage import calculate as coverage_calculate
from shield.phone_sources.phoneinfoga import scan as phoneinfoga_scan
from shield.phone_sources.parser import parse_phoneinfoga

def run(scan_type, value):
    report = {
        "scan_type": scan_type,
        "target": value,
        "modules": []
    }

    def add(scanner, target):
        try:
            module = scanner(target)
        except Exception as error:
            module = {
                "module": getattr(scanner, "__name__", "scanner"),
                "risk": "unknown",
                "scan_status": "error",
                "source": "Lumir SHIELD",
                "confidence": "brak",
                "findings": [f"Błąd częściowy modułu: {error}"],
            }
        module["risk_score"] = calculate(module)
        report["modules"].append(module)
        return module

    if scan_type == "email":
        add(email_scan, value)
        add(breach_scan, value)
        add(domain_scan, value.split("@", 1)[1])

    elif scan_type == "username":
        add(username_scan, value)

    elif scan_type == "phone":
        phone = add(phone_scan, value)

        pf = parse_phoneinfoga(phoneinfoga_scan(value))
        report["fusion"] = fuse(phone, pf)
        report["coverage"] = coverage_calculate(phone, pf)

    elif scan_type == "domain":
        add(domain_scan, value)

    elif scan_type == "url":
        add(url_scan, value)

    report["risk_score"] = calculate(report["modules"])
    report["risk"] = report["risk_score"]["risk"].lower()

    report["attack_surface"] = attack_surface(report)

    report["advice"] = advise({
        "risk": max(
            (m.get("risk", "low") for m in report["modules"]),
            default="low"
        )
    })

    report["action_plan"] = build_action_plan(report)
    report["executive_summary"] = build_summary(report)

    return report
