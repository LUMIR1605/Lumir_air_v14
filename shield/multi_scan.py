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

    if scan_type == "email":
        email = email_scan(value)
        email["risk_score"] = calculate(email)
        report["modules"].append(email)

        breach = breach_scan(value)
        breach["risk_score"] = calculate(breach)
        report["modules"].append(breach)

        domain = domain_scan(value.split("@")[1])
        domain["risk_score"] = calculate(domain)
        report["modules"].append(domain)

    elif scan_type == "username":
        user = username_scan(value)
        user["risk_score"] = calculate(user)
        report["modules"].append(user)

    elif scan_type == "phone":
        phone = phone_scan(value)
        phone["risk_score"] = calculate(phone)
        report["modules"].append(phone)

        pf = parse_phoneinfoga(phoneinfoga_scan(value))
        report["fusion"] = fuse(phone, pf)
        report["coverage"] = coverage_calculate(phone, pf)

    elif scan_type == "domain":
        domain = domain_scan(value)
        domain["risk_score"] = calculate(domain)
        report["modules"].append(domain)

    elif scan_type == "url":
        url = url_scan(value)
        url["risk_score"] = calculate(url)
        report["modules"].append(url)

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
