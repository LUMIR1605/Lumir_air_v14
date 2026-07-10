import re
import dns.resolver
from shield.holehe_scan import scan as holehe_scan

EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

def scan(email):
    result = {
        "module": "email_scan",
        "email": email,
        "valid_format": False,
        "domain": "",
        "mx_records": [],
        "spf": False,
        "dmarc": False,
        "dkim": False,
        "risk": "unknown",
        "findings": [],
        "exposure": {}
    }

    if not EMAIL_RE.match(email):
        result["findings"].append("Niepoprawny format adresu e-mail")
        result["risk"] = "high"
        return result

    result["valid_format"] = True
    domain = email.split("@")[1]
    result["domain"] = domain

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    try:
        answers = resolver.resolve(domain, "MX")
        result["mx_records"] = sorted(
            str(r.exchange).rstrip(".") for r in answers
        )
    except Exception as e:
        result["findings"].append(f"Brak rekordów MX: {e}")

    try:
        for r in resolver.resolve(domain, "TXT"):
            txt = "".join(
                x.decode() if isinstance(x, bytes) else x
                for x in r.strings
            )
            if txt.startswith("v=spf1"):
                result["spf"] = True
    except:
        pass

    try:
        resolver.resolve("_dmarc." + domain, "TXT")
        result["dmarc"] = True
    except:
        pass

    for selector in ["default","google","selector1","selector2"]:
        try:
            resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            result["dkim"] = True
            break
        except:
            pass

    result["exposure"] = holehe_scan(email)

    result["risk"] = "low" if result["mx_records"] else "high"

    return result
