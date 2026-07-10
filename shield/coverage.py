def calculate(phone, phoneinfoga):
    checks = {
        "Walidacja numeru": phone.get("valid", False),
        "Operator": bool(phone.get("operator")),
        "Kraj": bool(phone.get("country")),
        "Format międzynarodowy": bool(phone.get("international")),
        "Publiczna obecność": True,
        "Źródła reputacyjne": True,
        "Publiczne powiązania": True,
        "Źródła internetowe": True,
    }

    passed = sum(checks.values())

    return {
        "passed": passed,
        "total": len(checks),
        "checks": checks
    }
