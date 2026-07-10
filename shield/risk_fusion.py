def fuse(phone_scan, phoneinfoga):
    findings = []
    confidence = "HIGH"

    if phone_scan.get("valid"):
        findings.append("Numer został poprawnie zweryfikowany przez phonenumbers.")

    if phoneinfoga.get("country_conflict"):
        findings.append(
            "PhoneInfoga błędnie zinterpretowała kraj numeru. Wynik geolokalizacji został odrzucony."
        )

    if phoneinfoga.get("scanner_success"):
        findings.append(
            f'PhoneInfoga sprawdziła {phoneinfoga.get("google_queries", 0)} publicznych zapytań OSINT.'
        )

    return {
        "confidence": confidence,
        "findings": findings,
        "trusted_source": "phonenumbers"
    }
