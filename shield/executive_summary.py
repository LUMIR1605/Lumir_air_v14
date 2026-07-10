def build(report):
    score = report["modules"][0]["risk_score"]["score"]

    summary = []

    if score >= 90:
        summary.append("Nie wykryto krytycznych zagrożeń.")
    elif score >= 70:
        summary.append("Wykryto niewielkie ryzyko wymagające uwagi.")
    elif score >= 40:
        summary.append("Wykryto podwyższone ryzyko bezpieczeństwa.")
    else:
        summary.append("Wykryto krytyczne zagrożenia wymagające natychmiastowej reakcji.")

    for module in report["modules"]:
        if module["module"] == "email_scan" and module.get("valid_format"):
            summary.append("Adres e-mail jest poprawny.")

        if module["module"] == "domain_scan" and module.get("https"):
            summary.append("Domena obsługuje HTTPS.")

        if module["module"] == "breach_scan":
            if module.get("breaches_found", 0) == 0:
                summary.append("Nie wykryto znanych wycieków danych.")

    return summary
