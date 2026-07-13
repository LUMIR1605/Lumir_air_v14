def build(report):
    score = report.get("risk_score", {}).get("score", 0)

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
            if module.get("scan_status") == "completed" and module.get("breaches_found", 0) == 0:
                summary.append("Nie wykryto znanych wycieków danych.")
            elif module.get("scan_status") != "completed":
                summary.append("Nie udało się sprawdzić publicznych źródeł wycieków.")

    return summary
