"""Shared truthful Account Discovery presentation for RC6 reports."""
def details(report):
    module = next((m for m in report.get("modules", []) if m.get("module") == "account_exposure_scan"), {})
    services = module.get("services") or {}
    rows = [("Status", str(module.get("scan_status", "unavailable"))),
            ("Źródło", "Holehe — lokalny CLI"),
            ("Ograniczenie", "Prawdopodobne sygnały nie potwierdzają kont ani własności. Nie wpływają na scoring."),
            ("Sprawdzone źródła", str(services.get("checked_count", 0)))]
    for item in services.get("results", []):
        rows.append((str(item.get("service_name", "Brak nazwy")), "Prawdopodobny sygnał · niska pewność · własność niepotwierdzona"))
    if not services.get("results"):
        rows.append(("Wynik", "Brak potwierdzonych danych o kontach. Nie oznacza to braku kont."))
    return rows
