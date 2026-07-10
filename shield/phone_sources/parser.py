def parse_phoneinfoga(data):
    raw = data.get("raw", "")

    summary = []

    if "Social media:" in raw:
        summary.append("Sprawdzono publiczną obecność numeru w mediach społecznościowych.")

    if "Reputation:" in raw:
        summary.append("Sprawdzono publiczne źródła reputacyjne numeru.")

    if "Individuals:" in raw:
        summary.append("Sprawdzono publiczne powiązania numeru z osobami.")

    if "General:" in raw:
        summary.append("Przeszukano ogólnodostępne źródła internetowe.")

    return {
        "scanner_success": data.get("scanner_success", False),
        "categories_checked": raw.count("Results for"),
        "google_queries": raw.count("https://www.google.com/search"),
        "country_conflict": "Country: CU" in raw,
        "summary": summary
    }
