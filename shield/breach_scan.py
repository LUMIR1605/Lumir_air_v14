def scan(email: str):
    """Report the real state until a public breach provider is configured."""
    return {
        "module": "breach_scan",
        "email": email,
        "breaches_found": None,
        "breaches": [],
        "risk": "unknown",
        "scan_status": "unavailable",
        "source": "Brak skonfigurowanego publicznego źródła wycieków",
        "confidence": "brak",
        "explanation": "Moduł nie połączył się z bazą wycieków, dlatego wynik nie oznacza braku wycieków.",
        "findings": ["Nie udało się sprawdzić publicznych źródeł wycieków."],
    }
