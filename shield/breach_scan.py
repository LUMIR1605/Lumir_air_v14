import os
from urllib.parse import quote

import requests


def scan(email: str):
    api_key = os.getenv("LUMIR_HIBP_API_KEY")
    base = {
        "module": "breach_scan", "email": email, "breaches": [],
        "source": "Have I Been Pwned API v3", "confidence": "wysoka",
    }
    if not api_key:
        return {**base, "breaches_found": None, "risk": "unknown", "scan_status": "unavailable",
                "explanation": "Ustaw LUMIR_HIBP_API_KEY, aby wykonać sprawdzenie Have I Been Pwned.",
                "findings": ["Nie skonfigurowano klucza publicznego źródła wycieków."]}
    try:
        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}",
            headers={"hibp-api-key": api_key, "user-agent": "Lumir-SHIELD"}, timeout=15,
        )
        if response.status_code == 404:
            return {**base, "breaches_found": 0, "risk": "low", "scan_status": "completed",
                    "explanation": "Nie znaleziono wpisów dla adresu w sprawdzonym źródle.", "findings": []}
        response.raise_for_status()
        breaches = response.json()
        names = [item.get("Name", "Nieznane źródło") for item in breaches]
        return {**base, "breaches_found": len(names), "breaches": names, "risk": "high" if names else "low",
                "scan_status": "completed", "explanation": "Wynik pochodzi z Have I Been Pwned.",
                "findings": [f"Znaleziono {len(names)} wpisów w publicznym źródle wycieków."] if names else []}
    except requests.Timeout:
        return {**base, "breaches_found": None, "risk": "unknown", "scan_status": "timeout",
                "explanation": "Przekroczono czas oczekiwania na źródło wycieków.", "findings": ["Nie udało się zakończyć sprawdzenia źródła wycieków."]}
    except requests.RequestException as error:
        return {**base, "breaches_found": None, "risk": "unknown", "scan_status": "error",
                "explanation": "Źródło wycieków nie odpowiedziało poprawnie.", "findings": [f"Nie udało się sprawdzić źródła wycieków: {error}"]}
