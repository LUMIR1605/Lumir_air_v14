def scan(email: str):
    return {
        "module": "breach_scan",
        "email": email,
        "breaches_found": 0,
        "breaches": [],
        "risk": "low",
        "findings": []
    }
