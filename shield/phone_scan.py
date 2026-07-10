import phonenumbers
from phonenumbers import carrier, geocoder
from shield.phone_sources.engine import run as run_sources

def scan(number):
    result = {
        "module": "phone_scan",
        "number": number,
        "valid": False,
        "country": "",
        "operator": "",
        "international": "",
        "risk": "high",
        "findings": [],
        "sources": []
    }

    try:
        parsed = phonenumbers.parse(number, "PL")

        result["valid"] = phonenumbers.is_valid_number(parsed)
        result["international"] = phonenumbers.format_number(
            parsed,
            phonenumbers.PhoneNumberFormat.INTERNATIONAL
        )
        result["country"] = geocoder.description_for_number(parsed, "pl")
        result["operator"] = carrier.name_for_number(parsed, "pl")

        if result["valid"]:
            result["risk"] = "low"
        else:
            result["findings"].append("Nieprawidłowy numer telefonu")

    except Exception as e:
        result["findings"].append(str(e))

    result["sources"] = run_sources(number)

    return result
