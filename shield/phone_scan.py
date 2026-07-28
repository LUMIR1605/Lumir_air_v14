"""Local phone-number metadata validation; no reverse lookup or person identification."""

import phonenumbers
from phonenumbers import carrier, geocoder

from shield.truth import source_record


def scan(number):
    result = {
        "module": "phone_scan",
        "number": number,
        "valid": False,
        "country": "",
        "operator": "",
        "international": "",
        "risk": "unknown",
        "score": None,
        "score_basis": [],
        "confidence": None,
        "findings": [],
        "scan_status": "partial",
    }
    try:
        parsed = phonenumbers.parse(number, "PL")
        result["valid"] = phonenumbers.is_valid_number(parsed)
        result["international"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        result["country"] = geocoder.description_for_number(parsed, "pl")
        result["operator"] = carrier.name_for_number(parsed, "pl")
        if result["valid"]:
            result["findings"].append("Format numeru potwierdzony przez lokalną bibliotekę metadanych.")
        else:
            result["findings"].append("Niepotwierdzony poprawny numer telefonu.")
    except phonenumbers.NumberParseException:
        result["findings"].append("Niepoprawny format numeru telefonu.")

    result["sources"] = [source_record(
        "local_phone_metadata", "completed", confidence=0.9,
        evidence={"method": "local metadata validation", "ownership": "unconfirmed"},
    )]
    return result
