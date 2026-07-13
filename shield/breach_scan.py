"""Approved HIBP v3 integration with truthful unavailable/error states."""

import os
from urllib.parse import quote

import requests

from shield.truth import source_record


def scan(email: str):
    api_key = os.getenv("LUMIR_HIBP_API_KEY")
    base = {"module": "breach_scan", "email": email, "breaches": None, "source": "Have I Been Pwned API v3", "confidence": None}
    if not api_key:
        return {**base, "breaches_found": None, "risk": "unknown", "scan_status": "unavailable", "score": None, "error_reason": "HIBP API key is not configured", "findings": ["Nie skonfigurowano klucza API HIBP."], "sources": [source_record("hibp_v3", "unavailable", error_reason="HIBP API key is not configured")]}
    try:
        response = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}", headers={"hibp-api-key": api_key, "user-agent": "Lumir-SHIELD"}, timeout=15)
        if response.status_code == 404:
            return {**base, "breaches_found": 0, "breaches": [], "risk": "low", "scan_status": "completed", "findings": [], "sources": [source_record("hibp_v3", "completed", confidence=0.95, evidence={"http_status": 404})]}
        response.raise_for_status()
        names = [item.get("Name", "Nieznane zrodlo") for item in response.json()]
        return {**base, "breaches_found": len(names), "breaches": names, "risk": "high" if names else "low", "scan_status": "completed", "findings": [f"Znaleziono {len(names)} wpisow w publicznym zrodle wyciekow."] if names else [], "sources": [source_record("hibp_v3", "completed", confidence=0.95, evidence={"breach_count": len(names)})]}
    except requests.Timeout:
        return {**base, "breaches_found": None, "risk": "unknown", "scan_status": "timeout", "score": None, "error_reason": "request timeout", "findings": ["Nie udalo sie zakonczyc sprawdzenia HIBP."], "sources": [source_record("hibp_v3", "timeout", error_reason="request timeout")]}
    except requests.RequestException as error:
        return {**base, "breaches_found": None, "risk": "unknown", "scan_status": "error", "score": None, "error_reason": type(error).__name__, "findings": ["Zrodlo HIBP nie odpowiedzialo poprawnie."], "sources": [source_record("hibp_v3", "error", error_reason=type(error).__name__)]}
