"""Lookup of one public GitHub profile through the official API only."""

from __future__ import annotations

from time import monotonic
from urllib.parse import quote
from uuid import uuid4

import requests

from shield.truth import now_iso, source_record


SOURCE_ID = "github_public_api"
API_URL = "https://api.github.com/users/{}"


def _result(username, status, finding, source_status, *, confidence=None, evidence=None, error_reason=None, log=None, profile=None):
    source = source_record(
        SOURCE_ID, source_status, confidence=confidence,
        evidence=evidence or {"ownership": "unconfirmed"}, error_reason=error_reason,
        request_log_ref=log["request_id"] if log else None,
    )
    return {
        "module": "username_scan", "username": username, "scan_status": status,
        "risk": "unknown", "score": None, "score_basis": [], "confidence": None,
        "findings": [finding], "error_reason": error_reason, "profile": profile,
        "sources": [source], "request_log": [log] if log else [],
    }


def scan(username):
    """Retrieve public profile metadata; it never proves that the user owns it."""
    request_id = str(uuid4())
    started_at, started = now_iso(), monotonic()
    log = {
        "request_id": request_id, "source_id": SOURCE_ID, "method": "GET",
        "endpoint_class": "public_user_profile", "started_at": started_at,
        "target_redacted": username,
    }
    try:
        response = requests.get(
            API_URL.format(quote(username, safe="")),
            headers={"Accept": "application/vnd.github+json", "User-Agent": "Lumir-SHIELD"},
            timeout=10,
        )
        log.update({"finished_at": now_iso(), "duration_ms": round((monotonic() - started) * 1000), "http_status": response.status_code})
        if response.status_code == 404:
            log["status"] = "completed"
            return _result(username, "partial", "Nie potwierdzono publicznego profilu GitHub o tym nicku. Nie oznacza to braku kont na innych platformach.", "completed", confidence=0.98, evidence={"http_status": 404, "public_profile": "not_confirmed", "ownership": "unconfirmed"}, log=log)
        if response.status_code in {403, 429}:
            log["status"] = "error"
            return _result(username, "unavailable", "Publiczne źródło GitHub jest chwilowo limitowane.", "unavailable", error_reason="GITHUB_RATE_LIMITED", log=log)
        response.raise_for_status()
        data = response.json()
        log["status"] = "completed"
        profile = {
            "platform": "GitHub", "login": data.get("login"), "url": data.get("html_url"),
            "account_type": data.get("type"), "public_repos": data.get("public_repos"),
            "created_at": data.get("created_at"), "ownership": "unconfirmed",
        }
        return _result(username, "partial", "Wykryto publiczny profil GitHub o tym nicku. Powiązanie tego profilu z użytkownikiem pozostaje niepotwierdzone.", "completed", confidence=0.98, evidence={"http_status": 200, "public_profile": "confirmed", "ownership": "unconfirmed"}, log=log, profile=profile)
    except requests.Timeout:
        log.update({"finished_at": now_iso(), "duration_ms": round((monotonic() - started) * 1000), "http_status": None, "status": "timeout"})
        return _result(username, "timeout", "Przekroczono czas sprawdzania publicznego profilu GitHub.", "timeout", error_reason="GITHUB_TIMEOUT", log=log)
    except requests.RequestException as error:
        log.update({"finished_at": now_iso(), "duration_ms": round((monotonic() - started) * 1000), "http_status": None, "status": "error"})
        return _result(username, "error", "Nie udało się sprawdzić publicznego profilu GitHub.", "error", error_reason=type(error).__name__, log=log)
