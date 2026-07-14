"""Approved HIBP v3 integration with evidence scoring and redacted audit logs."""

import os
from time import monotonic
from urllib.parse import quote
from uuid import uuid4

import requests

from shield.truth import load_sources, mask_email, now_iso, source_record


def _basis(count, status):
    score = 100 if count == 0 else max(0, 70 - min(count, 7) * 10)
    return score, [{"check_id": "hibp_breach_lookup", "status": status, "weight": 100, "points_awarded": score, "evidence": {"breaches_found": count}}]


def scan(email: str):
    source = load_sources()["hibp_v3"]
    api_key = os.getenv(source["api_key_env"])
    base = {"module": "breach_scan", "email": email, "breaches": None, "source": source["source_name"], "confidence": None, "request_log": []}
    if not api_key:
        return {**base, "breaches_found": None, "risk": "unknown", "scan_status": "unavailable", "score": None, "score_basis": [], "error_reason": "HIBP API key is not configured", "findings": ["Nie skonfigurowano klucza API HIBP."], "sources": [source_record("hibp_v3", "unavailable", error_reason="HIBP API key is not configured")]}
    request_id, started, clock = str(uuid4()), now_iso(), monotonic()
    log = {"request_id": request_id, "source_id": "hibp_v3", "method": "GET", "endpoint_class": "breachedaccount", "started_at": started, "target_redacted": mask_email(email)}
    try:
        response = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}", headers={"hibp-api-key": api_key, "user-agent": "Lumir-SHIELD"}, timeout=15)
        log.update({"finished_at": now_iso(), "duration_ms": round((monotonic() - clock) * 1000), "http_status": response.status_code, "status": "completed"})
        if response.status_code == 404:
            score, basis = _basis(0, "passed")
            basis[0]["evidence"]["http_status"] = 404
            return {**base, "breaches_found": 0, "breaches": [], "risk": "low", "scan_status": "completed", "score": score, "score_basis": basis, "findings": [], "request_log": [log], "sources": [source_record("hibp_v3", "completed", confidence=.95, evidence={"http_status": 404}, request_log_ref=request_id)]}
        if response.status_code in {401, 403, 429}:
            reason = "HIBP_AUTH_ERROR" if response.status_code in {401, 403} else "HIBP_RATE_LIMITED"
            log["status"] = "error"
            return {**base, "breaches_found": None, "risk": "unknown", "scan_status": "error", "score": None, "score_basis": [], "error_reason": reason, "findings": [], "request_log": [log], "sources": [source_record("hibp_v3", "error", error_reason=reason, request_log_ref=request_id)]}
        response.raise_for_status()
        names = [item.get("Name", "Nieznane zrodlo") for item in response.json()]
        score, basis = _basis(len(names), "failed" if names else "passed")
        return {**base, "breaches_found": len(names), "breaches": names, "risk": "high" if names else "low", "scan_status": "completed", "score": score, "score_basis": basis, "findings": [f"Znaleziono {len(names)} wpisow w publicznym zrodle wyciekow."] if names else [], "request_log": [log], "sources": [source_record("hibp_v3", "completed", confidence=.95, evidence={"breach_count": len(names)}, request_log_ref=request_id)]}
    except requests.Timeout:
        log.update({"finished_at": now_iso(), "duration_ms": round((monotonic() - clock) * 1000), "http_status": None, "status": "timeout"})
        return {**base, "breaches_found": None, "risk": "unknown", "scan_status": "timeout", "score": None, "score_basis": [], "error_reason": "request timeout", "findings": [], "request_log": [log], "sources": [source_record("hibp_v3", "timeout", error_reason="request timeout", request_log_ref=request_id)]}
    except requests.RequestException as error:
        log.update({"finished_at": now_iso(), "duration_ms": round((monotonic() - clock) * 1000), "http_status": None, "status": "error"})
        return {**base, "breaches_found": None, "risk": "unknown", "scan_status": "error", "score": None, "score_basis": [], "error_reason": type(error).__name__, "findings": [], "request_log": [log], "sources": [source_record("hibp_v3", "error", error_reason=type(error).__name__, request_log_ref=request_id)]}
