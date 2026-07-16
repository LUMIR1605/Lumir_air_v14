"""Consent-gated account discovery evidence without security scoring."""

from shield.holehe_scan import scan as holehe_scan
from shield.truth import source_record


SOURCE_ID = "holehe_local"
_NO_SCORE_REASON = "Wyniki wskazują jedynie prawdopodobne usługi i nie mają score bezpieczeństwa."


def _services(results, *, attempted, source_status):
    probable = [
        {
            "service_name": name,
            "status": "probable",
            "confidence": "low",
            "evidence": {"match_type": "local_cli_output"},
            "source_id": SOURCE_ID,
        }
        for name in results
    ]
    return {
        "planned_count": 1,
        "attempted_count": attempted,
        "checked_count": 1 if source_status == "completed" else 0,
        "confirmed_count": 0,
        "probable_count": len(probable),
        "not_found_count": 1 if source_status == "completed" and not probable else 0,
        "not_checked_count": 0 if source_status == "completed" else 1,
        "results": probable,
    }


def _base(email, status, *, error_reason=None, services=None, source_status=None, service_signals=0, exit_code=None):
    services = services or []
    source_status = source_status or status
    attempted = 0 if source_status == "blocked" else 1
    source = source_record(
        SOURCE_ID,
        source_status,
        confidence=0.35 if source_status == "completed" else None,
        error_reason=error_reason if source_status != "completed" else None,
        evidence={"service_signals": service_signals, "services_count": len(services), "process_exit_code": exit_code},
    )
    return {
        "module": "account_exposure_scan",
        "email": email,
        "scan_status": status,
        "risk": "unknown",
        "score": None,
        "score_basis": [],
        "confidence": None,
        "findings": [],
        "error_reason": error_reason,
        "services": _services(services, attempted=attempted, source_status=source_status),
        "sources": [source],
    }


def scan(email, *, consent_declared=False):
    """Discover probable account indicators only after owner consent."""
    if not consent_declared:
        return _base(email, "blocked", error_reason="CONSENT_REQUIRED", source_status="blocked")

    result = holehe_scan(email)
    status = result.get("scan_status", "error")
    if status != "completed":
        return _base(
            email,
            status,
            error_reason=result.get("error_reason", "HOLEHE_PROCESS_ERROR"),
            source_status=status,
            service_signals=result.get("checked", 0),
            exit_code=result.get("process_exit_code"),
        )

    services = result.get("services", [])
    module = _base(
        email,
        "partial",
        error_reason=_NO_SCORE_REASON,
        services=services,
        source_status="completed",
        service_signals=result.get("checked", 0),
        exit_code=result.get("process_exit_code"),
    )
    if services:
        module["findings"] = ["Znaleziono prawdopodobne wskaźniki rejestracji w usługach."]
    return module
