from unittest.mock import patch

from shield.multi_scan import run


def _scored_module(name):
    return {
        "module": name,
        "scan_status": "completed",
        "score": 100,
        "risk": "low",
        "score_basis": [
            {
                "check_id": f"{name}_check",
                "status": "passed",
                "weight": 100,
                "points_awarded": 100,
                "evidence": {},
            }
        ],
        "findings": [],
    }


def _account_module(status, *, results=None, attempted=0, checked=0, not_found=0, not_checked=0):
    results = results or []
    return {
        "module": "account_exposure_scan",
        "scan_status": status,
        "score": None,
        "risk": "unknown",
        "score_basis": [],
        "findings": [],
        "services": {
            "planned_count": 1,
            "attempted_count": attempted,
            "checked_count": checked,
            "confirmed_count": 0,
            "probable_count": len(results),
            "not_found_count": not_found,
            "not_checked_count": not_checked,
            "results": results,
        },
    }


def _run(account_module, consent_declared):
    with (
        patch("shield.multi_scan.email_scan", return_value=_scored_module("email_scan")),
        patch("shield.multi_scan.breach_scan", return_value=_scored_module("breach_scan")),
        patch("shield.multi_scan.domain_scan", return_value=_scored_module("domain_scan")),
        patch("shield.multi_scan.account_exposure_scan", return_value=account_module) as discovery,
        patch("shield.multi_scan.attack_surface", return_value={}),
        patch("shield.multi_scan.advise", return_value=[]),
        patch("shield.multi_scan.build_action_plan", return_value={}),
    ):
        report = run("email", "test@example.com", consent_declared=consent_declared)
    return report, discovery


def test_report_blocks_account_discovery_without_consent():
    module = _account_module("blocked", not_checked=1)
    report, discovery = _run(module, consent_declared=False)

    discovery.assert_called_once_with("test@example.com", consent_declared=False)
    assert report["services"]["planned_count"] == 1
    assert report["services"]["attempted_count"] == 0
    assert report["services"]["not_checked_count"] == 1
    assert report["services"]["results"] == []


def test_report_includes_two_probable_services_without_changing_score():
    results = [
        {"service_name": "Spotify", "status": "probable", "confidence": "low", "evidence": {}, "source_id": "holehe_local"},
        {"service_name": "Office365", "status": "probable", "confidence": "low", "evidence": {}, "source_id": "holehe_local"},
    ]
    report, discovery = _run(_account_module("partial", results=results, attempted=1, checked=1), consent_declared=True)

    discovery.assert_called_once_with("test@example.com", consent_declared=True)
    assert report["risk_score"]["score"] == 100
    assert report["services"]["confirmed_count"] == 0
    assert report["services"]["checked_count"] == 1
    assert report["services"]["probable_count"] == 2
    assert all(item["status"] == "probable" for item in report["services"]["results"])
    assert report["services"]["title"] == "Sprawd\u017a, co internet nadal pami\u0119ta o Tobie"
    assert report["services"]["explanation"] == "Wykryte us\u0142ugi s\u0105 sygna\u0142em technicznym, a nie potwierdzeniem istnienia konta."


def test_report_marks_empty_holehe_result_as_completed_without_services():
    report, _ = _run(_account_module("partial", attempted=1, checked=1, not_found=1), consent_declared=True)

    assert report["services"]["attempted_count"] == 1
    assert report["services"]["probable_count"] == 0
    assert report["services"]["checked_count"] == 1
    assert report["services"]["not_found_count"] == 1
    assert report["services"]["not_checked_count"] == 0
    assert report["services"]["results"] == []


def test_report_marks_missing_holehe_binary_as_not_checked():
    report, _ = _run(_account_module("unavailable", attempted=1, not_checked=1), consent_declared=True)

    assert report["services"]["attempted_count"] == 1
    assert report["services"]["checked_count"] == 0
    assert report["services"]["not_checked_count"] == 1
    assert report["services"]["not_found_count"] == 0


def test_report_marks_holehe_timeout_as_not_checked():
    report, _ = _run(_account_module("timeout", attempted=1, not_checked=1), consent_declared=True)

    assert report["services"]["attempted_count"] == 1
    assert report["services"]["checked_count"] == 0
    assert report["services"]["not_checked_count"] == 1
    assert report["services"]["results"] == []


def test_report_marks_holehe_process_error_as_not_checked():
    report, _ = _run(_account_module("error", attempted=1, not_checked=1), consent_declared=True)

    assert report["services"]["attempted_count"] == 1
    assert report["services"]["checked_count"] == 0
    assert report["services"]["not_checked_count"] == 1
    assert report["services"]["confirmed_count"] == 0
