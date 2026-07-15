import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from shield.account_exposure_scan import scan as account_exposure_scan
from shield.holehe_scan import scan as holehe_scan
from shield.truth import assessment, base_report, validate_report


def _completed(stdout):
    return SimpleNamespace(returncode=0, stdout=stdout)


def test_holehe_normalizes_found_services():
    with patch("shield.holehe_scan.subprocess.run", return_value=_completed("[+] Spotify\n[+] Email used on a provider\n[+] Spotify\n[+] Office365\n")) as run:
        result = holehe_scan("test@example.com")

    assert run.call_args.kwargs["timeout"] == 120
    assert result["scan_status"] == "completed"
    assert result["services"] == ["Spotify", "Office365"]
    assert "stdout" not in result


def test_holehe_returns_completed_empty_result():
    with patch("shield.holehe_scan.subprocess.run", return_value=_completed("")):
        result = holehe_scan("test@example.com")

    assert result["scan_status"] == "completed"
    assert result["services"] == []
    assert result["checked"] == 0


def test_holehe_handles_missing_binary():
    with patch("shield.holehe_scan.subprocess.run", side_effect=FileNotFoundError):
        result = holehe_scan("test@example.com")

    assert result["scan_status"] == "unavailable"
    assert result["error_reason"] == "HOLEHE_NOT_INSTALLED"


def test_holehe_handles_timeout():
    with patch("shield.holehe_scan.subprocess.run", side_effect=subprocess.TimeoutExpired(["holehe"], 120)):
        result = holehe_scan("test@example.com")

    assert result["scan_status"] == "timeout"
    assert result["error_reason"] == "HOLEHE_TIMEOUT"


def test_holehe_handles_process_error():
    with patch("shield.holehe_scan.subprocess.run", return_value=SimpleNamespace(returncode=2, stdout="diagnostic output")):
        result = holehe_scan("test@example.com")

    assert result["scan_status"] == "error"
    assert result["error_reason"] == "HOLEHE_PROCESS_FAILED"
    assert "diagnostic output" not in str(result)


def test_account_exposure_requires_consent():
    with patch("shield.account_exposure_scan.holehe_scan") as holehe:
        result = account_exposure_scan("test@example.com", consent_declared=False)

    holehe.assert_not_called()
    assert result["scan_status"] == "blocked"
    assert result["error_reason"] == "CONSENT_REQUIRED"
    assert result["score"] is None


def test_account_exposure_maps_services_as_probable_only():
    holehe_result = {"scan_status": "completed", "checked": 2, "services": ["Spotify", "Office365"], "process_exit_code": 0}
    with patch("shield.account_exposure_scan.holehe_scan", return_value=holehe_result):
        result = account_exposure_scan("test@example.com", consent_declared=True)

    assert result["scan_status"] == "partial"
    assert result["score"] is None
    assert result["services"]["confirmed_count"] == 0
    assert result["services"]["probable_count"] == 2
    assert all(item["status"] == "probable" for item in result["services"]["results"])


def test_account_exposure_partial_module_is_valid_v3():
    holehe_result = {"scan_status": "completed", "checked": 0, "services": [], "process_exit_code": 0}
    with patch("shield.account_exposure_scan.holehe_scan", return_value=holehe_result):
        module = account_exposure_scan("test@example.com", consent_declared=True)

    report = base_report("email", "test@example.com", consent_declared=True)
    report["modules"] = [module]
    report.update(assessment(report["modules"], "email"))
    assert validate_report(report)
