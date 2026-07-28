from unittest.mock import patch

import pytest

from shield.input_validation import InputValidationError, normalize
from shield.multi_scan import run
from shield.report_paths import ensure_reports_directory, report_paths


def test_normalizes_the_three_supported_input_types():
    assert normalize(" Test@EXAMPLE.pl ", "email").value == "Test@example.pl"
    assert normalize("0048 123 456 789", "phone").value == "+48123456789"
    assert normalize("@lumir_1605", "username").value == "lumir_1605"


@pytest.mark.parametrize("value,kind", [("wrong@", "email"), ("123", "phone"), ("bad nick!", "username")])
def test_rejects_invalid_input(value, kind):
    with pytest.raises(InputValidationError):
        normalize(value, kind)


def test_self_scan_requires_consent_before_any_source_runs():
    report = run("phone", "+48123456789", consent_declared=False)
    assert report["consent"]["declared"] is False
    assert report["modules"][0]["scan_status"] == "blocked"
    assert report["modules"][0]["error_reason"] == "CONSENT_REQUIRED"


def test_phone_is_local_partial_evidence_without_identity_claim():
    report = run("phone", "+48123456789", consent_declared=True)
    module = report["modules"][0]
    assert module["scan_status"] == "partial"
    assert module["score"] is None
    assert module["sources"][0]["source_id"] == "local_phone_metadata"


def test_public_github_username_is_marked_unconfirmed():
    response = type("Response", (), {"status_code": 200, "json": lambda self: {"login": "lumir1605", "html_url": "https://github.com/lumir1605", "type": "User", "public_repos": 1, "created_at": "2020-01-01T00:00:00Z"}, "raise_for_status": lambda self: None})()
    with patch("shield.username_scan.requests.get", return_value=response):
        report = run("username", "lumir1605", consent_declared=True)
    module = report["modules"][0]
    assert module["scan_status"] == "partial"
    assert module["profile"]["ownership"] == "unconfirmed"
    assert module["sources"][0]["source_id"] == "github_public_api"


def test_report_paths_are_local_to_user_profile_not_documents_or_onedrive(monkeypatch, tmp_path):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    directory = ensure_reports_directory()
    paths = report_paths("email", "test@example.com")
    assert directory == tmp_path / "Lumir SHIELD" / "Reports"
    assert all(path.parent == directory for path in paths.values())
