from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import threading

import pytest

from osint_lab.account_audit import (
    AccountAuditAuthorizationError,
    AccountAuditBudget,
    AccountAuditConfidence,
    AccountAuditResult,
    AccountAuditService,
    AccountAuditStatus,
    AccountCleanupCatalog,
    AccountReviewStatus,
    CleanupPriority,
    DependencyStatus,
    DetectionMethod,
    HoleheAccountAuditAdapter,
    ProviderDiagnostic,
    normalize_holehe_result,
)
from osint_lab.graph import GraphStore
from osint_lab.orchestrator.audit import AuditEventType, AuditLog


NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
EMAIL = "self.audit@example.test"


def raw(**overrides):
    value = {
        "name": "github",
        "domain": "github.com",
        "exists": True,
        "rateLimit": False,
        "error": False,
        "detection_method": "register",
        "emailrecovery": None,
        "phoneNumber": None,
    }
    value.update(overrides)
    return value


@pytest.mark.parametrize(
    ("payload", "expected"),
    (
        (raw(exists=True), AccountAuditStatus.FOUND),
        (raw(exists=False), AccountAuditStatus.NOT_FOUND),
        (raw(exists=None), AccountAuditStatus.UNKNOWN),
        (raw(exists=None, rateLimit=True), AccountAuditStatus.RATE_LIMITED),
        (raw(exists=False, error=True), AccountAuditStatus.ERROR),
        (raw(exists=None, error=True, error_code="CHALLENGE"), AccountAuditStatus.BLOCKED),
    ),
)
def test_holehe_normalization_is_truthful(payload, expected):
    result = normalize_holehe_result(payload, checked_at=NOW)
    assert result.status is expected
    assert result.status is not AccountAuditStatus.NOT_FOUND or payload["exists"] is False and not payload["error"]
    assert result.provider_version == "1.61"


def test_holehe_recovery_values_remain_masked_and_method_is_preserved():
    result = normalize_holehe_result(
        raw(emailrecovery="se***@example.test", phoneNumber="***1234", detection_method="forgot-password"),
        checked_at=NOW,
    )
    assert result.recovery_email_masked == "se***@example.test"
    assert result.recovery_phone_masked == "***1234"
    assert result.detection_method is DetectionMethod.FORGOT_PASSWORD
    assert "właściciela" in result.notes


class FakeProvider:
    provider_id = "holehe_v1"

    def __init__(self, *, installed=True):
        self.calls = []
        self.installed = installed

    def diagnose(self):
        return ProviderDiagnostic(
            status=DependencyStatus.INSTALLED if self.installed else DependencyStatus.NOT_INSTALLED,
            provider_id=self.provider_id,
            provider_version="1.61" if self.installed else None,
            python_interpreter="C:/fixture/python.exe",
            python_version="3.12.10" if self.installed else None,
            cli_available=self.installed,
            library_available=self.installed,
            provider_modules_detected=121 if self.installed else 0,
            reason="fixture",
        )

    def audit(self, email, *, budget, progress_callback=None, cancel_event=None):
        self.calls.append(email)
        payloads = (
            raw(),
            raw(name="spotify", domain="spotify.com", exists=False),
            raw(name="ambiguous", domain="ambiguous.test", exists=None),
            raw(name="limited", domain="limited.test", exists=None, rateLimit=True,
                emailrecovery="se***@example.test", phoneNumber="***1234"),
        )
        values = tuple(normalize_holehe_result(item, checked_at=NOW) for item in payloads)
        delivered = []
        for item in values:
            if cancel_event is not None and cancel_event.is_set():
                break
            delivered.append(item)
            if progress_callback:
                progress_callback(len(delivered), len(values), item)
        return tuple(delivered)


def build_service(tmp_path, *, provider=None):
    repo = tmp_path / "repo"
    repo.mkdir()
    cases = tmp_path / "private-cases"
    audit = AuditLog(repo_root=repo, root=tmp_path / "private-audit")
    selected = provider or FakeProvider()
    service = AccountAuditService(
        repo_root=repo,
        case_root=cases,
        audit_log=audit,
        provider=selected,
        clock=lambda: NOW,
    )
    return service, selected, cases, audit, repo


def test_self_audit_gate_blocks_before_storage_or_provider(tmp_path):
    service, provider, cases, audit, _ = build_service(tmp_path)
    with pytest.raises(AccountAuditAuthorizationError, match="AUTHORIZATION_REQUIRED"):
        service.run(email=EMAIL, authorization_confirmed=False, privacy_disclosure_accepted=True)
    with pytest.raises(AccountAuditAuthorizationError, match="PRIVACY_DISCLOSURE_REQUIRED"):
        service.run(email=EMAIL, authorization_confirmed=True, privacy_disclosure_accepted=False)
    assert provider.calls == []
    assert not cases.exists()
    assert not audit.root.exists()


def test_account_audit_private_storage_audit_privacy_exports_and_graph(tmp_path):
    service, provider, cases, audit, repo = build_service(tmp_path)
    progress = []
    run = service.run(
        email=EMAIL,
        authorization_confirmed=True,
        privacy_disclosure_accepted=True,
        progress_callback=lambda done, total, item: progress.append((done, total, item.service_id)),
    )
    assert provider.calls == [EMAIL]
    assert run.status == "COMPLETE"
    assert run.summary() == {
        "FOUND": 1, "NOT_FOUND": 1, "UNKNOWN": 1, "RATE_LIMITED": 1,
        "BLOCKED": 0, "ERROR": 0, "SERVICES_CHECKED": 4,
        "HIGH_CONFIDENCE_FOUND": 1, "NEEDS_MANUAL_REVIEW": 2,
    }
    assert progress[-1] == (4, 4, "limited")

    private_input = cases / run.case_id / "account_audit" / "private_input.json"
    assert json.loads(private_input.read_text(encoding="utf-8"))["email"] == EMAIL
    audit_bytes = (audit.root / run.case_id / "audit.jsonl").read_bytes()
    assert EMAIL.encode() not in audit_bytes
    assert b"se***@example.test" not in audit_bytes
    assert b"***1234" not in audit_bytes
    entries = audit.read(run.case_id)
    assert entries[0]["event_type"] == AuditEventType.SELF_AUDIT_AUTHORIZATION_CONFIRMED.value
    assert entries[0]["metadata"]["email_sha256"] == run.email_hash

    report_json = json.loads(Path(run.report_paths["json"]).read_text(encoding="utf-8"))
    assert report_json["mode"] == "ACCOUNT_AUDIT"
    assert report_json["results"][0]["status"] == "FOUND"
    assert report_json["results"][3]["recovery_phone_masked"] == "***1234"
    csv_text = Path(run.report_paths["csv"]).read_text(encoding="utf-8-sig")
    assert "Service,Domain,Detection status" in csv_text
    html = Path(run.report_paths["html"]).read_text(encoding="utf-8")
    assert "AUDYT KONT - PODSUMOWANIE" in html
    assert "PRAWDOPODOBNIE MASZ KONTO" in html
    assert "NIE ZNALEZIONO (1)" in html
    assert "nie potwierdzają właściciela" in html

    snapshot = GraphStore(repo_root=repo, case_root=cases, case_id=run.case_id).snapshot()
    account_edges = [item for item in snapshot["edges"]
                     if item["relation_type"] == "POSSIBLE_ACCOUNT_AT"]
    assert len(account_edges) == 1
    assert account_edges[0]["status"] == "POSSIBLE"
    assert not any(item["status"] == "CONFIRMED" for item in snapshot["edges"])
    assert not any(item["entity_type"] in {"NAME", "SOCIAL_PROFILE"} for item in snapshot["nodes"])


def test_missing_dependency_is_nonfatal_and_still_exports_private_report(tmp_path):
    service, provider, _, _, _ = build_service(tmp_path, provider=FakeProvider(installed=False))
    run = service.run(email=EMAIL, authorization_confirmed=True, privacy_disclosure_accepted=True)
    assert run.status == "DEPENDENCY_MISSING"
    assert run.results == ()
    assert provider.calls == []
    assert Path(run.report_paths["html"]).is_file()


def test_cancel_preserves_already_returned_results(tmp_path):
    service, _, _, _, _ = build_service(tmp_path)
    cancel = threading.Event()

    def progress(done, total, item):
        if done == 2:
            cancel.set()

    run = service.run(
        email=EMAIL,
        authorization_confirmed=True,
        privacy_disclosure_accepted=True,
        progress_callback=progress,
        cancel_event=cancel,
    )
    assert run.cancelled is True
    assert len(run.results) == 2
    assert Path(run.report_paths["json"]).is_file()


def test_review_decision_and_user_note_are_local_with_append_only_history(tmp_path):
    service, _, _, audit, _ = build_service(tmp_path)
    run = service.run(email=EMAIL, authorization_confirmed=True, privacy_disclosure_accepted=True)
    secret_note = "konto z 2018 - usunąć ręcznie"
    service.record_review(
        case_id=run.case_id,
        service_id="github",
        status=AccountReviewStatus.DELETE_CANDIDATE,
        note=secret_note,
    )
    service.record_review(
        case_id=run.case_id,
        service_id="github",
        status=AccountReviewStatus.DELETED,
        note="usunięto ręcznie",
    )
    history = service.store.review_history(run.case_id)
    assert [item["review_status"] for item in history] == ["DELETE_CANDIDATE", "DELETED"]
    updated = json.loads(Path(run.report_paths["json"]).read_text(encoding="utf-8"))
    github = next(item for item in updated["results"] if item["service_id"] == "github")
    assert github["review_status"] == "DELETED"
    assert github["user_note"] == "usunięto ręcznie"
    assert "usunięto ręcznie" in Path(run.report_paths["html"]).read_text(encoding="utf-8")
    audit_text = (audit.root / run.case_id / "audit.jsonl").read_text(encoding="utf-8")
    assert secret_note not in audit_text
    assert "usunięto ręcznie" not in audit_text


def test_cleanup_catalog_uses_reviewed_https_or_null_only():
    catalog = AccountCleanupCatalog()
    github = catalog.get("github")
    assert github.deletion_url.startswith("https://docs.github.com/")
    assert github.privacy_url.startswith("https://docs.github.com/")
    unknown = catalog.get("unknown-fixture")
    assert unknown.homepage is None
    assert unknown.account_settings_url is None
    assert unknown.deletion_url is None
    assert unknown.privacy_url is None


def test_account_result_model_is_json_safe_and_cleanup_is_not_threat_score():
    result = AccountAuditResult(
        service_id="fixture", service_name="Fixture", domain="fixture.test", category="cloud",
        status=AccountAuditStatus.FOUND, confidence=AccountAuditConfidence.MEDIUM,
        detection_method=DetectionMethod.LOGIN, source_adapter="mock", checked_at=NOW,
        rate_limited=False, error_code=None, recovery_email_masked=None,
        recovery_phone_masked=None, notes="possible only", cleanup_priority=CleanupPriority.HIGH,
    )
    payload = json.loads(json.dumps(result.to_dict()))
    assert payload["cleanup_priority"] == "HIGH"
    assert payload["status"] == "FOUND"
    assert "threat" not in json.dumps(payload).casefold()


def test_holehe_diagnostic_missing_is_explicit(tmp_path):
    adapter = HoleheAccountAuditAdapter(interpreter=tmp_path / "missing-python.exe", repo_root=tmp_path)
    diagnostic = adapter.diagnose()
    assert diagnostic.status is DependencyStatus.NOT_INSTALLED
    assert diagnostic.provider_modules_detected == 0
    assert "DEPENDENCY_MISSING" in diagnostic.reason


def test_holehe_diagnostic_rejects_unreviewed_python_version(tmp_path):
    interpreter = tmp_path / "python.exe"
    interpreter.write_bytes(b"fixture")
    payload = json.dumps({
        "library_available": True,
        "cli_available": True,
        "version": "1.61",
        "python_version": "3.14.6",
        "provider_modules_detected": 121,
    })

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=payload, stderr="")

    adapter = HoleheAccountAuditAdapter(
        interpreter=interpreter,
        repo_root=tmp_path,
        command_runner=runner,
    )
    diagnostic = adapter.diagnose()
    assert diagnostic.status is DependencyStatus.INCOMPATIBLE
    assert diagnostic.python_version == "3.14.6"
    assert "Python 3.10-3.12" in diagnostic.reason


def test_windows_helper_manifest_and_gui_contract_are_separate_from_public_osint():
    root = Path(__file__).resolve().parents[1]
    helper = (root / "INSTALL_ACCOUNT_AUDIT.cmd").read_text(encoding="utf-8")
    manifest = json.loads((root / "account_audit_dependency_manifest.json").read_text(encoding="utf-8"))
    gui = (root / "osint_lab" / "desktop_gui.py").read_text(encoding="utf-8")
    runner = (root / "osint_lab" / "case_runner.py").read_text(encoding="utf-8")
    assert "%LOCALAPPDATA%\\LumirOSINTLab\\account_audit_env" in helper
    assert "holehe==1.61" in helper
    assert manifest["version"] == "1.61"
    assert manifest["license"] == "GPL-3.0-only"
    assert "AUDYT KONT" in gui
    assert "SELF-AUDIT" in gui
    assert "account_audit" not in runner


def test_budget_rejects_aggressive_concurrency():
    with pytest.raises(ValueError, match="low"):
        AccountAuditBudget(max_concurrency=9)
