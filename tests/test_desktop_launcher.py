from datetime import datetime, timezone
from pathlib import Path

import pytest

from osint_lab.application import ApplicationServices
from osint_lab.agents import PhoneMetadataCollector, PhonePublicWebCollector, build_default_registry
from osint_lab.agents.phone_public_http import PhonePublicHttpResponse
from osint_lab.case_runner import (
    CaseRunResult,
    CaseRunStatus,
    CaseRunner,
)
from osint_lab.case_storage import CaseStore
from osint_lab.desktop import (
    DesktopAnalysisError,
    DesktopBackend,
    DesktopInput,
    DesktopValidationError,
)
from osint_lab.evidence import EvidenceVault
from osint_lab.orchestrator.audit import AuditLog, AuditVerification
from osint_lab.orchestrator.authorization_store import AuthorizationStore
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.reporting import ReportEngine, ReportReference
from osint_lab.verification.contradictions import ContradictionResult, ContradictionSeverity


NOW = datetime(2026, 9, 19, 20, 15, tzinfo=timezone.utc)


class FakePhonePublicHttpClient:
    def __init__(self):
        self.calls = []

    def get(self, url, *, timeout, headers):
        self.calls.append(url)
        return PhonePublicHttpResponse(
            status_code=200,
            final_url=url,
            body="No results.",
            redirected=False,
        )


class RecordingRunner:
    def __init__(self, root: Path, *, status: CaseRunStatus = CaseRunStatus.SUCCESS):
        self.root = root
        self.status = status
        self.calls = []

    def run(self, manifest, *, progress_callback=None):
        self.calls.append(manifest)
        if progress_callback:
            for event in (
                "collector:phone_metadata", "phone_public:search", "phone_public:verify", "intelligence", "report",
            ):
                progress_callback(event)
        reports = self.root / manifest.case_id / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        html = reports / "report.html"
        json_path = reports / "report.json"
        html.write_text("<html>fixture</html>", encoding="utf-8")
        json_path.write_text("{}", encoding="utf-8")
        reference = ReportReference(
            json_path=str(json_path),
            json_sha256="1" * 64,
            json_evidence_id="evidence-json",
            html_path=str(html),
            html_sha256="2" * 64,
            html_evidence_id="evidence-html",
        )
        return CaseRunResult(
            case_id=manifest.case_id,
            run_id="desktop-fixture-run",
            started_at=NOW,
            finished_at=NOW,
            overall_status=self.status,
            executions=(),
            receipts=(),
            findings_summary={
                "CONFIRMED": 0,
                "PROBABLE": 0,
                "POSSIBLE": 2,
                "UNKNOWN": 1,
                "NOT_FOUND": 3,
                "FALSE_POSITIVE": 0,
            },
            contradictions=ContradictionResult(
                severity=ContradictionSeverity.NONE,
                reasons=(),
                evidence_refs=(),
            ),
            warnings=("fixture warning",) if self.status is CaseRunStatus.PARTIAL else (),
            report_reference=reference,
            audit_verification=AuditVerification(
                valid=True,
                entry_count=1,
                head_hash="3" * 64,
                reason="valid",
            ),
        )


class FailingRunner:
    def run(self, manifest, *, progress_callback=None):
        raise RuntimeError("sensitive fixture must not be logged")


def build_fake_backend(tmp_path, *, status=CaseRunStatus.SUCCESS, runner=None, opener=None):
    repo = tmp_path / "repo"
    repo.mkdir()
    store = CaseStore(repo_root=repo, root=tmp_path / "private-cases")
    selected_runner = runner or RecordingRunner(store.root, status=status)
    app = ApplicationServices(case_store=store, runner=selected_runner, audit_log=object())
    backend = DesktopBackend(application=app, clock=lambda: NOW, path_opener=opener)
    return backend, store, selected_runner


@pytest.mark.parametrize(
    ("field", "value", "entity_type"),
    (
        ("phone", "+48123456789", "PHONE"),
        ("email", "Fixture.User@example.test", "EMAIL"),
        ("username", "fixture_user", "USERNAME"),
        ("domain", "domain.test", "DOMAIN"),
    ),
)
def test_desktop_accepts_each_single_input(tmp_path, field, value, entity_type):
    backend, store, runner = build_fake_backend(tmp_path)
    summary = backend.analyze(DesktopInput(**{field: value}))
    manifest = runner.calls[0]
    assert [(seed.entity_type, seed.value) for seed in manifest.seed_entities] == [(entity_type, value)]
    assert store.load(summary.case_id) == manifest
    assert summary.case_id == "lumir_20260919_201500"


def test_desktop_accepts_mixed_inputs_and_ignores_blanks(tmp_path):
    backend, _, runner = build_fake_backend(tmp_path)
    backend.analyze(DesktopInput(
        phone=" +48123456789 ",
        email="Fixture.User@example.test",
        username=" ",
        domain="domain.test",
    ))
    assert [(item.entity_type, item.value) for item in runner.calls[0].seed_entities] == [
        ("PHONE", "+48123456789"),
        ("EMAIL", "Fixture.User@example.test"),
        ("DOMAIN", "domain.test"),
    ]


def test_desktop_rejects_empty_form_without_creating_case(tmp_path):
    backend, store, runner = build_fake_backend(tmp_path)
    with pytest.raises(DesktopValidationError, match="Nie podano"):
        backend.analyze(DesktopInput())
    assert runner.calls == []
    assert not store.root.exists()


@pytest.mark.parametrize("enabled", (False, True))
def test_desktop_passive_web_toggle_controls_manifest(tmp_path, enabled):
    backend, _, runner = build_fake_backend(tmp_path)
    backend.analyze(DesktopInput(email="Fixture.User@example.test", allow_passive_web=enabled))
    allowed = runner.calls[0].allowed_source_classes
    assert (SourceClass.PASSIVE_WEB in allowed) is enabled
    assert SourceClass.LOCAL in allowed


def test_desktop_reports_progress_summary_and_run_invocation(tmp_path):
    messages = []
    backend, _, runner = build_fake_backend(tmp_path, status=CaseRunStatus.PARTIAL)
    summary = backend.analyze(
        DesktopInput(phone="+48123456789"),
        status_callback=messages.append,
    )
    assert len(runner.calls) == 1
    assert messages == [
        "Przygotowanie...",
        "Analiza telefonu...",
        "Szukanie publicznych wyników...",
        "Weryfikacja stron źródłowych...",
        "Analiza dowodów...",
        "Generowanie raportu...",
        "Gotowe.",
    ]
    assert summary.overall_status == "PARTIAL"
    assert (summary.possible_count, summary.unknown_count, summary.not_found_count) == (2, 1, 3)
    assert summary.report_html_path is not None
    assert (summary.public_matches_verified, summary.rejected_false_positives, summary.target_pages_checked) == (0, 0, 0)


def test_desktop_opens_only_valid_report_and_case_paths(tmp_path):
    opened = []
    backend, _, _ = build_fake_backend(tmp_path, opener=opened.append)
    summary = backend.analyze(DesktopInput(domain="domain.test"))
    report = backend.open_report(summary)
    folder = backend.open_case_folder(summary)
    assert opened == [str(report), str(folder)]

    outside = tmp_path / "outside.html"
    outside.write_text("fixture", encoding="utf-8")
    with pytest.raises(DesktopValidationError, match="raportu"):
        backend.validate_report_path(summary.case_id, str(outside))
    with pytest.raises(DesktopValidationError, match="folderu"):
        backend.validate_case_folder(summary.case_id, str(tmp_path))


def test_desktop_backend_error_is_safe_and_omits_identifiers(tmp_path):
    backend, store, _ = build_fake_backend(tmp_path, runner=FailingRunner())
    raw_email = "Private.Person@example.test"
    with pytest.raises(DesktopAnalysisError, match="Nie udało"):
        backend.analyze(DesktopInput(email=raw_email))
    log = (store.root.parent / "logs" / "desktop.jsonl").read_text(encoding="utf-8")
    assert raw_email not in log
    assert "RuntimeError" in log
    assert "test_desktop_launcher.py" in log
    assert "raw identifiers intentionally omitted" in log


def test_real_desktop_phone_path_uses_orchestrator_and_keeps_audit_private(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    case_root = tmp_path / "private-cases"
    store = CaseStore(repo_root=repo, root=case_root)
    vault = EvidenceVault(repo_root=repo, root=case_root)
    audit = AuditLog(repo_root=repo, root=tmp_path / "private-audit")
    registry = build_default_registry()
    orchestrator = Orchestrator(
        audit_log=audit,
        authorization_store=AuthorizationStore(repo_root=repo, root=tmp_path / "private-auth"),
        collector_registry=registry,
        evidence_vault=vault,
        clock=lambda: NOW,
    )
    phone_http = FakePhonePublicHttpClient()
    runner = CaseRunner(
        orchestrator=orchestrator,
        registry=registry,
        collectors={
            "phone_metadata": PhoneMetadataCollector(),
            "phone_public_web": PhonePublicWebCollector(http_client=phone_http, clock=lambda: NOW),
        },
        case_store=store,
        report_engine=ReportEngine(evidence_vault=vault, case_root=case_root, clock=lambda: NOW),
        audit_log=audit,
        clock=lambda: NOW,
        id_factory=lambda: "desktop-real-fixture",
    )
    backend = DesktopBackend(
        application=ApplicationServices(case_store=store, runner=runner, audit_log=audit),
        clock=lambda: NOW,
        path_opener=lambda path: None,
    )
    raw_phone = "+48123456789"
    summary = backend.analyze(DesktopInput(phone=raw_phone, allow_passive_web=True))
    assert summary.overall_status in {"SUCCESS", "PARTIAL"}
    assert Path(summary.report_html_path).is_file()
    audit_bytes = (audit.root / summary.case_id / "audit.jsonl").read_bytes()
    assert raw_phone.encode() not in audit_bytes
    assert (case_root / summary.case_id / "raw").is_dir()
    assert phone_http.calls
    assert summary.target_pages_checked == 0
    html = Path(summary.report_html_path).read_text(encoding="utf-8")
    assert "PHONE PUBLIC INTELLIGENCE" in html


def test_launcher_and_gui_keep_windows_mvp_contract():
    root = Path(__file__).resolve().parents[1]
    launcher = (root / "LUMIR_OSINT_LAB.cmd").read_text(encoding="utf-8")
    shortcut = (root / "CREATE_DESKTOP_SHORTCUT.ps1").read_text(encoding="utf-8")
    gui = (root / "osint_lab" / "desktop_gui.py").read_text(encoding="utf-8")
    assert "%~dp0" in launcher
    assert "python -m osint_lab.desktop_gui" in launcher
    assert "LUMIR OSINT LAB.lnk" in shortcut
    assert "LUMIR_OSINT_LAB.cmd" in shortcut
    assert "tk.BooleanVar(value=False)" in gui
    assert "threading.Thread" in gui
