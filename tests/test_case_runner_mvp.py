from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import dns.resolver
import pytest

from osint_lab.__main__ import CliApplication, build_parser, main
from osint_lab.agents import (
    CollectorRegistry,
    DomainDNSCollector,
    EmailExposureCollector,
    EmailLocalMetadataCollector,
    ExecutionStatus,
    PhoneMetadataCollector,
    PhonePublicWebCollector,
    UsernameCollector,
    build_default_registry,
    metadata_for,
)
from osint_lab.agents.base import Collector, FindingCandidate, RawObservation
from osint_lab.agents.username_http import UsernameHttpResponse
from osint_lab.agents.phone_public_http import PhonePublicHttpResponse
from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.case_runner import CaseExecutionPlan, CaseRunStatus, CaseRunner
from osint_lab.case_storage import CaseStore, default_case_root
from osint_lab.evidence import EvidenceVault
from osint_lab.orchestrator.audit import AuditLog, verify_audit_log
from osint_lab.orchestrator.authorization_store import AuthorizationStore
from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.reporting import ReportEngine
from osint_lab.schemas import FindingStatus
from osint_lab.verification.contradictions import ContradictionAssertion, ContradictionSeverity


NOW = datetime(2026, 9, 19, 20, 0, tzinfo=timezone.utc)


class FakeResolver:
    def __init__(self):
        self.calls = []

    def resolve(self, query_name, query_type, **kwargs):
        self.calls.append((query_name, query_type, dict(kwargs)))
        raise dns.resolver.NoAnswer()


class FakeHttpClient:
    def __init__(self):
        self.calls = []

    def get(self, url, *, timeout, headers):
        self.calls.append({"url": url, "timeout": timeout, "headers": dict(headers)})
        return UsernameHttpResponse(
            status_code=404,
            final_url=url,
            body="generic not found",
            redirected=False,
        )


class FakePhonePublicHttpClient:
    def __init__(self):
        self.calls = []

    def get(self, url, *, timeout, headers):
        self.calls.append({"url": url, "timeout": timeout, "headers": dict(headers)})
        return PhonePublicHttpResponse(
            status_code=200,
            final_url=url,
            body="No results.",
            redirected=False,
        )


class FailingPhoneCollector(Collector):
    agent_name = "phone_metadata"
    agent_type = "PHONE"
    version = "fixture-failure"
    source_class = SourceClass.LOCAL
    network_required = False

    def validate_input(self, seed_reference: str) -> None:
        if not seed_reference:
            raise ValueError("seed required")

    def _run(self, context: ExecutionContext, seed_reference: str) -> tuple[RawObservation, ...]:
        raise RuntimeError("synthetic collector failure")

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        raise AssertionError("no observation expected")

    def describe_capabilities(self):
        return {"network": False, "fixture_failure": True}


def mixed_manifest(*, allow_passive=True, seeds=None, case_id="case-mvp-001"):
    allowed = {SourceClass.LOCAL}
    if allow_passive:
        allowed.add(SourceClass.PASSIVE_WEB)
    seed_values = seeds or (
        SeedEntity(entity_type="PHONE", value="+48123456789"),
        SeedEntity(entity_type="DOMAIN", value="domain.test"),
        SeedEntity(entity_type="USERNAME", value="fixture_user"),
        SeedEntity(entity_type="EMAIL", value="Fixture.User@example.test"),
    )
    return CaseManifest(
        case_id=case_id,
        case_name="Synthetic full MVP case",
        created_at=NOW - timedelta(days=1),
        authorized_by="fixture-owner",
        purpose="Offline end-to-end CaseRunner test",
        legal_basis_or_consent_note="Reserved synthetic fixtures only.",
        seed_entities=tuple(seed_values),
        allowed_source_classes=frozenset(allowed),
        forbidden_source_classes=frozenset({
            SourceClass.THIRD_PARTY_API,
            SourceClass.TOR,
            SourceClass.DIRECT_TARGET,
        }),
        allowed_agent_types=frozenset({"PHONE", "DOMAIN", "USERNAME", "EMAIL"}),
        retention_days=7,
        status=CaseStatus.ACTIVE,
    )


def build_test_application(tmp_path, *, collector_mapping=None, registry=None):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    case_root = tmp_path / "private-cases"
    store = CaseStore(repo_root=repo, root=case_root)
    vault = EvidenceVault(repo_root=repo, root=case_root)
    audit = AuditLog(repo_root=repo, root=tmp_path / "private-audit")
    authorization_store = AuthorizationStore(
        repo_root=repo,
        root=tmp_path / "private-authorizations",
    )
    resolver = FakeResolver()
    username_http = FakeHttpClient()
    email_http = FakeHttpClient()
    phone_public_http = FakePhonePublicHttpClient()
    collectors = collector_mapping or {
        "phone_metadata": PhoneMetadataCollector(),
        "phone_public_web": PhonePublicWebCollector(http_client=phone_public_http, clock=lambda: NOW),
        "domain_dns": DomainDNSCollector(resolver=resolver, resolver_label="mock://192.0.2.53"),
        "username_lookup": UsernameCollector(http_client=username_http, clock=lambda: NOW),
        "email_local_metadata": EmailLocalMetadataCollector(),
        "email_exposure": EmailExposureCollector(http_client=email_http, clock=lambda: NOW),
    }
    registry = registry or build_default_registry()
    orchestrator = Orchestrator(
        audit_log=audit,
        authorization_store=authorization_store,
        collector_registry=registry,
        evidence_vault=vault,
        clock=lambda: NOW,
    )
    reporter = ReportEngine(evidence_vault=vault, case_root=case_root, clock=lambda: NOW)
    runner = CaseRunner(
        orchestrator=orchestrator,
        registry=registry,
        collectors=collectors,
        case_store=store,
        report_engine=reporter,
        audit_log=audit,
        clock=lambda: NOW,
        id_factory=lambda: "fixture-run-id",
    )
    app = CliApplication(case_store=store, runner=runner, audit_log=audit)
    return app, resolver, username_http, email_http, vault


def contradiction_assertions(case_id="case-mvp-001"):
    return (
        ContradictionAssertion(
            assertion_id="assert-1",
            case_id=case_id,
            subject_id="fixture-subject",
            attribute="location",
            value="Fixture North",
            source_name="fixture-a",
            evidence_ref="ev-fixture-a",
            collected_at=NOW,
        ),
        ContradictionAssertion(
            assertion_id="assert-2",
            case_id=case_id,
            subject_id="fixture-subject",
            attribute="location",
            value="Fixture South",
            source_name="fixture-b",
            evidence_ref="ev-fixture-b",
            collected_at=NOW,
        ),
    )


def test_default_case_root_uses_local_app_data():
    assert default_case_root({"LOCALAPPDATA": r"C:\Fixture\Local"}) == Path(
        r"C:\Fixture\Local\LumirOSINTLab\cases"
    )


def test_case_creation_reload_and_no_silent_overwrite(tmp_path):
    app, *_ = build_test_application(tmp_path)
    manifest = mixed_manifest()
    path = app.case_store.create(manifest)
    assert path.is_file()
    assert app.case_store.load(manifest.case_id) == manifest
    with pytest.raises(FileExistsError):
        app.case_store.create(manifest)


def test_case_loader_fails_closed_on_invalid_manifest(tmp_path):
    app, *_ = build_test_application(tmp_path)
    directory = app.case_store.root / "case-broken"
    directory.mkdir(parents=True)
    (directory / "case.json").write_text('{"case_id":"case-broken"}', encoding="utf-8")
    with pytest.raises(ValueError, match="failed validation"):
        app.case_store.load("case-broken")


def test_plan_is_deterministic_and_maps_all_mvp_seeds(tmp_path):
    app, *_ = build_test_application(tmp_path)
    manifest = mixed_manifest()
    plan_a = app.runner.plan(manifest, persist=False)
    plan_b = app.runner.plan(manifest, persist=False)
    assert plan_a.to_dict() == plan_b.to_dict()
    assert [step.collector_name for step in plan_a.planned_steps] == [
        "phone_metadata",
        "phone_public_web",
        "domain_dns",
        "username_lookup",
        "email_local_metadata",
        "email_exposure",
        "domain_dns",
    ]
    assert plan_a.planned_steps[-1].dependencies == ("step-005",)
    assert set(plan_a.available_collectors) == {
        "phone_metadata",
        "phone_public_web",
        "domain_dns",
        "username_lookup",
        "email_local_metadata",
        "email_exposure",
    }


def test_dry_run_performs_no_collection_audit_or_evidence_publication(tmp_path):
    app, resolver, username_http, email_http, vault = build_test_application(tmp_path)
    manifest = mixed_manifest()
    app.case_store.create(manifest)
    result = app.runner.run(manifest, dry_run=True)
    assert isinstance(result, CaseExecutionPlan)
    assert resolver.calls == []
    assert username_http.calls == []
    assert email_http.calls == []
    assert app.audit_log.read(manifest.case_id) == ()
    assert not (vault.root / manifest.case_id / "raw").exists()


def test_duplicate_unknown_and_unavailable_steps_are_explicit(tmp_path):
    app, *_ = build_test_application(tmp_path)
    manifest = mixed_manifest(seeds=(
        SeedEntity(entity_type="PHONE", value="+48123456789"),
        SeedEntity(entity_type="phone", value="+48123456789"),
        SeedEntity(entity_type="DOCUMENT", value="fixture-document"),
    ))
    plan = app.runner.plan(manifest, persist=False)
    assert len(plan.planned_steps) == 2
    assert {item.reason for item in plan.skipped_steps} == {"duplicate seed", "unknown seed type"}

    mapping = dict(app.runner._collectors)
    del mapping["phone_metadata"]
    unavailable_app, *_ = build_test_application(tmp_path / "unavailable", collector_mapping=mapping)
    unavailable = unavailable_app.runner.plan(manifest, persist=False)
    assert any(item.reason == "collector is unavailable" for item in unavailable.skipped_steps)


def test_local_only_plan_and_passive_web_denial_do_not_call_network(tmp_path):
    app, resolver, username_http, email_http, _ = build_test_application(tmp_path)
    manifest = mixed_manifest(
        allow_passive=False,
        seeds=(SeedEntity(entity_type="EMAIL", value="Fixture.User@example.test"),),
    )
    app.case_store.create(manifest)
    plan = app.runner.plan(manifest, persist=False)
    assert [step.collector_name for step in plan.planned_steps] == ["email_local_metadata"]
    assert {step.collector_name for step in plan.denied_steps} == {"email_exposure", "domain_dns"}

    result = app.runner.run(manifest)
    assert result.overall_status is CaseRunStatus.PARTIAL
    assert [item.result_status for item in result.executions].count("DENIED") == 2
    assert resolver.calls == []
    assert username_http.calls == []
    assert email_http.calls == []


def test_phone_plan_runs_local_metadata_and_denies_public_web_when_disabled(tmp_path):
    app, *_ = build_test_application(tmp_path)
    case = mixed_manifest(
        allow_passive=False,
        seeds=(SeedEntity(entity_type="PHONE", value="+48123456789"),),
        case_id="case-phone-passive-disabled",
    )
    app.case_store.create(case)
    plan = app.runner.plan(case, persist=False)
    assert [item.collector_name for item in plan.planned_steps] == ["phone_metadata"]
    assert [item.collector_name for item in plan.denied_steps] == ["phone_public_web"]
    result = app.runner.run(case)
    assert [item.result_status for item in result.executions] == ["SUCCESS", "DENIED"]
    client = app.runner._collectors["phone_public_web"]._http_client
    assert client.calls == []


def test_all_denied_case_returns_denied(tmp_path):
    app, _, username_http, _, _ = build_test_application(tmp_path)
    manifest = mixed_manifest(
        allow_passive=False,
        seeds=(SeedEntity(entity_type="USERNAME", value="fixture_user"),),
    )
    app.case_store.create(manifest)
    result = app.runner.run(manifest)
    assert result.overall_status is CaseRunStatus.DENIED
    assert result.executions[0].result_status == "DENIED"
    assert username_http.calls == []


def test_failed_collector_returns_failed_case(tmp_path):
    collector = FailingPhoneCollector()
    registry = CollectorRegistry()
    registry.register(
        collector,
        metadata_for(collector, network_required=False, provenance="fixture:failure"),
    )
    app, *_ = build_test_application(
        tmp_path,
        collector_mapping={"phone_metadata": collector},
        registry=registry,
    )
    manifest = mixed_manifest(
        seeds=(SeedEntity(entity_type="PHONE", value="fixture-phone"),),
    )
    app.case_store.create(manifest)
    result = app.runner.run(manifest)
    assert result.overall_status is CaseRunStatus.FAILED
    assert result.executions[0].result_status == ExecutionStatus.FAILED.value
    assert result.report_reference is not None


def test_report_write_failure_degrades_success(monkeypatch, tmp_path):
    app, *_ = build_test_application(tmp_path)
    manifest = mixed_manifest(
        seeds=(SeedEntity(entity_type="EMAIL", value="Fixture.User@example.test"),),
        allow_passive=False,
    )
    app.case_store.create(manifest)
    monkeypatch.setattr(
        app.runner._report_engine,
        "write",
        lambda **kwargs: (_ for _ in ()).throw(OSError("report unavailable")),
    )
    result = app.runner.run(manifest, include_email_domain_dns=False)
    assert result.overall_status is CaseRunStatus.PARTIAL
    assert result.report_reference is None
    assert any("required report write failed" in item for item in result.warnings)


def test_full_offline_end_to_end_pipeline_and_reports(tmp_path):
    app, resolver, username_http, email_http, vault = build_test_application(tmp_path)
    manifest = mixed_manifest()
    app.case_store.create(manifest)
    plan = app.runner.plan(manifest)
    assert len(plan.planned_steps) == 7

    result = app.runner.run(
        manifest,
        contradiction_assertions=contradiction_assertions(),
    )
    assert result.overall_status is CaseRunStatus.PARTIAL
    assert len(result.executions) == 7
    assert len(result.receipts) == 7
    assert result.contradictions.severity is ContradictionSeverity.MEDIUM
    assert set(result.contradictions.evidence_refs) == {"ev-fixture-a", "ev-fixture-b"}
    assert result.findings_summary == {
        "CONFIRMED": 0,
        "PROBABLE": 0,
        "POSSIBLE": 2,
        "UNKNOWN": 1,
        "NOT_FOUND": 17,
        "FALSE_POSITIVE": 0,
    }
    assert len(resolver.calls) == 12
    assert len(username_http.calls) == 1
    assert len(email_http.calls) == 1
    assert result.audit_verification.valid is True
    assert verify_audit_log(app.audit_log, manifest.case_id).head_hash == result.audit_verification.head_hash

    reference = result.report_reference
    assert reference is not None
    json_bytes = Path(reference.json_path).read_bytes()
    html_bytes = Path(reference.html_path).read_bytes()
    assert hashlib.sha256(json_bytes).hexdigest() == reference.json_sha256
    assert hashlib.sha256(html_bytes).hexdigest() == reference.html_sha256
    report = json.loads(json_bytes)
    assert report["schema_version"] == "1.3"
    assessment = report["analytical_assessment"]
    assert assessment["known_technical_facts"]
    assert "probable_correlations" in assessment
    assert "open_hypotheses" in assessment
    assert "alternative_explanations" in assessment
    assert assessment["evidence_quality"]
    assert assessment["evidence_quality_summary"]["evidence_count"] > 0
    assert assessment["recommended_next_pivots"]
    assert assessment["layer_labels"] == ["FACT", "CORRELATION", "HYPOTHESIS", "VERIFICATION"]
    phone_execution = next(
        item for item in report["executions"] if item["collector"] == "phone_metadata"
    )
    assert len(phone_execution["observations"]) == 1
    phone_observation = phone_execution["observations"][0]
    assert phone_observation["raw_status"] == "PHONE_METADATA"
    phone_payload = phone_observation["payload"]
    assert phone_payload["normalized_e164"] == "+48123456789"
    assert phone_payload["international_format"] == "+48 12 345 67 89"
    assert phone_payload["national_format"] == "12 345 67 89"
    assert phone_payload["country_code"] == 48
    assert phone_payload["region_code"] == "PL"
    assert phone_payload["possible"] is True
    assert phone_payload["valid"] is True
    assert phone_payload["number_type"] == "FIXED_LINE"
    assert phone_payload["carrier_name"] is None
    assert phone_payload["geographic_description"]
    assert phone_payload["timezones"] == ["Europe/Warsaw"]
    serialized_phone_record = next(
        item.to_dict()
        for item in result.executions
        if item.step.collector_name == "phone_metadata"
    )
    assert serialized_phone_record["observations"][0]["payload"] == phone_payload
    assert report["privacy_source_exposure"] == {
        "DIRECT_TARGET": 0,
        "LOCAL": 2,
        "PASSIVE_WEB": 5,
        "THIRD_PARTY_API": 0,
        "TOR": 0,
    }
    assert report["contradictions"]["severity"] == "MEDIUM"
    assert len(report["audit"]["execution_receipt_refs"]) == 7
    assert report["audit"]["verified"] is True
    assert b"Private case report" in html_bytes
    combined = (json_bytes + html_bytes).decode("utf-8").casefold()
    html = html_bytes.decode("utf-8")
    assert "Szczegóły techniczne numeru" in html
    assert "Numer znormalizowany E.164" in html
    assert "+48123456789" in html
    assert "Czy numer możliwy</th><td>Tak" in html
    assert "Czy numer poprawny</th><td>Tak" in html
    assert "Typ numeru</th><td>FIXED_LINE" in html
    assert "Operator / carrier metadata</th><td>Brak danych lokalnych" in html
    assert "Europe/Warsaw" in html
    assert (
        "Dane planu numeracyjnego — nie potwierdzają aktualnego operatora, "
        "właściciela ani lokalizacji osoby."
    ) in html
    assert "ustalono właściciela" not in combined
    assert "to na pewno ta sama osoba" not in combined
    assert "not independently verified" in combined
    assert "ANALYTICAL ASSESSMENT" in html
    assert "Known technical facts" in html
    assert "Probable correlations" in html
    assert "Open hypotheses" in html
    assert "Evidence quality" in html
    assert "Alternative explanations" in html
    assert "Recommended next pivots" in html
    assert "Unresolved questions" in html
    assert "is the owner" not in combined
    assert "confirmed identity" not in combined

    receipt_json = json.dumps(
        [receipt.to_dict() for receipt in result.receipts],
        ensure_ascii=False,
    )
    assert "+48123456789" not in receipt_json

    for evidence_id in (reference.json_evidence_id, reference.html_evidence_id):
        evidence_directory = vault.root / manifest.case_id / "reports" / evidence_id
        assert (evidence_directory / "metadata.json").is_file()
    audit_bytes = (app.audit_log.root / manifest.case_id / "audit.jsonl").read_bytes()
    for seed in manifest.seed_entities:
        assert seed.value.encode() not in audit_bytes


def test_phone_report_shows_missing_local_carrier_and_geocoder_data(tmp_path):
    app, *_ = build_test_application(tmp_path)
    raw_phone = "123"
    manifest = mixed_manifest(
        case_id="case-phone-report-missing-001",
        allow_passive=False,
        seeds=(SeedEntity(entity_type="PHONE", value=raw_phone),),
    )
    app.case_store.create(manifest)
    result = app.runner.run(manifest)

    assert result.report_reference is not None
    report = json.loads(Path(result.report_reference.json_path).read_text(encoding="utf-8"))
    execution = report["executions"][0]
    payload = execution["observations"][0]["payload"]
    assert payload["normalized_e164"] == "+48123"
    assert payload["possible"] is False
    assert payload["valid"] is False
    assert payload["number_type"] == "UNKNOWN"
    assert payload["carrier_name"] is None
    assert payload["geographic_description"] is None
    assert payload["timezones"] == ["Etc/Unknown"]

    html = Path(result.report_reference.html_path).read_text(encoding="utf-8")
    assert "Operator / carrier metadata</th><td>Brak danych lokalnych" in html
    assert "Opis geograficzny</th><td>Brak danych lokalnych" in html
    assert "Czy numer możliwy</th><td>Nie" in html
    assert "Czy numer poprawny</th><td>Nie" in html
    assert "Typ numeru</th><td>UNKNOWN" in html
    assert "Strefy czasowe</th><td>Etc/Unknown" in html

    audit_bytes = (app.audit_log.root / manifest.case_id / "audit.jsonl").read_bytes()
    audit_entries = [json.loads(line) for line in audit_bytes.decode("utf-8").splitlines()]

    def scalar_values(value):
        if isinstance(value, dict):
            for item in value.values():
                yield from scalar_values(item)
        elif isinstance(value, list):
            for item in value:
                yield from scalar_values(item)
        else:
            yield value

    assert raw_phone not in {item for entry in audit_entries for item in scalar_values(entry)}
    receipt_bytes = json.dumps(result.receipts[0].to_dict(), ensure_ascii=False).encode("utf-8")
    assert raw_phone.encode() not in receipt_bytes


def test_cli_parser_exposes_required_commands():
    parser = build_parser()
    for arguments in (
        ["plan", "case-fixture"],
        ["run", "case-fixture", "--dry-run"],
        ["report", "case-fixture"],
        ["verify-audit", "case-fixture"],
    ):
        assert parser.parse_args(arguments).command == arguments[0]


def test_case_runner_source_has_no_private_collector_execution():
    source = (Path(__file__).resolve().parents[1] / "osint_lab" / "case_runner.py").read_text(
        encoding="utf-8"
    )
    assert "._run(" not in source


def test_cli_new_case_dry_run_report_and_verify(capsys, tmp_path):
    app, resolver, username_http, email_http, _ = build_test_application(tmp_path)
    create_args = [
        "new-case",
        "--case-id", "case-cli-001",
        "--case-name", "CLI fixture",
        "--purpose", "Offline CLI test",
        "--authorized-by", "fixture-owner",
        "--legal-note", "Synthetic fixture only",
        "--seed", "EMAIL=Fixture.User@example.test",
        "--allow-passive-web",
    ]
    assert main(create_args, application=app) == 0
    assert app.case_store.load("case-cli-001").case_id == "case-cli-001"
    assert main(["run", "case-cli-001", "--dry-run"], application=app) == 0
    assert resolver.calls == []
    assert username_http.calls == []
    assert email_http.calls == []

    manifest = app.case_store.load("case-cli-001")
    result = app.runner.run(manifest, include_email_domain_dns=False)
    assert result.report_reference is not None
    assert main(["report", "case-cli-001"], application=app) == 0
    assert main(["verify-audit", "case-cli-001"], application=app) == 0
    output = capsys.readouterr().out
    assert '"json_sha256"' in output
    assert '"valid": true' in output
