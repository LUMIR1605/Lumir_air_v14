import ast
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from osint_lab.agents import (
    CollectorRegistry,
    EmailExposureCollector,
    EmailLocalMetadataCollector,
    EmailProvider,
    ExecutionStatus,
    build_default_registry,
    metadata_for,
)
from osint_lab.agents.email_exposure import (
    DISPOSABLE_PROVIDER_DOMAINS,
    FREE_PROVIDER_DOMAINS,
    normalize_email,
)
from osint_lab.agents.username_http import (
    UsernameHttpConnectionError,
    UsernameHttpResponse,
    UsernameHttpTimeout,
)
from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.evidence import EvidenceVault
from osint_lab.orchestrator.audit import AuditLog, verify_audit_log
from osint_lab.orchestrator.authorization_store import AuthorizationStore
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus


NOW = datetime(2026, 9, 19, 19, 0, tzinfo=timezone.utc)
EMAIL = "Fixture.User@example.test"


class FakeHttpClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, *, timeout, headers):
        self.calls.append({"url": url, "timeout": timeout, "headers": dict(headers)})
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


def fixture_provider(**changes):
    values = dict(
        provider_id="fixture_public",
        name="Fixture public profile",
        method="GET",
        endpoint_template="https://profiles.test/public/{email_sha256}",
        claimed_signals=('"profile_url"',),
        available_signals=("PROFILE_ABSENT",),
        error_signals=("captcha", "cloudflare", "just a moment", "too many requests", "rate limit"),
        allowed_status_codes=(200, 403, 404, 429, 500, 503),
        available_status_codes=(404,),
        timeout=3.0,
        enabled=True,
        privacy_notes="Fixture receives only a SHA-256 identifier.",
        notes="Deterministic offline fixture.",
    )
    values.update(changes)
    return EmailProvider(**values)


def response(status, body, *, final_url="https://profiles.test/public/hash", redirected=False, truncated=False):
    return UsernameHttpResponse(
        status_code=status,
        final_url=final_url,
        body=body,
        redirected=redirected,
        body_truncated=truncated,
    )


def email_manifest(*, allow_local=True, allow_passive=True):
    allowed = set()
    if allow_local:
        allowed.add(SourceClass.LOCAL)
    if allow_passive:
        allowed.add(SourceClass.PASSIVE_WEB)
    return CaseManifest(
        case_id="case-email-001",
        case_name="Synthetic email fixture",
        created_at=NOW - timedelta(days=1),
        authorized_by="fixture-owner",
        purpose="Deterministic email metadata test",
        legal_basis_or_consent_note="Reserved example.test input only.",
        seed_entities=(SeedEntity(entity_type="EMAIL", value=EMAIL),),
        allowed_source_classes=frozenset(allowed),
        forbidden_source_classes=frozenset({
            SourceClass.THIRD_PARTY_API,
            SourceClass.TOR,
            SourceClass.DIRECT_TARGET,
        }),
        allowed_agent_types=frozenset({"EMAIL"}),
        retention_days=7,
        status=CaseStatus.ACTIVE,
    )


def setup_orchestrator(tmp_path, collector):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    audit = AuditLog(repo_root=repo, root=tmp_path / "private-audit")
    vault = EvidenceVault(repo_root=repo, root=tmp_path / "private-vault")
    registry = CollectorRegistry()
    registry.register(
        collector,
        metadata_for(
            collector,
            network_required=collector.network_required,
            provenance="fixture:email",
        ),
    )
    orchestrator = Orchestrator(
        audit_log=audit,
        authorization_store=AuthorizationStore(
            repo_root=repo,
            root=tmp_path / "private-authorizations",
        ),
        collector_registry=registry,
        evidence_vault=vault,
        clock=lambda: NOW,
    )
    return orchestrator, audit, vault


def execute(orchestrator, collector, *, manifest=None, email=EMAIL):
    return orchestrator.execute(
        manifest=manifest or email_manifest(),
        collector=collector,
        seed_reference=email,
        purpose="Deterministic email metadata test",
        requested_by="fixture-requester",
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (EMAIL, EMAIL),
        (f"  {EMAIL}  ", EMAIL),
        ("Fixture.User@EXAMPLE.TEST", EMAIL),
        ("Fixture.User@täst.example", "Fixture.User@xn--tst-qla.example"),
    ],
)
def test_email_input_normalization(value, expected):
    assert normalize_email(value)[0] == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "fixture.example.test",
        "a@b@example.test",
        "@example.test",
        "fixture@",
        "fixture@localhost",
        "fixture@bad..example",
        "fixture@-bad.example",
        f"{'a' * 65}@example.test",
        f"fixture@{'a' * 244}.example",
    ],
)
def test_invalid_email_is_rejected_without_repair(value):
    with pytest.raises(ValueError):
        normalize_email(value)


def test_local_metadata_preserves_local_part_and_unknown_list_semantics(tmp_path):
    collector = EmailLocalMetadataCollector()
    orchestrator, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector, email="Mixed.Case@EXAMPLE.TEST")

    assert result.status is ExecutionStatus.SUCCESS
    payload = result.observations[0].payload
    assert payload["normalized_email"] == "Mixed.Case@example.test"
    assert payload["local_part"] == "Mixed.Case"
    assert payload["domain"] == "example.test"
    assert payload["domain_idna"] == "example.test"
    assert payload["syntax_valid"] is True
    assert payload["provider_class"] is None
    assert payload["free_provider"] is None
    assert payload["disposable_provider"] is None
    assert payload["domain_dns_dependency"] == {
        "collector": "domain_dns",
        "seed_reference": "example.test",
        "source_class": "PASSIVE_WEB",
        "requires_separate_policy_evaluation": True,
    }
    assert json.loads(json.dumps(dict(payload)))
    assert result.finding_candidates[0].raw_status == "EMAIL_SYNTAX_VALID"
    assert result.finding_candidates[0].normalized_status is FindingStatus.POSSIBLE


def test_explicit_provider_lists_never_turn_missing_into_false():
    assert EmailLocalMetadataCollector._provider_metadata(next(iter(FREE_PROVIDER_DOMAINS))) == (
        "FREE_WEBMAIL", True, None
    )
    assert EmailLocalMetadataCollector._provider_metadata(next(iter(DISPOSABLE_PROVIDER_DOMAINS))) == (
        "DISPOSABLE_CANDIDATE", None, True
    )
    assert EmailLocalMetadataCollector._provider_metadata("unknown.example") == (None, None, None)


@pytest.mark.parametrize(
    ("http_response", "provider_changes", "expected", "candidate"),
    [
        (response(200, '{"profile_url":"https://profiles.test/u"}'), {}, "CLAIMED", FindingStatus.POSSIBLE),
        (response(200, "PROFILE_ABSENT"), {}, "AVAILABLE", FindingStatus.NOT_FOUND),
        (response(200, "generic page"), {}, "UNKNOWN", FindingStatus.UNKNOWN),
        (response(200, "CAPTCHA PROFILE_ABSENT"), {}, "UNKNOWN", FindingStatus.UNKNOWN),
        (response(403, "forbidden"), {}, "UNKNOWN", FindingStatus.UNKNOWN),
        (response(429, "too many requests"), {}, "UNKNOWN", FindingStatus.UNKNOWN),
        (response(503, "server unavailable"), {}, "ERROR", FindingStatus.UNKNOWN),
        (
            response(
                200,
                '{"profile_url":"https://profiles.test/u"}',
                final_url="https://profiles.test/login",
                redirected=True,
            ),
            {},
            "UNKNOWN",
            FindingStatus.UNKNOWN,
        ),
        (response(404, "generic not found"), {}, "AVAILABLE", FindingStatus.NOT_FOUND),
        (response(404, "generic not found"), {"available_status_codes": ()}, "UNKNOWN", FindingStatus.UNKNOWN),
    ],
)
def test_exposure_false_positive_policy(tmp_path, http_response, provider_changes, expected, candidate):
    collector = EmailExposureCollector(
        providers=(fixture_provider(**provider_changes),),
        http_client=FakeHttpClient(http_response),
        clock=lambda: NOW,
    )
    orchestrator, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)

    assert result.status is ExecutionStatus.SUCCESS
    assert result.observations[0].payload["status"] == expected
    assert result.finding_candidates[0].normalized_status is candidate
    assert result.finding_candidates[0].normalized_status is not FindingStatus.CONFIRMED


@pytest.mark.parametrize(
    ("failure", "status", "error_code"),
    [
        (UsernameHttpTimeout("timeout"), "UNKNOWN", "TIMEOUT"),
        (UsernameHttpConnectionError("connection"), "UNKNOWN", "CONNECTION_ERROR"),
        (RuntimeError("client failure"), "ERROR", "RUNTIMEERROR"),
    ],
)
def test_exposure_failures_are_not_false_availability(tmp_path, failure, status, error_code):
    collector = EmailExposureCollector(
        providers=(fixture_provider(),),
        http_client=FakeHttpClient(failure),
        clock=lambda: NOW,
    )
    orchestrator, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)
    assert result.observations[0].payload["status"] == status
    assert result.observations[0].payload["error_code"] == error_code
    assert result.finding_candidates[0].normalized_status is FindingStatus.UNKNOWN


def test_malformed_response_and_disabled_provider_are_safe(tmp_path):
    malformed = EmailExposureCollector(
        providers=(fixture_provider(),),
        http_client=FakeHttpClient({"status_code": 200}),
        clock=lambda: NOW,
    )
    orchestrator, _, _ = setup_orchestrator(tmp_path, malformed)
    malformed_result = execute(orchestrator, malformed)
    assert malformed_result.observations[0].payload["status"] == "ERROR"
    assert malformed_result.observations[0].payload["error_code"] == "MALFORMED_RESPONSE"

    client = FakeHttpClient(response(200, '{"profile_url":"x"}'))
    disabled = EmailExposureCollector(
        providers=(fixture_provider(enabled=False),),
        http_client=client,
        clock=lambda: NOW,
    )
    orchestrator, _, _ = setup_orchestrator(tmp_path / "disabled", disabled)
    disabled_result = execute(orchestrator, disabled)
    assert disabled_result.observations[0].payload["status"] == "UNKNOWN"
    assert disabled_result.observations[0].payload["error_code"] == "PROVIDER_DISABLED"
    assert client.calls == []


def test_exposure_uses_only_provider_normalized_hash(tmp_path):
    client = FakeHttpClient(response(200, "generic"))
    collector = EmailExposureCollector(
        providers=(fixture_provider(),),
        http_client=client,
        clock=lambda: NOW,
    )
    orchestrator, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)
    expected_hash = hashlib.sha256(EMAIL.casefold().encode()).hexdigest()

    assert expected_hash in client.calls[0]["url"]
    assert EMAIL not in client.calls[0]["url"]
    assert result.observations[0].payload["email_reference"] == f"sha256:{expected_hash}"
    assert EMAIL not in json.dumps(dict(result.observations[0].payload))


def test_email_provider_rejects_raw_or_abusive_endpoints():
    with pytest.raises(ValueError, match="raw email"):
        fixture_provider(endpoint_template="https://profiles.test/public/{email}/{email_sha256}")
    for path in ("login", "signup", "password-reset", "account-recovery", "challenge"):
        with pytest.raises(ValueError, match="forbidden"):
            fixture_provider(endpoint_template=f"https://profiles.test/{path}/{{email_sha256}}")


def test_registry_factory_binds_both_collectors_and_provider_config():
    registry = build_default_registry()
    local = EmailLocalMetadataCollector()
    exposure = EmailExposureCollector()

    local_metadata = registry.validate(local)
    exposure_metadata = registry.validate(exposure)
    assert local_metadata.source_class is SourceClass.LOCAL
    assert local_metadata.network_required is False
    assert exposure_metadata.source_class is SourceClass.PASSIVE_WEB
    assert exposure_metadata.network_required is True
    assert exposure_metadata.capabilities["provider_config_sha256"]

    changed = EmailExposureCollector(providers=(fixture_provider(),))
    with pytest.raises(PermissionError, match="metadata"):
        registry.validate(changed)


def test_registry_detects_provider_config_change_after_registration():
    collector = EmailExposureCollector(providers=(fixture_provider(),))
    registry = CollectorRegistry()
    registry.register(collector, metadata_for(collector, network_required=True, provenance="fixture"))
    collector._providers = (fixture_provider(enabled=False),)
    with pytest.raises(PermissionError, match="metadata"):
        registry.validate(collector)


def test_policy_gate_is_separate_for_local_and_passive_web(tmp_path):
    local = EmailLocalMetadataCollector()
    local_orchestrator, _, _ = setup_orchestrator(tmp_path / "local", local)
    assert execute(local_orchestrator, local, manifest=email_manifest(allow_local=True, allow_passive=False)).status is ExecutionStatus.SUCCESS
    assert execute(local_orchestrator, local, manifest=email_manifest(allow_local=False, allow_passive=True)).status is ExecutionStatus.DENIED

    client = FakeHttpClient(response(200, '{"profile_url":"x"}'))
    exposure = EmailExposureCollector(
        providers=(fixture_provider(),),
        http_client=client,
        clock=lambda: NOW,
    )
    web_orchestrator, _, _ = setup_orchestrator(tmp_path / "web", exposure)
    assert execute(web_orchestrator, exposure, manifest=email_manifest()).status is ExecutionStatus.SUCCESS
    calls_after_allowed = len(client.calls)
    assert execute(
        web_orchestrator,
        exposure,
        manifest=email_manifest(allow_local=True, allow_passive=False),
    ).status is ExecutionStatus.DENIED
    assert len(client.calls) == calls_after_allowed


def test_orchestrator_email_privacy_vault_receipt_and_audit_chain(tmp_path):
    collector = EmailLocalMetadataCollector()
    orchestrator, audit, vault = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)

    assert result.status is ExecutionStatus.SUCCESS
    assert result.receipt is not None
    assert result.receipt.collector == "email_local_metadata"
    assert result.receipt.audit_head_hash == verify_audit_log(audit, "case-email-001").head_hash
    audit_bytes = (audit.root / "case-email-001" / "audit.jsonl").read_bytes()
    assert EMAIL.encode() not in audit_bytes
    assert hashlib.sha256(EMAIL.encode()).hexdigest().encode() in audit_bytes

    raw_directory = next((vault.root / "case-email-001" / "raw").glob("ev-*"))
    record_bytes = next(raw_directory.glob("run-*.json")).read_bytes()
    assert EMAIL.encode() in record_bytes
    receipt_directory = next((vault.root / "case-email-001" / "reports").glob("ev-*"))
    receipt_bytes = next(receipt_directory.glob("run-*-receipt.json")).read_bytes()
    assert EMAIL.encode() not in receipt_bytes
    assert result.receipt.evidence_refs

    serialized = record_bytes.decode("utf-8")
    for forbidden_claim in ("ACCOUNT_OWNER", "IDENTITY_CONFIRMED", "SAME_PERSON", "PERSON_TO_EMAIL"):
        assert forbidden_claim not in serialized


def test_email_module_has_no_subprocess_browser_or_holehe_imports():
    source_path = Path(__file__).resolve().parents[1] / "osint_lab" / "agents" / "email_exposure.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports.isdisjoint({"subprocess", "selenium", "playwright", "webbrowser", "holehe"})
