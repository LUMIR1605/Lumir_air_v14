from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from osint_lab.agents import (
    CollectorRegistry,
    ExecutionStatus,
    UsernameCollector,
    UsernameProvider,
    build_default_registry,
    metadata_for,
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


NOW = datetime(2026, 9, 19, 17, 0, tzinfo=timezone.utc)
USERNAME = "fixture_user"


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
        provider_id="fixture",
        name="Fixture Profiles",
        profile_url_template="https://profiles.test/{username}",
        method="GET",
        claimed_signals=("PROFILE::{username}",),
        available_signals=("USERNAME_AVAILABLE",),
        error_signals=("captcha", "cloudflare", "just a moment", "too many requests", "rate limit"),
        allowed_status_codes=(200, 403, 404, 429, 503),
        available_status_codes=(404,),
        timeout=3.0,
        enabled=True,
        notes="Deterministic offline fixture.",
        username_pattern=r"[A-Za-z0-9_.-]{1,64}",
        home_url="https://profiles.test/",
    )
    values.update(changes)
    return UsernameProvider(**values)


def response(status, body, *, final_url=None, redirected=False, truncated=False):
    return UsernameHttpResponse(
        status_code=status,
        final_url=final_url or f"https://profiles.test/{USERNAME}",
        body=body,
        redirected=redirected,
        body_truncated=truncated,
    )


def username_manifest(*, allow_passive=True):
    allowed = {SourceClass.LOCAL}
    if allow_passive:
        allowed.add(SourceClass.PASSIVE_WEB)
    return CaseManifest(
        case_id="case-username-001",
        case_name="Synthetic username fixture",
        created_at=NOW - timedelta(days=1),
        authorized_by="fixture-owner",
        purpose="Deterministic public profile test",
        legal_basis_or_consent_note="Reserved .test provider only.",
        seed_entities=(SeedEntity(entity_type="USERNAME", value=USERNAME),),
        allowed_source_classes=frozenset(allowed),
        forbidden_source_classes=frozenset({
            SourceClass.THIRD_PARTY_API,
            SourceClass.TOR,
            SourceClass.DIRECT_TARGET,
        }),
        allowed_agent_types=frozenset({"USERNAME"}),
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
        metadata_for(collector, network_required=True, provenance="fixture:http"),
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


def execute(orchestrator, collector, *, manifest=None):
    return orchestrator.execute(
        manifest=manifest or username_manifest(),
        collector=collector,
        seed_reference=USERNAME,
        purpose="Deterministic public profile test",
        requested_by="fixture-requester",
    )


@pytest.mark.parametrize(
    ("http_response", "provider_changes", "expected"),
    [
        (response(200, f"<html>PROFILE::{USERNAME}</html>"), {}, "CLAIMED"),
        (response(200, "USERNAME_AVAILABLE"), {}, "AVAILABLE"),
        (response(200, "generic landing page"), {}, "UNKNOWN"),
        (response(404, "generic not found"), {"available_status_codes": ()}, "UNKNOWN"),
        (response(404, "generic not found"), {}, "AVAILABLE"),
        (response(404, "CAPTCHA USERNAME_AVAILABLE"), {}, "UNKNOWN"),
        (response(503, "Cloudflare Just a moment..."), {}, "UNKNOWN"),
        (response(429, "Too Many Requests"), {}, "UNKNOWN"),
        (response(403, "Forbidden"), {}, "UNKNOWN"),
        (response(500, "USERNAME_AVAILABLE"), {}, "UNKNOWN"),
        (
            response(
                200,
                f"PROFILE::{USERNAME}",
                final_url="https://profiles.test/",
                redirected=True,
            ),
            {},
            "UNKNOWN",
        ),
        (
            response(
                200,
                f"PROFILE::{USERNAME}",
                final_url=f"https://profiles.test/{USERNAME}/",
                redirected=True,
            ),
            {},
            "CLAIMED",
        ),
    ],
)
def test_provider_specific_false_positive_policy(
    tmp_path,
    http_response,
    provider_changes,
    expected,
):
    provider = fixture_provider(**provider_changes)
    collector = UsernameCollector(
        providers=(provider,),
        http_client=FakeHttpClient(http_response),
        clock=lambda: NOW,
    )
    orchestrator, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)

    assert result.status is ExecutionStatus.SUCCESS
    assert result.observations[0].payload["status"] == expected
    expected_candidate = {
        "CLAIMED": FindingStatus.POSSIBLE,
        "AVAILABLE": FindingStatus.NOT_FOUND,
        "UNKNOWN": FindingStatus.UNKNOWN,
    }[expected]
    assert result.finding_candidates[0].normalized_status is expected_candidate
    assert result.finding_candidates[0].normalized_status is not FindingStatus.CONFIRMED


def test_http_200_without_claimed_signal_never_means_claimed(tmp_path):
    client = FakeHttpClient(response(200, "generic public homepage"))
    collector = UsernameCollector(
        providers=(fixture_provider(),),
        http_client=client,
        clock=lambda: NOW,
    )
    orchestrator, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)
    assert result.observations[0].payload["http_status"] == 200
    assert result.observations[0].payload["status"] == "UNKNOWN"
    assert "no_provider_specific_signal" in result.observations[0].payload["signals"]


@pytest.mark.parametrize(
    "body,status_code",
    [
        ("CAPTCHA USERNAME_AVAILABLE", 200),
        ("Cloudflare challenge USERNAME_AVAILABLE", 200),
        ("rate limit USERNAME_AVAILABLE", 429),
    ],
)
def test_challenge_or_rate_limit_never_means_available(tmp_path, body, status_code):
    collector = UsernameCollector(
        providers=(fixture_provider(),),
        http_client=FakeHttpClient(response(status_code, body)),
        clock=lambda: NOW,
    )
    orchestrator, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)
    assert result.observations[0].payload["status"] == "UNKNOWN"
    assert result.finding_candidates[0].normalized_status is FindingStatus.UNKNOWN


@pytest.mark.parametrize(
    ("failure", "status", "error_code"),
    [
        (UsernameHttpTimeout("timeout"), "UNKNOWN", "TIMEOUT"),
        (UsernameHttpConnectionError("connection"), "UNKNOWN", "CONNECTION_ERROR"),
        (RuntimeError("client failure"), "ERROR", "RUNTIMEERROR"),
    ],
)
def test_http_failures_are_not_false_availability(tmp_path, failure, status, error_code):
    collector = UsernameCollector(
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
    malformed_client = FakeHttpClient({"status_code": 200})
    collector = UsernameCollector(
        providers=(fixture_provider(),),
        http_client=malformed_client,
        clock=lambda: NOW,
    )
    orchestrator, _, _ = setup_orchestrator(tmp_path, collector)
    malformed = execute(orchestrator, collector)
    assert malformed.observations[0].payload["status"] == "ERROR"
    assert malformed.observations[0].payload["error_code"] == "MALFORMED_RESPONSE"

    disabled_client = FakeHttpClient(response(200, f"PROFILE::{USERNAME}"))
    disabled_collector = UsernameCollector(
        providers=(fixture_provider(enabled=False),),
        http_client=disabled_client,
        clock=lambda: NOW,
    )
    disabled_orchestrator, _, _ = setup_orchestrator(tmp_path / "disabled", disabled_collector)
    disabled = execute(disabled_orchestrator, disabled_collector)
    assert disabled.observations[0].payload["status"] == "UNKNOWN"
    assert disabled.observations[0].payload["error_code"] == "PROVIDER_DISABLED"
    assert disabled_client.calls == []


@pytest.mark.parametrize(
    "value",
    ["", "   ", "https://profiles.test/user", "user name", "user/name", "@user", "user😀", "x" * 65],
)
def test_invalid_username_is_rejected(value):
    with pytest.raises(ValueError):
        UsernameCollector._normalize_username(value)


def test_default_registry_binds_username_provider_configuration():
    registry = build_default_registry()
    collector = UsernameCollector()
    metadata = registry.validate(collector)
    assert collector.source_class is SourceClass.PASSIVE_WEB
    assert collector.network_required is True
    assert metadata.network_required is True
    assert metadata.provenance.startswith("requests:")
    assert metadata.capabilities["providers"] == ["github", "gitlab"]

    with pytest.raises(ValueError, match="duplicate"):
        registry.register(collector, metadata)

    changed = UsernameCollector(providers=(replace(fixture_provider(), provider_id="other"),))
    with pytest.raises(PermissionError, match="metadata"):
        registry.validate(changed)

    class ReplacementUsernameCollector(UsernameCollector):
        agent_name = "username_lookup"

    with pytest.raises(PermissionError, match="substituted"):
        registry.validate(ReplacementUsernameCollector())


def test_policy_gate_denies_before_http_without_passive_web(tmp_path):
    client = FakeHttpClient(response(200, f"PROFILE::{USERNAME}"))
    collector = UsernameCollector(
        providers=(fixture_provider(),),
        http_client=client,
        clock=lambda: NOW,
    )
    orchestrator, audit, _ = setup_orchestrator(tmp_path, collector)
    result = execute(
        orchestrator,
        collector,
        manifest=username_manifest(allow_passive=False),
    )
    assert result.status is ExecutionStatus.DENIED
    assert client.calls == []
    assert audit.read("case-username-001")[-1]["event_type"] == "RUN_DENIED"


def test_orchestrator_persists_username_evidence_receipt_and_private_audit(tmp_path):
    unique_body = f"<html>PROFILE::{USERNAME} PRIVATE_FIXTURE_BODY</html>"
    client = FakeHttpClient(response(200, unique_body))
    collector = UsernameCollector(
        providers=(fixture_provider(),),
        http_client=client,
        clock=lambda: NOW,
    )
    orchestrator, audit, vault = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)

    assert result.status is ExecutionStatus.SUCCESS
    assert result.receipt is not None
    assert result.receipt.collector == "username_lookup"
    assert result.receipt.source_class is SourceClass.PASSIVE_WEB
    assert result.receipt.audit_head_hash == verify_audit_log(
        audit,
        "case-username-001",
    ).head_hash
    assert client.calls[0]["headers"]["User-Agent"] == "LumirOSINTLab-UsernameCollector/1.0"
    assert client.calls[0]["timeout"] == 3.0

    audit_bytes = (audit.root / "case-username-001" / "audit.jsonl").read_bytes()
    assert USERNAME.encode() not in audit_bytes
    assert hashlib.sha256(USERNAME.encode()).hexdigest().encode() in audit_bytes
    events = audit.read("case-username-001")
    assert events[1]["decision"] == "ALLOW"
    assert events[2]["decision"] == "NOT_REQUIRED"

    raw_directory = next((vault.root / "case-username-001" / "raw").glob("ev-*"))
    record_path = next(raw_directory.glob("run-*.json"))
    record_bytes = record_path.read_bytes()
    record = json.loads(record_bytes)
    payload = record["raw_observations"][0]["payload"]
    assert payload["username"] == USERNAME
    assert payload["profile_url"] == f"https://profiles.test/{USERNAME}"
    assert payload["status"] == "CLAIMED"
    assert payload["request_method"] == "GET"
    assert payload["collector_version"] == "1.0.0"
    assert payload["body_sha256"] == hashlib.sha256(unique_body.encode()).hexdigest()
    assert b"PRIVATE_FIXTURE_BODY" not in record_bytes

    receipt_directory = next((vault.root / "case-username-001" / "reports").glob("ev-*"))
    receipt_bytes = next(receipt_directory.glob("run-*-receipt.json")).read_bytes()
    assert USERNAME.encode() not in receipt_bytes
    assert result.receipt.evidence_refs[0] == json.loads(
        (raw_directory / "metadata.json").read_text(encoding="utf-8")
    )["evidence_id"]

    serialized = json.dumps(record)
    for forbidden_claim in ("SAME_PERSON", "IDENTITY_CONFIRMED", "PERSON_TO_USERNAME"):
        assert forbidden_claim not in serialized
    assert all(
        candidate.normalized_status is not FindingStatus.CONFIRMED
        for candidate in result.finding_candidates
    )


def test_username_collector_has_no_subprocess_or_browser_automation_imports():
    repository = Path(__file__).resolve().parents[1]
    source = "\n".join(
        (repository / "osint_lab" / "agents" / name).read_text(encoding="utf-8")
        for name in ("username_lookup.py", "username_http.py", "username_providers.py")
    )
    assert "subprocess" not in source
    assert "selenium" not in source
    assert "playwright" not in source
