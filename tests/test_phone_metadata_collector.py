import ast
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import urllib.request

import pytest

from osint_lab.agents import (
    CollectorRegistry,
    ExecutionStatus,
    PhoneMetadataCollector,
    RawObservation,
    build_default_registry,
)
from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.evidence import EvidenceVault
from osint_lab.orchestrator.audit import AuditLog, verify_audit_log
from osint_lab.orchestrator.authorization_store import AuthorizationStore
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus


NOW = datetime(2026, 9, 19, 15, 0, tzinfo=timezone.utc)
OFFICIAL_PL_EXAMPLE = "+48123456789"


def phone_manifest() -> CaseManifest:
    return CaseManifest(
        case_id="case-phone-local-001",
        case_name="Synthetic local phone metadata fixture",
        created_at=NOW - timedelta(days=1),
        authorized_by="fixture-owner",
        purpose="Test local numbering-plan metadata",
        legal_basis_or_consent_note="Official phonenumbers example only.",
        seed_entities=(SeedEntity(entity_type="PHONE", value=OFFICIAL_PL_EXAMPLE),),
        allowed_source_classes=frozenset({SourceClass.LOCAL}),
        forbidden_source_classes=frozenset({
            SourceClass.THIRD_PARTY_API,
            SourceClass.TOR,
            SourceClass.DIRECT_TARGET,
        }),
        allowed_agent_types=frozenset({"PHONE"}),
        retention_days=7,
        status=CaseStatus.ACTIVE,
    )


def setup_orchestrator(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    audit = AuditLog(repo_root=repo, root=tmp_path / "private-audit")
    vault = EvidenceVault(repo_root=repo, root=tmp_path / "private-vault")
    orchestrator = Orchestrator(
        audit_log=audit,
        authorization_store=AuthorizationStore(
            repo_root=repo,
            root=tmp_path / "private-authorizations",
        ),
        collector_registry=build_default_registry(),
        evidence_vault=vault,
        clock=lambda: NOW,
    )
    return orchestrator, audit, vault


def execute(orchestrator, value):
    return orchestrator.execute(
        manifest=phone_manifest(),
        collector=PhoneMetadataCollector(),
        seed_reference=value,
        purpose="Synthetic local phone metadata test",
        requested_by="fixture-requester",
    )


@pytest.mark.parametrize(
    "value",
    [
        OFFICIAL_PL_EXAMPLE,
        "48123456789",
        "123456789",
        "+48 123 456 789",
        "+48-123-456-789",
        "+48 (12) 345-67-89",
    ],
)
def test_supported_polish_input_forms_normalize_to_e164(tmp_path, value):
    orchestrator, _, _ = setup_orchestrator(tmp_path)
    result = execute(orchestrator, value)
    payload = result.observations[0].payload

    assert result.status is ExecutionStatus.SUCCESS
    assert payload["raw_input"] == value
    assert payload["normalized_e164"] == OFFICIAL_PL_EXAMPLE
    assert payload["international_format"] == "+48 12 345 67 89"
    assert payload["national_format"] == "12 345 67 89"
    assert payload["country_code"] == 48
    assert payload["region_code"] == "PL"
    assert payload["valid"] is True
    assert payload["possible"] is True
    assert payload["number_type"] == "FIXED_LINE"
    assert payload["carrier_name"] is None
    assert payload["timezones"] == ["Europe/Warsaw"]
    assert result.finding_candidates[0].normalized_status is FindingStatus.POSSIBLE


@pytest.mark.parametrize(
    ("value", "possible"),
    [
        ("+48111111111", True),
        ("123", False),
    ],
)
def test_invalid_or_impossible_parsable_number_is_unknown_not_failed(tmp_path, value, possible):
    orchestrator, _, _ = setup_orchestrator(tmp_path)
    result = execute(orchestrator, value)
    observation = result.observations[0]

    assert result.status is ExecutionStatus.SUCCESS
    assert observation.raw_status == "UNKNOWN"
    assert observation.payload["possible"] is possible
    assert observation.payload["valid"] is False
    assert result.finding_candidates[0].normalized_status is FindingStatus.UNKNOWN
    assert observation.payload["carrier_name"] is None
    if value == "123":
        assert observation.payload["geographic_description"] is None
    assert "NOT_FOUND" not in observation.notes


def test_raw_observation_payload_is_optional_json_safe_and_backward_compatible():
    legacy = RawObservation(raw_status="FOUND", value_reference="fixture-ref")
    assert dict(legacy.payload) == {}
    assert json.loads(json.dumps(dict(legacy.payload))) == {}

    observation = RawObservation(
        raw_status="FOUND",
        value_reference="fixture-ref",
        payload={"value": None, "items": ["a", 1, True]},
    )
    assert json.loads(json.dumps(dict(observation.payload))) == {
        "value": None,
        "items": ["a", 1, True],
    }
    with pytest.raises(ValueError, match="JSON-safe"):
        RawObservation(raw_status="FOUND", value_reference="fixture-ref", payload={"bad": object()})


def test_phone_collector_metadata_and_default_registry_enforcement():
    collector = PhoneMetadataCollector()
    assert collector.agent_name == "phone_metadata"
    assert collector.agent_type == "PHONE"
    assert collector.version == "1.0.0"
    assert collector.source_class is SourceClass.LOCAL
    assert collector.network_required is False
    assert collector.default_region == "PL"
    assert collector.describe_capabilities()["network"] is False

    registry = build_default_registry()
    metadata = registry.validate(collector)
    assert metadata.network_required is False
    assert metadata.source_class is SourceClass.LOCAL
    assert metadata.provenance.startswith("phonenumbers:")
    with pytest.raises(PermissionError, match="not registered"):
        CollectorRegistry().validate(collector)


def test_phone_collector_has_no_banned_network_imports():
    source_path = Path(__file__).resolve().parents[1] / "osint_lab" / "agents" / "phone_metadata.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports.isdisjoint({"requests", "urllib", "socket", "subprocess", "dns"})


def test_orchestrator_path_uses_no_network_and_persists_private_evidence(
    tmp_path,
    monkeypatch,
):
    orchestrator, audit, vault = setup_orchestrator(tmp_path)

    def network_forbidden(*args, **kwargs):
        raise AssertionError("network or subprocess access is forbidden")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", network_forbidden)
    monkeypatch.setattr(subprocess, "Popen", network_forbidden)
    monkeypatch.setattr(subprocess, "run", network_forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", network_forbidden)

    result = execute(orchestrator, OFFICIAL_PL_EXAMPLE)
    assert result.status is ExecutionStatus.SUCCESS
    assert result.receipt is not None
    assert result.receipt.collector == "phone_metadata"
    assert result.receipt.collector_version == "1.0.0"
    assert result.receipt.source_class is SourceClass.LOCAL
    assert result.receipt.audit_head_hash == verify_audit_log(
        audit,
        "case-phone-local-001",
    ).head_hash

    events = audit.read("case-phone-local-001")
    assert [entry["event_type"] for entry in events] == [
        "RUN_REQUESTED",
        "POLICY_EVALUATED",
        "AUTHORIZATION_CHECKED",
        "RUN_ALLOWED",
        "AGENT_STARTED",
        "AGENT_FINISHED",
    ]
    assert events[1]["decision"] == "ALLOW"
    audit_bytes = (audit.root / "case-phone-local-001" / "audit.jsonl").read_bytes()
    assert OFFICIAL_PL_EXAMPLE.encode() not in audit_bytes
    assert hashlib.sha256(OFFICIAL_PL_EXAMPLE.encode()).hexdigest().encode() in audit_bytes

    raw_root = vault.root / "case-phone-local-001" / "raw"
    raw_directory = next(raw_root.glob("ev-*"))
    record = json.loads(next(raw_directory.glob("run-*.json")).read_text(encoding="utf-8"))
    stored_observation = record["raw_observations"][0]
    assert stored_observation["payload"]["raw_input"] == OFFICIAL_PL_EXAMPLE
    assert stored_observation["payload"]["normalized_e164"] == OFFICIAL_PL_EXAMPLE
    assert stored_observation["payload"]["geographic_description"]
    assert record["normalized_candidates"][0]["normalized_status"] == "POSSIBLE"

    receipt_root = vault.root / "case-phone-local-001" / "reports"
    receipt_directory = next(receipt_root.glob("ev-*"))
    receipt_bytes = next(receipt_directory.glob("run-*-receipt.json")).read_bytes()
    assert OFFICIAL_PL_EXAMPLE.encode() not in receipt_bytes
    assert result.receipt.evidence_refs[0] == json.loads(
        (raw_directory / "metadata.json").read_text(encoding="utf-8")
    )["evidence_id"]

    serialized = json.dumps(record, ensure_ascii=False)
    for forbidden_claim in ("PERSON → PHONE", "OWNER", "IDENTITY_MATCH", "SOCIAL_PROFILE_MATCH"):
        assert forbidden_claim not in serialized
    assert all(
        candidate.normalized_status is not FindingStatus.CONFIRMED
        for candidate in result.finding_candidates
    )


def test_phone_collector_cannot_bypass_orchestrator():
    with pytest.raises(PermissionError, match="orchestrator-issued"):
        PhoneMetadataCollector().run(object(), OFFICIAL_PL_EXAMPLE)
