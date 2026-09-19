from datetime import datetime, timedelta, timezone
import json

import pytest

from osint_lab.agents import (
    Collector,
    CollectorMetadata,
    CollectorRegistry,
    ExecutionStatus,
    FindingCandidate,
    RawObservation,
    implementation_identifier,
    metadata_for,
)
from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.evidence import EvidenceVault
from osint_lab.orchestrator.audit import AuditEntry, AuditEventType, AuditLog, verify_audit_log
from osint_lab.orchestrator.authorization import AuthorizationDecision, RunAuthorization
from osint_lab.orchestrator.authorization_store import AuthorizationStore
from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus, initial_status


NOW = datetime(2026, 9, 19, 10, 0, tzinfo=timezone.utc)
RISKY_CLASSES = frozenset({
    SourceClass.THIRD_PARTY_API,
    SourceClass.TOR,
    SourceClass.DIRECT_TARGET,
})


class SyntheticLocalCollector(Collector):
    agent_name = "synthetic-local-fixture"
    agent_type = "SyntheticLocalCollector"
    source_class = SourceClass.LOCAL
    version = "1.0"

    def __init__(self, *, fail=False, promote_confirmed=False):
        self.fail = fail
        self.promote_confirmed = promote_confirmed
        self.run_count = 0
        super().__init__()

    def validate_input(self, seed_reference: str) -> None:
        if not seed_reference.startswith("seed-ref:"):
            raise ValueError("synthetic seed reference required")

    def _run(self, context, seed_reference: str) -> tuple[RawObservation, ...]:
        self.run_count += 1
        if self.fail:
            raise RuntimeError("synthetic failure payload must not be logged")
        return (
            RawObservation(
                raw_status="FOUND",
                value_reference=seed_reference,
                evidence_ref="ev-synthetic",
                notes="Synthetic observation only.",
            ),
        )

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        status = FindingStatus.CONFIRMED if self.promote_confirmed else initial_status(observation.raw_status)
        return FindingCandidate(
            raw_status=observation.raw_status,
            normalized_status=status,
            value_reference=observation.value_reference,
            evidence_ref=observation.evidence_ref,
            notes="Synthetic candidate only.",
        )

    def describe_capabilities(self):
        return {"synthetic": True, "network": False}


class SyntheticPolicyCollector(SyntheticLocalCollector):
    agent_name = "synthetic-policy-fixture"
    agent_type = "SyntheticPolicyCollector"

    def __init__(self, source_class, **kwargs):
        self.source_class = source_class
        super().__init__(**kwargs)


def manifest_for(collector, **changes):
    source_class = collector.source_class
    values = dict(
        case_id="case-run-001",
        case_name="Synthetic execution fixture",
        created_at=NOW - timedelta(days=1),
        authorized_by="fixture-owner",
        purpose="Synthetic orchestrator tests",
        legal_basis_or_consent_note="Synthetic data only.",
        seed_entities=(SeedEntity(entity_type="REFERENCE", value="seed-ref:synthetic"),),
        allowed_source_classes=frozenset({source_class}),
        forbidden_source_classes=RISKY_CLASSES - {source_class},
        allowed_agent_types=frozenset({collector.agent_type}),
        third_party_api_allowed=source_class is SourceClass.THIRD_PARTY_API,
        tor_allowed=source_class is SourceClass.TOR,
        direct_target_allowed=source_class is SourceClass.DIRECT_TARGET,
        retention_days=7,
        status=CaseStatus.ACTIVE,
    )
    values.update(changes)
    return CaseManifest(**values)


def authorization_for(collector, **changes):
    values = dict(
        authorization_id="auth-001",
        case_id="case-run-001",
        requested_agent=collector.agent_name,
        requested_source_class=collector.source_class,
        requested_at=NOW - timedelta(minutes=5),
        requested_by="fixture-requester",
        purpose="Synthetic orchestrator tests",
        decision=AuthorizationDecision.APPROVED,
        decision_at=NOW - timedelta(minutes=4),
        approved_by="fixture-reviewer",
        expires_at=NOW + timedelta(minutes=30),
        scope="single synthetic run",
        notes="No real collection.",
    )
    values.update(changes)
    return RunAuthorization(**values)


def setup_orchestrator(tmp_path, collector):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    audit = AuditLog(repo_root=repo, root=tmp_path / "private-audit")
    store = AuthorizationStore(repo_root=repo, root=tmp_path / "private-authorizations")
    registry = CollectorRegistry()
    registry.register(collector, metadata_for(collector, network_required=False, provenance="synthetic:test"))
    vault = EvidenceVault(repo_root=repo, root=tmp_path / "private-vault")
    return Orchestrator(
        audit_log=audit,
        authorization_store=store,
        collector_registry=registry,
        evidence_vault=vault,
        clock=lambda: NOW,
    ), audit, repo


def execute(orchestrator, case_manifest, collector, run_authorization=None):
    authorization_id = None
    if run_authorization is not None:
        orchestrator._authorization_store.save(run_authorization)
        authorization_id = run_authorization.authorization_id
    return orchestrator.execute(
        manifest=case_manifest,
        collector=collector,
        seed_reference="seed-ref:synthetic",
        purpose="Synthetic orchestrator tests",
        requested_by="fixture-requester",
        authorization_id=authorization_id,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"requested_at": datetime.now()},
        {"requested_agent": "*"},
        {"scope": "*"},
        {"approved_by": None},
        {"expires_at": NOW - timedelta(minutes=5)},
    ],
)
def test_run_authorization_rejects_invalid_or_global_values(changes):
    with pytest.raises(ValueError):
        authorization_for(SyntheticPolicyCollector(SourceClass.THIRD_PARTY_API), **changes)


def test_local_collector_runs_only_when_case_allows_it(tmp_path):
    collector = SyntheticLocalCollector()
    orchestrator, audit, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, manifest_for(collector), collector)

    assert result.status is ExecutionStatus.SUCCESS
    assert collector.run_count == 1
    assert result.finding_candidates[0].normalized_status is FindingStatus.POSSIBLE
    assert [entry["event_type"] for entry in audit.read("case-run-001")] == [
        "RUN_REQUESTED",
        "POLICY_EVALUATED",
        "AUTHORIZATION_CHECKED",
        "RUN_ALLOWED",
        "AGENT_STARTED",
        "AGENT_FINISHED",
    ]

    denied_collector = SyntheticLocalCollector()
    passive_manifest = manifest_for(
        SyntheticPolicyCollector(SourceClass.PASSIVE_WEB),
        allowed_agent_types=frozenset({denied_collector.agent_type}),
    )
    denied = execute(orchestrator, passive_manifest, denied_collector)
    assert denied.status is ExecutionStatus.DENIED
    assert denied_collector.run_count == 0


def test_allowed_passive_web_runs_without_per_run_authorization(tmp_path):
    collector = SyntheticPolicyCollector(SourceClass.PASSIVE_WEB)
    orchestrator, audit, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, manifest_for(collector), collector)
    assert result.status is ExecutionStatus.SUCCESS
    assert collector.run_count == 1
    checks = [entry for entry in audit.read("case-run-001") if entry["event_type"] == "AUTHORIZATION_CHECKED"]
    assert checks[-1]["decision"] == "NOT_REQUIRED"


@pytest.mark.parametrize(
    "source_class",
    [SourceClass.THIRD_PARTY_API, SourceClass.TOR, SourceClass.DIRECT_TARGET],
)
def test_risky_source_without_run_authorization_is_denied(tmp_path, source_class):
    collector = SyntheticPolicyCollector(source_class)
    orchestrator, audit, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, manifest_for(collector), collector)

    assert result.status is ExecutionStatus.DENIED
    assert collector.run_count == 0
    assert audit.read("case-run-001")[-1]["event_type"] == "RUN_DENIED"


def test_valid_scoped_authorization_allows_risky_synthetic_collector(tmp_path):
    collector = SyntheticPolicyCollector(SourceClass.THIRD_PARTY_API)
    orchestrator, audit, _ = setup_orchestrator(tmp_path, collector)
    approval = authorization_for(collector)
    result = execute(orchestrator, manifest_for(collector), collector, approval)

    assert result.status is ExecutionStatus.SUCCESS
    assert collector.run_count == 1
    checked = [entry for entry in audit.read("case-run-001") if entry["event_type"] == "AUTHORIZATION_CHECKED"]
    assert checked[-1]["decision"] == "APPROVED"
    assert checked[-1]["authorization_id"] == "auth-001"


@pytest.mark.parametrize(
    "changes",
    [
        {"decision": AuthorizationDecision.REVOKED},
        {
            "requested_at": NOW - timedelta(minutes=30),
            "decision_at": NOW - timedelta(minutes=20),
            "expires_at": NOW - timedelta(minutes=1),
        },
        {"case_id": "case-other"},
        {"requested_agent": "other-agent"},
        {"requested_source_class": SourceClass.TOR},
    ],
)
def test_invalid_or_mismatched_authorization_is_denied(tmp_path, changes):
    collector = SyntheticPolicyCollector(SourceClass.THIRD_PARTY_API)
    orchestrator, audit, _ = setup_orchestrator(tmp_path, collector)
    result = execute(
        orchestrator,
        manifest_for(collector),
        collector,
        authorization_for(collector, **changes),
    )
    assert result.status is ExecutionStatus.DENIED
    assert collector.run_count == 0
    assert audit.read("case-run-001")[-1]["event_type"] == "RUN_DENIED"


def test_collector_failure_is_safely_recorded(tmp_path):
    collector = SyntheticLocalCollector(fail=True)
    orchestrator, audit, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, manifest_for(collector), collector)

    assert result.status is ExecutionStatus.FAILED
    assert collector.run_count == 1
    assert result.errors == ("RuntimeError: collector execution failed",)
    entries = audit.read("case-run-001")
    assert entries[-1]["event_type"] == "AGENT_FAILED"
    assert "synthetic failure payload" not in str(entries)


def test_collector_cannot_promote_candidate_to_confirmed(tmp_path):
    collector = SyntheticLocalCollector(promote_confirmed=True)
    orchestrator, audit, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, manifest_for(collector), collector)

    assert result.status is ExecutionStatus.FAILED
    assert result.finding_candidates == ()
    assert audit.read("case-run-001")[-1]["event_type"] == "AGENT_FAILED"


def test_public_collector_api_has_no_policy_bypass():
    collector = SyntheticLocalCollector()
    with pytest.raises(PermissionError, match="orchestrator-issued"):
        collector.run(object(), "seed-ref:synthetic")
    with pytest.raises(TypeError, match="only be created"):
        ExecutionContext(
            case_id="case-run-001",
            execution_id="run-manual",
            authorization_id=None,
            agent_name=collector.agent_name,
            source_class=collector.source_class,
            started_at=NOW,
            purpose="manual bypass",
            seed_reference="seed-ref:synthetic",
        )
    with pytest.raises(TypeError, match="must not override"):
        class BypassCollector(SyntheticLocalCollector):
            def run(self, context, seed_reference):
                return ()


def test_audit_log_appends_and_omits_raw_request_values(tmp_path):
    collector = SyntheticLocalCollector()
    orchestrator, audit, repo = setup_orchestrator(tmp_path, collector)
    execute(orchestrator, manifest_for(collector), collector)

    audit_path = audit.root / "case-run-001" / "audit.jsonl"
    first_bytes = audit_path.read_bytes()
    execute(orchestrator, manifest_for(SyntheticLocalCollector()), SyntheticLocalCollector())
    second_bytes = audit_path.read_bytes()
    assert second_bytes.startswith(first_bytes)
    assert len(second_bytes) > len(first_bytes)
    assert repo not in audit_path.parents
    assert b"seed-ref:synthetic" not in second_bytes
    assert b"fixture-requester" not in second_bytes
    assert b"Synthetic orchestrator tests" not in second_bytes


def test_audit_entry_rejects_secret_like_metadata(tmp_path):
    _, audit, _ = setup_orchestrator(tmp_path, SyntheticLocalCollector())
    with pytest.raises(ValueError, match="secret-like"):
        audit.append(AuditEntry(
            audit_id="audit-test",
            case_id="case-run-001",
            execution_id="run-test",
            authorization_id=None,
            agent_name="synthetic-local-fixture",
            source_class=SourceClass.LOCAL,
            event_type=AuditEventType.RUN_REQUESTED,
            decision="PENDING",
            timestamp=NOW,
            message="Synthetic event.",
            metadata={"api_key": "must-not-be-logged"},
        ))


def test_durable_authorization_reload_expiry_and_revocation(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    root = tmp_path / "private-authorizations"
    collector = SyntheticPolicyCollector(SourceClass.THIRD_PARTY_API)
    approval = authorization_for(collector)
    AuthorizationStore(repo_root=repo, root=root).save(approval)

    reloaded_store = AuthorizationStore(repo_root=repo, root=root)
    reloaded = reloaded_store.load(approval.case_id, approval.authorization_id)
    assert reloaded == approval
    assert reloaded.check(
        case_id=approval.case_id,
        agent_name=collector.agent_name,
        source_class=collector.source_class,
        at=approval.expires_at,
    ).valid is False

    revoked = authorization_for(
        collector,
        decision=AuthorizationDecision.REVOKED,
        decision_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=31),
        approved_by="fixture-reviewer",
        notes="Revoked synthetic authorization.",
    )
    reloaded_store.save(revoked)
    latest = AuthorizationStore(repo_root=repo, root=root).load(approval.case_id, approval.authorization_id)
    assert latest.decision is AuthorizationDecision.REVOKED
    assert latest.check(
        case_id=approval.case_id,
        agent_name=collector.agent_name,
        source_class=collector.source_class,
        at=NOW + timedelta(minutes=2),
    ).valid is False
    assert len(reloaded_store.history(approval.case_id, approval.authorization_id)) == 2
    with pytest.raises(FileNotFoundError):
        reloaded_store.load("case-other", approval.authorization_id)


def _append_three_audit_entries(audit):
    for index in range(3):
        audit.append(AuditEntry(
            audit_id=f"audit-{index}",
            case_id="case-audit-001",
            execution_id="run-audit-001",
            authorization_id=None,
            agent_name="synthetic-local-fixture",
            source_class=SourceClass.LOCAL,
            event_type=AuditEventType.RUN_REQUESTED,
            decision="PENDING",
            timestamp=NOW + timedelta(seconds=index),
            message=f"Synthetic event {index}.",
            metadata={"index": index},
        ))


def test_audit_hash_chain_is_valid_and_exposes_head(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    audit = AuditLog(repo_root=repo, root=tmp_path / "private-audit")
    _append_three_audit_entries(audit)
    verification = verify_audit_log(audit, "case-audit-001")
    assert verification.valid is True
    assert verification.entry_count == 3
    assert verification.head_hash == audit.read("case-audit-001")[-1]["entry_hash"]


@pytest.mark.parametrize("damage", ["modify", "delete", "reorder", "hash"])
def test_audit_hash_chain_detects_modification_deletion_and_reordering(tmp_path, damage):
    repo = tmp_path / "repo"
    repo.mkdir()
    audit = AuditLog(repo_root=repo, root=tmp_path / "private-audit")
    _append_three_audit_entries(audit)
    path = audit.root / "case-audit-001" / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    if damage == "modify":
        record = json.loads(lines[1])
        record["message"] = "Changed old entry."
        lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    elif damage == "delete":
        del lines[1]
    elif damage == "reorder":
        lines[0], lines[1] = lines[1], lines[0]
    else:
        record = json.loads(lines[1])
        record["entry_hash"] = "f" * 64
        lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_audit_log(audit, "case-audit-001").valid is False


def test_registry_denies_unregistered_duplicate_and_mismatched_collectors(tmp_path):
    collector = SyntheticLocalCollector()
    registry = CollectorRegistry()
    with pytest.raises(PermissionError, match="not registered"):
        registry.validate(collector)

    metadata = metadata_for(collector, network_required=False, provenance="synthetic:test")
    registry.register(collector, metadata)
    with pytest.raises(ValueError, match="duplicate"):
        registry.register(collector, metadata)

    mismatched = CollectorRegistry()
    with pytest.raises(ValueError, match="does not match"):
        mismatched.register(collector, CollectorMetadata(
            agent_name=collector.agent_name,
            agent_type=collector.agent_type,
            version="2.0",
            source_class=collector.source_class,
            capabilities=collector.describe_capabilities(),
            network_required=False,
            provenance="synthetic:test",
            implementation_identifier=implementation_identifier(collector),
        ))
    with pytest.raises(ValueError, match="source_class"):
        CollectorMetadata(
            agent_name=collector.agent_name,
            agent_type=collector.agent_type,
            version=collector.version,
            source_class="UNKNOWN",
            capabilities=collector.describe_capabilities(),
            network_required=False,
            provenance="synthetic:test",
            implementation_identifier=implementation_identifier(collector),
        )
    with pytest.raises(ValueError, match="CollectorMetadata"):
        CollectorRegistry().register(collector, None)


def test_registry_detects_implementation_substitution():
    collector = SyntheticLocalCollector()
    registry = CollectorRegistry()
    registry.register(collector, metadata_for(collector, network_required=False, provenance="synthetic:test"))

    class ReplacementCollector(SyntheticLocalCollector):
        agent_name = collector.agent_name

    with pytest.raises(PermissionError, match="substituted"):
        registry.validate(ReplacementCollector())


def test_unregistered_collector_is_not_executed(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    collector = SyntheticLocalCollector()
    orchestrator = Orchestrator(
        audit_log=AuditLog(repo_root=repo, root=tmp_path / "private-audit"),
        authorization_store=AuthorizationStore(repo_root=repo, root=tmp_path / "private-authorizations"),
        collector_registry=CollectorRegistry(),
        evidence_vault=EvidenceVault(repo_root=repo, root=tmp_path / "private-vault"),
        clock=lambda: NOW,
    )
    with pytest.raises(PermissionError, match="not registered"):
        execute(orchestrator, manifest_for(collector), collector)
    assert collector.run_count == 0


def test_success_saves_evidence_and_correct_execution_receipt(tmp_path):
    collector = SyntheticLocalCollector()
    orchestrator, audit, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, manifest_for(collector), collector)
    assert result.status is ExecutionStatus.SUCCESS
    assert result.receipt is not None
    assert result.receipt.execution_id == result.execution_id
    assert result.receipt.collector == collector.agent_name
    assert result.receipt.collector_version == collector.version
    assert result.receipt.source_class is SourceClass.LOCAL
    assert result.receipt.authorization_id is None
    assert result.receipt.observation_count == 1
    assert result.receipt.audit_head_hash == verify_audit_log(audit, "case-run-001").head_hash

    raw_directories = list((tmp_path / "private-vault" / "case-run-001" / "raw").glob("ev-*"))
    receipt_directories = list((tmp_path / "private-vault" / "case-run-001" / "reports").glob("ev-*"))
    assert len(raw_directories) == 1
    assert len(receipt_directories) == 1
    raw_record = json.loads(next(raw_directories[0].glob("run-*.json")).read_text(encoding="utf-8"))
    assert raw_record["execution_metadata"]["execution_id"] == result.execution_id
    assert len(raw_record["raw_observations"]) == 1
    assert len(raw_record["normalized_candidates"]) == 1
    metadata = json.loads((raw_directories[0] / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["execution_id"] == result.execution_id
    assert metadata["collector_version"] == collector.version
    assert metadata["sha256"]
    assert result.receipt.evidence_refs == (metadata["evidence_id"],)


def test_audit_failure_is_fail_closed_before_collector_execution(tmp_path, monkeypatch):
    collector = SyntheticLocalCollector()
    orchestrator, audit, _ = setup_orchestrator(tmp_path, collector)
    monkeypatch.setattr(audit, "append", lambda entry: (_ for _ in ()).throw(OSError("audit unavailable")))
    with pytest.raises(OSError, match="audit unavailable"):
        execute(orchestrator, manifest_for(collector), collector)
    assert collector.run_count == 0


def test_vault_failure_is_fail_closed_and_never_returns_success(tmp_path, monkeypatch):
    collector = SyntheticLocalCollector()
    orchestrator, audit, _ = setup_orchestrator(tmp_path, collector)
    monkeypatch.setattr(
        orchestrator._evidence_vault,
        "store_bytes",
        lambda **kwargs: (_ for _ in ()).throw(OSError("vault unavailable")),
    )
    result = execute(orchestrator, manifest_for(collector), collector)
    assert collector.run_count == 1
    assert result.status is ExecutionStatus.FAILED
    assert result.receipt is None
    assert result.observations == ()
    assert "required Evidence Vault write failed" in result.errors[0]
    assert audit.read("case-run-001")[-1]["event_type"] == "AGENT_FAILED"
