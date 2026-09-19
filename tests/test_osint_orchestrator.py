from datetime import datetime, timedelta, timezone

import pytest

from osint_lab.agents import Collector, ExecutionStatus, FindingCandidate, RawObservation
from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.orchestrator.audit import AuditEntry, AuditEventType, AuditLog
from osint_lab.orchestrator.authorization import AuthorizationDecision, RunAuthorization
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


def setup_orchestrator(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    audit = AuditLog(repo_root=repo, root=tmp_path / "private-audit")
    return Orchestrator(audit_log=audit, clock=lambda: NOW), audit, repo


def execute(orchestrator, case_manifest, collector, run_authorization=None):
    return orchestrator.execute(
        manifest=case_manifest,
        collector=collector,
        seed_reference="seed-ref:synthetic",
        purpose="Synthetic orchestrator tests",
        requested_by="fixture-requester",
        authorization=run_authorization,
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
    orchestrator, audit, _ = setup_orchestrator(tmp_path)
    collector = SyntheticLocalCollector()
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
    orchestrator, audit, _ = setup_orchestrator(tmp_path)
    collector = SyntheticPolicyCollector(SourceClass.PASSIVE_WEB)
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
    orchestrator, audit, _ = setup_orchestrator(tmp_path)
    collector = SyntheticPolicyCollector(source_class)
    result = execute(orchestrator, manifest_for(collector), collector)

    assert result.status is ExecutionStatus.DENIED
    assert collector.run_count == 0
    assert audit.read("case-run-001")[-1]["event_type"] == "RUN_DENIED"


def test_valid_scoped_authorization_allows_risky_synthetic_collector(tmp_path):
    orchestrator, audit, _ = setup_orchestrator(tmp_path)
    collector = SyntheticPolicyCollector(SourceClass.THIRD_PARTY_API)
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
    orchestrator, audit, _ = setup_orchestrator(tmp_path)
    collector = SyntheticPolicyCollector(SourceClass.THIRD_PARTY_API)
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
    orchestrator, audit, _ = setup_orchestrator(tmp_path)
    collector = SyntheticLocalCollector(fail=True)
    result = execute(orchestrator, manifest_for(collector), collector)

    assert result.status is ExecutionStatus.FAILED
    assert collector.run_count == 1
    assert result.errors == ("RuntimeError: collector execution failed",)
    entries = audit.read("case-run-001")
    assert entries[-1]["event_type"] == "AGENT_FAILED"
    assert "synthetic failure payload" not in str(entries)


def test_collector_cannot_promote_candidate_to_confirmed(tmp_path):
    orchestrator, audit, _ = setup_orchestrator(tmp_path)
    collector = SyntheticLocalCollector(promote_confirmed=True)
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
    orchestrator, audit, repo = setup_orchestrator(tmp_path)
    execute(orchestrator, manifest_for(SyntheticLocalCollector()), SyntheticLocalCollector())

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
    _, audit, _ = setup_orchestrator(tmp_path)
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
