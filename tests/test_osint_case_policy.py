from datetime import datetime, timezone

import pytest

from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.policies import SourceClass
from osint_lab.policies.gate import PolicyDecision, PolicyGate


def manifest(**changes):
    values = dict(
        case_id="case-001",
        case_name="Synthetic fixture",
        created_at=datetime.now(timezone.utc),
        authorized_by="fixture-owner",
        purpose="Local regression test",
        legal_basis_or_consent_note="Synthetic data and explicit test authorization.",
        seed_entities=(SeedEntity(entity_type="USERNAME", value="sample_name"),),
        allowed_source_classes=frozenset({SourceClass.LOCAL}),
        forbidden_source_classes=frozenset({
            SourceClass.THIRD_PARTY_API,
            SourceClass.TOR,
            SourceClass.DIRECT_TARGET,
        }),
        allowed_agent_types=frozenset({"FixtureAgent"}),
        status=CaseStatus.ACTIVE,
    )
    values.update(changes)
    return CaseManifest(**values)


def decision(case_manifest, source_class, agent_type="FixtureAgent"):
    return PolicyGate.decide(
        case_manifest,
        agent_type=agent_type,
        source_class=source_class,
    ).decision


def test_case_manifest_contains_exact_statuses_and_serializes_policy():
    item = manifest()
    assert {status.value for status in CaseStatus} == {
        "DRAFT", "AUTHORIZED", "ACTIVE", "PAUSED", "CLOSED", "ARCHIVED"
    }
    payload = item.to_dict()
    assert payload["case_id"] == "case-001"
    assert payload["seed_entities"] == [{"entity_type": "USERNAME", "value": "sample_name"}]
    assert payload["allowed_source_classes"] == ["LOCAL"]
    assert payload["direct_target_allowed"] is False


@pytest.mark.parametrize(
    "changes",
    [
        {"case_id": "../escape"},
        {"created_at": datetime.now()},
        {"seed_entities": ()},
        {"retention_days": 0},
        {"status": "ACTIVE"},
        {"allowed_source_classes": frozenset({SourceClass.LOCAL, SourceClass.TOR})},
        {
            "allowed_source_classes": frozenset({SourceClass.LOCAL}),
            "forbidden_source_classes": frozenset({SourceClass.LOCAL}),
        },
    ],
)
def test_case_manifest_rejects_invalid_or_inconsistent_values(changes):
    with pytest.raises(ValueError):
        manifest(**changes)


def test_policy_gate_allows_local_and_manifest_allowed_passive_web():
    assert decision(manifest(), SourceClass.LOCAL) is PolicyDecision.ALLOW
    passive = manifest(
        allowed_source_classes=frozenset({SourceClass.LOCAL, SourceClass.PASSIVE_WEB}),
    )
    assert decision(passive, SourceClass.PASSIVE_WEB) is PolicyDecision.ALLOW


def test_risky_source_classes_are_denied_by_default():
    item = manifest()
    assert decision(item, SourceClass.THIRD_PARTY_API) is PolicyDecision.DENY
    assert decision(item, SourceClass.TOR) is PolicyDecision.DENY
    assert decision(item, SourceClass.DIRECT_TARGET) is PolicyDecision.DENY


def test_enabled_risky_source_still_requires_per_run_approval():
    item = manifest(
        allowed_source_classes=frozenset({SourceClass.LOCAL, SourceClass.THIRD_PARTY_API}),
        forbidden_source_classes=frozenset({SourceClass.TOR, SourceClass.DIRECT_TARGET}),
        third_party_api_allowed=True,
    )
    assert decision(item, SourceClass.THIRD_PARTY_API) is PolicyDecision.REQUIRE_EXPLICIT_APPROVAL


def test_policy_gate_denies_inactive_cases_and_unknown_agents():
    assert decision(manifest(status=CaseStatus.PAUSED), SourceClass.LOCAL) is PolicyDecision.DENY
    assert decision(manifest(), SourceClass.LOCAL, agent_type="OtherAgent") is PolicyDecision.DENY
