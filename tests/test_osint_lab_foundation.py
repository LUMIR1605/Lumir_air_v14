from datetime import datetime, timezone

import pytest

from osint_lab.agents.base import Agent, Observation
from osint_lab.policies import SourceClass, SourcePolicy
from osint_lab.schemas import Finding, FindingStatus, initial_status


def finding(**changes):
    values = dict(
        case_id="synthetic-case", entity_type="username", value="sample_name",
        relation="unverified-match", source_name="offline-fixture", source_url=None,
        source_class=SourceClass.LOCAL, collection_method="fixture",
        collected_at=datetime.now(timezone.utc), raw_status="FOUND",
        normalized_status=FindingStatus.POSSIBLE, confidence=None,
        evidence_ref=None, artifact_hash=None, notes="Synthetic data only.",
    )
    values.update(changes)
    return Finding(**values)


def test_statuses_and_source_classes_are_exact():
    assert {s.value for s in FindingStatus} == {
        "CONFIRMED", "PROBABLE", "POSSIBLE", "UNKNOWN", "NOT_FOUND", "FALSE_POSITIVE"
    }
    assert {s.value for s in SourceClass} == {
        "LOCAL", "PASSIVE_WEB", "THIRD_PARTY_API", "TOR", "DIRECT_TARGET"
    }
    assert SourcePolicy().permits(SourceClass.LOCAL)
    assert not SourcePolicy().permits(SourceClass.DIRECT_TARGET)
    with pytest.raises(ValueError):
        SourcePolicy(frozenset({"LOCAL"}))


def test_finding_requires_provenance_and_valid_types():
    assert finding().case_id == "synthetic-case"
    with pytest.raises(ValueError):
        finding(source_class="LOCAL")
    with pytest.raises(ValueError):
        finding(normalized_status="POSSIBLE")
    with pytest.raises(ValueError):
        finding(collected_at=datetime.now())
    with pytest.raises(ValueError):
        finding(artifact_hash="bad")
    with pytest.raises(ValueError):
        finding(confidence=1.1)


def test_found_is_never_automatically_confirmed():
    assert initial_status("FOUND") is FindingStatus.POSSIBLE
    assert initial_status("timeout") is FindingStatus.UNKNOWN
    with pytest.raises(ValueError, match="independent verification"):
        finding(normalized_status=FindingStatus.CONFIRMED)


def test_agent_contract_requires_name_class_and_collect():
    class FixtureAgent(Agent):
        name = "fixture"
        source_class = SourceClass.LOCAL

        def collect(self, seed: str) -> list[Observation]:
            return [Observation("FOUND")]

    assert FixtureAgent().collect("synthetic")[0].raw_status == "FOUND"

    class MissingCollect(Agent):
        name = "fixture"
        source_class = SourceClass.LOCAL

    with pytest.raises(TypeError):
        MissingCollect()

    class MissingClass(FixtureAgent):
        source_class = "LOCAL"

    with pytest.raises(ValueError):
        MissingClass()
