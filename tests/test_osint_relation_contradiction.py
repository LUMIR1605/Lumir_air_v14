from datetime import datetime, timezone

import pytest

from osint_lab.correlation import (
    NodeType,
    Relation,
    RelationGraph,
    RelationNode,
    RelationStatus,
    RelationType,
)
from osint_lab.verification import (
    ContradictionAssertion,
    ContradictionSeverity,
    detect_contradictions,
)


def node(node_id, value="sample_name", **changes):
    values = dict(
        node_id=node_id,
        case_id="case-graph-001",
        node_type=NodeType.USERNAME,
        value=value,
        created_at=datetime.now(timezone.utc),
    )
    values.update(changes)
    return RelationNode(**values)


def relation(**changes):
    values = dict(
        relation_id="relation-001",
        case_id="case-graph-001",
        source_node="node-001",
        target_node="node-002",
        relation_type=RelationType.POSSIBLE_MATCH,
        confidence=None,
        status=RelationStatus.PROPOSED,
        evidence_refs=("ev-001",),
        created_at=datetime.now(timezone.utc),
    )
    values.update(changes)
    return Relation(**values)


def assertion(assertion_id, attribute, value, evidence_ref, **changes):
    values = dict(
        assertion_id=assertion_id,
        case_id="case-graph-001",
        subject_id="profile:sample_name",
        attribute=attribute,
        value=value,
        source_name="offline-fixture",
        evidence_ref=evidence_ref,
        collected_at=datetime.now(timezone.utc),
    )
    values.update(changes)
    return ContradictionAssertion(**values)


def test_relation_graph_declares_required_node_and_relation_types():
    assert {item.value for item in NodeType} == {
        "PERSON", "EMAIL", "PHONE", "USERNAME", "DOMAIN", "WEBSITE", "COMPANY",
        "DOCUMENT", "IMAGE", "SOCIAL_PROFILE", "IP", "LOCATION", "OTHER",
    }
    assert {item.value for item in RelationType} == {
        "OWNS", "USES", "ASSOCIATED_WITH", "MENTIONS", "HOSTED_ON", "REGISTERED_TO",
        "LINKS_TO", "SAME_IDENTIFIER", "POSSIBLE_MATCH", "CONTRADICTS", "DERIVED_FROM",
    }


def test_graph_keeps_matching_identifiers_as_separate_nodes_without_auto_merge():
    graph = RelationGraph("case-graph-001")
    graph.add_node(node("node-001"))
    graph.add_node(node("node-002"))
    assert len(graph.nodes) == 2
    assert graph.nodes[0].value == graph.nodes[1].value
    assert graph.relations == ()


def test_relation_requires_evidence_valid_types_and_existing_endpoints():
    with pytest.raises(ValueError):
        relation(evidence_refs=())
    with pytest.raises(ValueError):
        relation(confidence=1.1)
    with pytest.raises(ValueError):
        relation(relation_type="POSSIBLE_MATCH")

    graph = RelationGraph("case-graph-001")
    graph.add_node(node("node-001"))
    with pytest.raises(ValueError, match="endpoints"):
        graph.add_relation(relation())
    graph.add_node(node("node-002", value="other_name"))
    graph.add_relation(relation())
    assert graph.relations[0].status is RelationStatus.PROPOSED


def test_graph_rejects_cross_case_nodes_and_relations():
    graph = RelationGraph("case-graph-001")
    with pytest.raises(ValueError, match="another case"):
        graph.add_node(node("node-other", case_id="case-other"))
    graph.add_node(node("node-001"))
    graph.add_node(node("node-002"))
    with pytest.raises(ValueError, match="another case"):
        graph.add_relation(relation(case_id="case-other"))


def test_contradiction_check_returns_none_for_consistent_values():
    result = detect_contradictions([
        assertion("a-1", "name", "Alice", "ev-1"),
        assertion("a-2", "name", "alice", "ev-2"),
    ])
    assert result.severity is ContradictionSeverity.NONE
    assert result.reasons == ()
    assert result.evidence_refs == ()


def test_contradiction_check_reports_simple_profile_conflicts():
    result = detect_contradictions([
        assertion("a-1", "name", "Alice", "ev-1"),
        assertion("a-2", "name", "Bob", "ev-2"),
        assertion("a-3", "location", "Warsaw", "ev-3"),
        assertion("a-4", "location", "Gdansk", "ev-4"),
    ])
    assert result.severity is ContradictionSeverity.MEDIUM
    assert len(result.reasons) == 2
    assert result.evidence_refs == ("ev-1", "ev-2", "ev-3", "ev-4")


def test_identifier_conflict_is_high_and_found_not_found_is_medium():
    identifier_result = detect_contradictions([
        assertion("a-1", "identifier", "id-001", "ev-1"),
        assertion("a-2", "identifier", "id-002", "ev-2"),
    ])
    status_result = detect_contradictions([
        assertion("a-3", "raw_status", "FOUND", "ev-3"),
        assertion("a-4", "raw_status", "NOT_FOUND", "ev-4"),
    ])
    assert identifier_result.severity is ContradictionSeverity.HIGH
    assert status_result.severity is ContradictionSeverity.MEDIUM
