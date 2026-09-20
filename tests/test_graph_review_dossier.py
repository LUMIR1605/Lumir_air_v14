from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from osint_lab.graph import (
    CorrelationPath,
    EntityNode,
    EntityRelation,
    GraphAdversarialVerifier,
    GraphEntityType,
    GraphPivot,
    GraphRelationType,
    GraphStatus,
    GraphStore,
    IdentityCandidate,
    IdentityStatus,
    ReviewerDecisionEvent,
    ReviewDecisionValue,
    ReviewTarget,
    build_dossier,
    deterministic_entity_id,
    deterministic_relation_id,
    score_benchmark,
)
from osint_lab.orchestrator.audit import AuditLog, verify_audit_log


NOW = datetime(2026, 9, 20, 17, 0, tzinfo=timezone.utc)
CASE = "review-case-001"


def setup(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    audit = AuditLog(repo_root=repo, root=tmp_path / "audit")
    graph = GraphStore(repo_root=repo, case_root=tmp_path / "cases", case_id=CASE, audit_log=audit)
    return graph, audit


def node(value):
    entity_id = deterministic_entity_id(CASE, GraphEntityType.DOMAIN, value)
    return EntityNode(
        entity_id=entity_id, case_id=CASE, entity_type=GraphEntityType.DOMAIN,
        canonical_value=value, display_value=value, aliases=(value,), first_seen=NOW, last_seen=NOW,
        created_at=NOW, updated_at=NOW, source_refs=("fixture",), evidence_refs=("ev-review",),
        confidence=0.8, status=GraphStatus.POSSIBLE,
    )


def test_review_decisions_are_append_only_preserve_previous_and_update_relation(tmp_path):
    graph, audit = setup(tmp_path)
    left, right = node("left.test"), node("right.test")
    relation_id = deterministic_relation_id(CASE, left.entity_id, right.entity_id,
                                            GraphRelationType.ASSOCIATED_WITH)
    edge = EntityRelation(
        relation_id=relation_id, case_id=CASE, source_entity_id=left.entity_id,
        target_entity_id=right.entity_id, relation_type=GraphRelationType.ASSOCIATED_WITH,
        first_seen=NOW, last_seen=NOW, evidence_refs=("ev-review",), source_refs=("fixture",),
        independence_groups=("independent-a",), confidence=0.75, status=GraphStatus.POSSIBLE,
        reasons=("synthetic relation",),
    )
    graph.add_batch(entities=(left, right), relations=(edge,))
    sensitive_note = "Private.Person@example.test must not enter audit"
    first = ReviewerDecisionEvent(
        decision_id="decision-confirm", case_id=CASE, reviewer="analyst-fixture", timestamp=NOW,
        target_type=ReviewTarget.RELATION, target_id=relation_id, decision=ReviewDecisionValue.CONFIRM,
        notes=sensitive_note, evidence_refs=("ev-review",),
    )
    graph.append_decision(first)
    second = ReviewerDecisionEvent(
        decision_id="decision-reject", case_id=CASE, reviewer="analyst-fixture", timestamp=NOW,
        target_type=ReviewTarget.RELATION, target_id=relation_id, decision=ReviewDecisionValue.REJECT,
        notes="newer synthetic review", evidence_refs=("ev-review",), previous_decision_ref=first.decision_id,
    )
    graph.append_decision(second)
    assert [item.decision_id for item in graph.decisions()] == ["decision-confirm", "decision-reject"]
    assert graph.snapshot()["edges"][0]["status"] == "REJECTED"
    assert verify_audit_log(audit, CASE).valid
    audit_text = (audit.root / CASE / "audit.jsonl").read_text(encoding="utf-8")
    assert "decision-confirm" in audit_text and "decision-reject" in audit_text
    assert sensitive_note not in audit_text and "Private.Person" not in audit_text


def test_identity_verified_is_impossible_without_reviewer_decision():
    with pytest.raises(ValueError, match="ReviewerDecision"):
        IdentityCandidate(identity_candidate_id="identity-test", entity_ids=("a", "b"),
                          supporting_paths=("path-a",), opposing_paths=(), confidence=0.8,
                          status=IdentityStatus.VERIFIED, reasons=("fixture",),
                          unresolved_questions=("fixture question",))


def test_identity_review_effect_is_durable_without_erasing_evidence(tmp_path):
    graph, _ = setup(tmp_path)
    decision = ReviewerDecisionEvent(
        decision_id="decision-identity", case_id=CASE, reviewer="analyst-fixture", timestamp=NOW,
        target_type=ReviewTarget.IDENTITY_CANDIDATE, target_id="identity-candidate-a",
        decision=ReviewDecisionValue.CONFIRM, notes="Synthetic review",
        evidence_refs=("ev-review",),
    )
    graph.append_decision(decision)
    snapshot = graph.snapshot()
    assert snapshot["review_effects"] == [{
        "target_type": "IDENTITY_CANDIDATE", "target_id": "identity-candidate-a",
        "status": "VERIFIED", "decision_id": "decision-identity",
    }]
    assert snapshot["reviewer_decisions"][0]["evidence_refs"] == ["ev-review"]


def path(*, groups=("group-a",), relations=("rel-a",), entities=("ent-a", "ent-b")):
    return CorrelationPath(path_id="path-a", entity_sequence=entities, relation_sequence=relations,
                           evidence_refs=("ev-a",), confidence=0.7, explanation="A -> B",
                           reasons=("weakest link confidence: 0.7",), independent_groups=groups)


def test_adversarial_graph_review_covers_copy_username_stale_contradiction_and_independence():
    snapshots = [
        ({"nodes": [{"entity_id": "ent-a", "entity_type": "DOMAIN"},
                     {"entity_id": "ent-b", "entity_type": "DOMAIN"}],
          "edges": [{"relation_id": "rel-a", "source_entity_id": "ent-a", "target_entity_id": "ent-b",
                     "relation_type": "REFERENCES", "status": "POSSIBLE", "attributes": {}}]}, path()),
        ({"nodes": [{"entity_id": "ent-a", "entity_type": "USERNAME"},
                     {"entity_id": "ent-b", "entity_type": "WEBSITE"}],
          "edges": [{"relation_id": "rel-a", "source_entity_id": "ent-a", "target_entity_id": "ent-b",
                     "relation_type": "LINKS_TO", "status": "POSSIBLE", "attributes": {"stale": True}}]}, path()),
        ({"nodes": [{"entity_id": "ent-a", "entity_type": "DOMAIN"},
                     {"entity_id": "ent-b", "entity_type": "DOMAIN"}],
          "edges": [{"relation_id": "rel-a", "source_entity_id": "ent-a", "target_entity_id": "ent-b",
                     "relation_type": "REFERENCES", "status": "REJECTED", "attributes": {}}]}, path()),
        ({"nodes": [{"entity_id": "ent-a", "entity_type": "DOMAIN"},
                     {"entity_id": "ent-b", "entity_type": "DOMAIN"}],
          "edges": [{"relation_id": "rel-a", "source_entity_id": "ent-a", "target_entity_id": "ent-b",
                     "relation_type": "REFERENCES", "status": "POSSIBLE",
                     "attributes": {"newer_conflict": True}}]}, path()),
    ]
    reviews = [GraphAdversarialVerifier().review(snapshot=snapshot, paths=(candidate,))[0]
               for snapshot, candidate in snapshots]
    assert "insufficient independent evidence" in reviews[0]["challenges"]
    assert {"username collision alternative", "stale-only relation"} <= set(reviews[1]["challenges"])
    assert reviews[2]["result"] == "WEAKENED"
    assert "contradictory newer source" in reviews[3]["challenges"]
    survives = GraphAdversarialVerifier().review(snapshot=snapshots[0][0],
                                                 paths=(path(groups=("first-party", "registry")),))[0]
    assert survives["result"] == "SURVIVES"


def test_dossier_separates_layers_and_professional_failure_state():
    snapshot = {"case_id": CASE, "graph_version": 1, "nodes": [], "edges": [], "timeline": [],
                "reviewer_decisions": []}
    intelligence = {
        "open_hypotheses": [{"statement": "Synthetic hypothesis", "status": "OPEN"}],
        "contradictions": [], "evidence_quality": [], "unresolved_questions": ["What remains unknown?"],
    }
    pivot = GraphPivot(pivot_id="pivot-a", case_id=CASE, source_entity_id="ent-a",
                       proposed_enricher="domain_dns", proposed_input="example.test",
                       expected_information_gain=0.7, privacy_cost=0.2, network_cost=0.6,
                       duplication_risk=0.1, graph_value=0.8, reason="synthetic", status="PROPOSED",
                       execution_fingerprint="f" * 64, hop=1)
    dossier = build_dossier(snapshot=snapshot, seeds=({"entity_type": "DOMAIN", "value": "example.test"},),
                            paths=(), intelligence=intelligence, pivots=(pivot,)).to_dict()
    assert {"key_entities", "key_relations", "important_paths", "hypotheses", "verified_findings",
            "rejected_findings", "contradictions", "timeline", "evidence_quality",
            "unresolved_questions", "recommended_pivots", "reviewer_decisions"} <= dossier.keys()
    assert "NO_VERIFIED_DATA" in dossier["case_summary"]["failure_states"]


def test_synthetic_benchmark_arena_and_metrics_are_deterministic():
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "osint_lab"
    fixtures = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(root.glob("*.json"))]
    assert len(fixtures) == 20 and all(item["synthetic"] is True for item in fixtures)
    expected = ({"id": "relation:a", "label": "TRUE"}, {"id": "hypothesis:b", "label": "UNKNOWN"})
    predicted = ({"id": "relation:a", "label": "TRUE", "independence_group": "g1"},
                 {"id": "hypothesis:b", "label": "UNKNOWN"})
    metrics = score_benchmark(predicted=predicted, expected=expected, pivot_count=2, useful_pivots=1)
    assert metrics.precision == 1.0
    assert metrics.pivot_efficiency == 0.5
