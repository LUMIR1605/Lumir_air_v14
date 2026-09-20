from datetime import datetime, timedelta, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from osint_lab.graph import (
    EntityNode,
    EntityNormalizer,
    EntityRelation,
    GraphEntityType,
    GraphExporter,
    GraphPathEngine,
    GraphRelationType,
    GraphStatus,
    GraphStore,
    TimelineEvent,
    TimelineEventType,
    detect_circular_provenance,
    deterministic_entity_id,
    deterministic_relation_id,
)


NOW = datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)
CASE = "graph-case-001"


def store(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    return GraphStore(repo_root=repo, case_root=tmp_path / "private", case_id=CASE)


def node(entity_type, value, *, seen=NOW, evidence="ev-1", source="fixture", attributes=None):
    normalized = EntityNormalizer().normalize(entity_type, value)
    return EntityNode(
        entity_id=deterministic_entity_id(CASE, entity_type, normalized.canonical_value), case_id=CASE,
        entity_type=entity_type, canonical_value=normalized.canonical_value, display_value=value,
        aliases=(value,), first_seen=seen, last_seen=seen, created_at=seen, updated_at=seen,
        source_refs=(source,), evidence_refs=(evidence,), confidence=0.8, status=GraphStatus.POSSIBLE,
        attributes=attributes or {},
    )


def relation(left, right, relation_type=GraphRelationType.REFERENCES, *, status=GraphStatus.POSSIBLE,
             evidence="ev-1", group="group-1", confidence=0.8, reviewer=None):
    return EntityRelation(
        relation_id=deterministic_relation_id(CASE, left.entity_id, right.entity_id, relation_type),
        case_id=CASE, source_entity_id=left.entity_id, target_entity_id=right.entity_id,
        relation_type=relation_type, first_seen=NOW, last_seen=NOW, evidence_refs=(evidence,),
        source_refs=("fixture",), independence_groups=(group,), confidence=confidence, status=status,
        reasons=("synthetic evidence-backed relation",), reviewer_decision_id=reviewer,
    )


def test_canonical_domain_dedup_persists_across_reload(tmp_path):
    graph = store(tmp_path)
    first = node(GraphEntityType.DOMAIN, "EXAMPLE.TEST")
    second = node(GraphEntityType.DOMAIN, "example.test", evidence="ev-2")
    assert first.entity_id == second.entity_id
    graph.add_batch(entities=(first, second))
    reopened = GraphStore(repo_root=graph.repo_root, case_root=graph.case_root, case_id=CASE)
    snapshot = reopened.snapshot()
    assert len(snapshot["nodes"]) == 1
    assert snapshot["nodes"][0]["evidence_refs"] == ["ev-1", "ev-2"]


def test_fuzzy_company_names_are_not_auto_merged(tmp_path):
    graph = store(tmp_path)
    full = node(GraphEntityType.COMPANY, "ABC Sp. z o.o.")
    short = node(GraphEntityType.COMPANY, "ABC")
    graph.add_batch(entities=(full, short))
    assert len(graph.snapshot()["nodes"]) == 2


def test_relation_requires_provenance_and_confirmed_requires_review():
    left = node(GraphEntityType.DOMAIN, "left.test")
    right = node(GraphEntityType.DOMAIN, "right.test")
    with pytest.raises(ValueError, match="evidence_refs"):
        EntityRelation(
            relation_id="rel-missing", case_id=CASE, source_entity_id=left.entity_id,
            target_entity_id=right.entity_id, relation_type=GraphRelationType.REFERENCES,
            first_seen=NOW, last_seen=NOW, evidence_refs=(), source_refs=("fixture",),
            independence_groups=("group",), confidence=0.5, status=GraphStatus.POSSIBLE,
            reasons=("fixture",),
        )
    with pytest.raises(ValueError, match="ReviewerDecision"):
        relation(left, right, status=GraphStatus.CONFIRMED)


def test_transaction_rolls_back_entity_when_relation_foreign_key_fails(tmp_path):
    graph = store(tmp_path)
    left = node(GraphEntityType.DOMAIN, "left.test")
    missing = node(GraphEntityType.DOMAIN, "missing.test")
    with pytest.raises(Exception):
        graph.add_batch(entities=(left,), relations=(relation(left, missing),))
    assert graph.snapshot()["nodes"] == []


def test_timeline_retains_first_and_last_seen_history(tmp_path):
    graph = store(tmp_path)
    value = node(GraphEntityType.DOMAIN, "timeline.test")
    later = NOW + timedelta(days=2)
    first = TimelineEvent(event_id="time-first", case_id=CASE, entity_ids=(value.entity_id,), relation_ids=(),
                          event_type=TimelineEventType.FIRST_SEEN, timestamp=NOW,
                          timestamp_source="fixture", evidence_refs=("ev-1",), confidence=0.8,
                          description="first")
    last = TimelineEvent(event_id="time-last", case_id=CASE, entity_ids=(value.entity_id,), relation_ids=(),
                         event_type=TimelineEventType.LAST_SEEN, timestamp=later,
                         timestamp_source="fixture", evidence_refs=("ev-2",), confidence=0.8,
                         description="last")
    graph.add_batch(entities=(value,), timeline=(first, last))
    assert [item["event_type"] for item in graph.snapshot()["timeline"]] == ["FIRST_SEEN", "LAST_SEEN"]


def test_path_confidence_uses_weakest_link_and_unique_independence(tmp_path):
    graph = store(tmp_path)
    a, b, c = (node(GraphEntityType.DOMAIN, f"{name}.test") for name in "abc")
    graph.add_batch(entities=(a, b, c), relations=(
        relation(a, b, confidence=0.9, evidence="ev-a", group="copied"),
        relation(b, c, confidence=0.6, evidence="ev-b", group="copied"),
    ))
    path = next(item for item in GraphPathEngine().paths(graph.snapshot()) if len(item.relation_sequence) == 2)
    assert path.confidence <= 0.6
    assert path.independent_groups == ("copied",)
    assert "weakest link" in " ".join(path.reasons)


def test_circular_provenance_is_detected_and_penalized(tmp_path):
    graph = store(tmp_path)
    a, b, c = (node(GraphEntityType.WEBSITE, f"https://{name}.test") for name in "abc")
    edges = (relation(a, b), relation(b, c, evidence="ev-2"), relation(c, a, evidence="ev-3"))
    graph.add_batch(entities=(a, b, c), relations=edges)
    cycles = detect_circular_provenance(graph.snapshot()["edges"])
    assert cycles
    assert any("circular provenance penalty" in reason
               for path in GraphPathEngine().paths(graph.snapshot()) for reason in path.reasons)


def test_graphml_export_is_valid_and_omits_raw_evidence_body(tmp_path):
    graph = store(tmp_path)
    left, right = node(GraphEntityType.DOMAIN, "left.test"), node(GraphEntityType.DOMAIN, "right.test")
    graph.add_batch(entities=(left, right), relations=(relation(left, right),))
    paths = GraphExporter().export_all(snapshot=graph.snapshot(), directory=graph.directory)
    root = ET.parse(paths["graphml_path"]).getroot()
    assert root.tag.endswith("graphml")
    assert "raw evidence body" not in Path(paths["graphml_path"]).read_text(encoding="utf-8")
    assert Path(paths["viewer_path"]).is_file()
