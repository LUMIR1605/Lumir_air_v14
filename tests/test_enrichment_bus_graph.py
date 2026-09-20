from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from osint_lab.agents import PhoneMetadataCollector, PhonePublicWebCollector, RawObservation, build_default_registry
from osint_lab.application import create_case_manifest
from osint_lab.case_manifest import SeedEntity
from osint_lab.case_runner import CaseRunner
from osint_lab.case_storage import CaseStore
from osint_lab.evidence import EvidenceVault
from osint_lab.graph import (
    EnrichmentBus,
    EntityNode,
    EntityNormalizer,
    GraphEntityType,
    GraphPivotPlanner,
    GraphProjector,
    GraphService,
    GraphStatus,
    GraphStore,
    PivotBudget,
    build_default_enricher_registry,
    deterministic_entity_id,
)
from osint_lab.intelligence import (
    CorrelationCandidate,
    CorrelationStatus,
    Directness,
    EntityRef,
    EntityType,
    EvidenceItem,
    EvidenceQualitySummary,
    IntelligenceSummary,
)
from osint_lab.orchestrator.audit import AuditLog
from osint_lab.orchestrator.authorization_store import AuthorizationStore
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.reporting import ReportEngine


NOW = datetime(2026, 9, 20, 16, 0, tzinfo=timezone.utc)
CASE = "enrichment-case-001"
PHONE = "+48123456789"


def setup(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    case_root = tmp_path / "cases"
    audit = AuditLog(repo_root=repo, root=tmp_path / "audit")
    collector_registry = build_default_registry()
    orchestrator = Orchestrator(
        audit_log=audit, authorization_store=AuthorizationStore(repo_root=repo, root=tmp_path / "auth"),
        collector_registry=collector_registry, evidence_vault=EvidenceVault(repo_root=repo, root=case_root),
        clock=lambda: NOW,
    )
    collectors = {"phone_metadata": PhoneMetadataCollector(), "phone_public_web": PhonePublicWebCollector()}
    bus = EnrichmentBus(registry=build_default_enricher_registry(), orchestrator=orchestrator,
                        collectors=collectors, clock=lambda: NOW)
    graph = GraphStore(repo_root=repo, case_root=case_root, case_id=CASE, audit_log=audit)
    return repo, graph, bus


def manifest(*, passive=False):
    return create_case_manifest(
        case_id=CASE, case_name="Synthetic graph", authorized_by="fixture", purpose="Synthetic test",
        legal_note="Synthetic identifiers only", seeds=(SeedEntity(entity_type="PHONE", value=PHONE),),
        allow_passive_web=passive, created_at=NOW,
    )


def phone_node():
    normalized = EntityNormalizer().normalize(GraphEntityType.PHONE, PHONE)
    return EntityNode(
        entity_id=deterministic_entity_id(CASE, GraphEntityType.PHONE, normalized.canonical_value),
        case_id=CASE, entity_type=GraphEntityType.PHONE, canonical_value=normalized.canonical_value,
        display_value=PHONE, aliases=(PHONE,), first_seen=NOW, last_seen=NOW, created_at=NOW, updated_at=NOW,
        source_refs=("manifest",), evidence_refs=("seed-phone",), confidence=1.0,
        status=GraphStatus.POSSIBLE, attributes={"hop": 0},
    )


def test_entity_routes_to_correct_enrichers_and_policy_filters_network(tmp_path):
    _, _, bus = setup(tmp_path)
    local = {item.enricher_id for item in bus.eligible(manifest=manifest(passive=False), entity=phone_node())}
    passive = {item.enricher_id for item in bus.eligible(manifest=manifest(passive=True), entity=phone_node())}
    assert local == {"phone_metadata"}
    assert passive == {"phone_metadata", "phone_public_web"}
    unsupported = EntityNode(**{**phone_node().__dict__, "entity_id": "ent-other",
                                "entity_type": GraphEntityType.OTHER, "canonical_value": "fixture"})
    assert bus.eligible(manifest=manifest(passive=True), entity=unsupported) == ()


def test_bus_executes_through_orchestrator_and_suppresses_duplicate(tmp_path):
    _, graph, bus = setup(tmp_path)
    result = bus.execute_seed(manifest=manifest(), entity_type="PHONE", seed_reference=PHONE,
                              enricher_id="phone_metadata", graph_store=graph)
    assert result.status.value == "SUCCESS"
    with pytest.raises(RuntimeError, match="duplicate enrichment"):
        bus.execute_seed(manifest=manifest(), entity_type="PHONE", seed_reference=PHONE,
                         enricher_id="phone_metadata", graph_store=graph)


def test_policy_and_max_hops_block_before_collector(tmp_path):
    _, graph, bus = setup(tmp_path)
    with pytest.raises(PermissionError, match="PolicyGate"):
        bus.execute(manifest=manifest(passive=False), entity=phone_node(), enricher_id="phone_public_web",
                    graph_store=graph, hop=1)
    bus.budget = PivotBudget(max_hops=1)
    with pytest.raises(RuntimeError, match="max hops"):
        bus.execute(manifest=manifest(), entity=phone_node(), enricher_id="phone_metadata",
                    graph_store=graph, hop=2)
    bus.budget = PivotBudget(max_network_requests=1)
    with pytest.raises(RuntimeError, match="network request budget"):
        bus.execute(manifest=manifest(passive=True), entity=phone_node(), enricher_id="phone_public_web",
                    graph_store=graph, hop=1)


def test_graph_pivot_budget_and_loop_history_are_enforced(tmp_path):
    _, graph, bus = setup(tmp_path)
    entity = phone_node()
    graph.add_batch(entities=(entity,))
    planner = GraphPivotPlanner(registry=bus.registry, budget=PivotBudget(max_pivots=2))
    first = planner.plan(snapshot=graph.snapshot(), store=graph)
    assert len(first) == 2
    graph.record_pivot(fingerprint=first[0].execution_fingerprint, entity_id=entity.entity_id,
                       enricher_id=first[0].proposed_enricher, status="PIVOT_EXECUTED", hop=1, timestamp=NOW)
    repeated = planner.plan(snapshot=graph.snapshot(), store=graph)
    assert len(repeated) == 2
    assert any(item.status == "SUPPRESSED_DUPLICATE" for item in repeated)


def evidence(evidence_id, group):
    return EvidenceItem(
        evidence_id=evidence_id, source_name="synthetic_collector", source_class=SourceClass.LOCAL.value,
        collected_at=NOW, freshness=1.0, independence_group=group, reproducible=True,
        directness=Directness.DIRECT, quality_score=0.8, quality_reasons=("synthetic direct evidence",),
    )


def correlation(correlation_id, left, right, status):
    return CorrelationCandidate(
        correlation_id=correlation_id, case_id=CASE, left_entity=left, right_entity=right,
        relation_type="MENTIONED_ON", evidence_refs=(f"ev-{correlation_id}",),
        supporting_sources=(f"group-{correlation_id}",), opposing_sources=(), confidence=0.72,
        reasons=("synthetic relation",), status=status,
    )


def test_projector_creates_nodes_and_only_non_rejected_positive_edges(tmp_path):
    _, graph, _ = setup(tmp_path)
    phone = EntityRef(entity_type=EntityType.PHONE, value_reference=PHONE)
    site = EntityRef(entity_type=EntityType.WEBSITE, value_reference="https://accepted.test/contact")
    rejected_site = EntityRef(entity_type=EntityType.WEBSITE, value_reference="https://rejected.test/id")
    accepted = correlation("accepted", phone, site, CorrelationStatus.POSSIBLE)
    rejected = correlation("rejected", phone, rejected_site, CorrelationStatus.REJECTED)
    summary = IntelligenceSummary(
        probable_correlations=(accepted, rejected),
        evidence_quality=(evidence("ev-accepted", "group-accepted"), evidence("ev-rejected", "group-rejected")),
        evidence_quality_summary=EvidenceQualitySummary(evidence_count=2, independent_group_count=2,
                                                       average_quality_score=0.8),
        unresolved_questions=("Synthetic unresolved question",),
    )
    GraphProjector().project(store=graph, manifest=manifest(), executions=(), intelligence=summary,
                             run_id="run-projector", started_at=NOW, finished_at=NOW)
    snapshot = graph.snapshot()
    assert {item["entity_type"] for item in snapshot["nodes"]} >= {"PHONE", "WEBSITE"}
    assert sum(item["status"] != "REJECTED" for item in snapshot["edges"]) == 1
    assert sum(item["status"] == "REJECTED" for item in snapshot["edges"]) == 1


def test_case_runner_production_adapter_creates_graph_dossier_report_and_viewer(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    case_root = tmp_path / "cases"
    case_store = CaseStore(repo_root=repo, root=case_root)
    vault = EvidenceVault(repo_root=repo, root=case_root)
    audit = AuditLog(repo_root=repo, root=tmp_path / "audit")
    collector_registry = build_default_registry()
    orchestrator = Orchestrator(
        audit_log=audit, authorization_store=AuthorizationStore(repo_root=repo, root=tmp_path / "auth"),
        collector_registry=collector_registry, evidence_vault=vault, clock=lambda: NOW,
    )
    collectors = {"phone_metadata": PhoneMetadataCollector()}
    enrichers = build_default_enricher_registry()
    graph_service = GraphService(repo_root=repo, case_root=case_root, audit_log=audit,
                                 enricher_registry=enrichers)
    bus = EnrichmentBus(registry=enrichers, orchestrator=orchestrator, collectors=collectors, clock=lambda: NOW)
    runner = CaseRunner(
        orchestrator=orchestrator, registry=collector_registry, collectors=collectors,
        case_store=case_store, report_engine=ReportEngine(evidence_vault=vault, case_root=case_root,
                                                         clock=lambda: NOW),
        audit_log=audit, clock=lambda: NOW, id_factory=lambda: "graph-runtime",
        graph_service=graph_service, enrichment_bus=bus,
    )
    result = runner.run(manifest())
    assert result.graph_bundle is not None
    assert result.graph_bundle["dossier"]["case_summary"]["case_id"] == CASE
    assert Path(result.graph_bundle["exports"]["viewer_path"]).is_file()
    report = json.loads(Path(result.report_reference.json_path).read_text(encoding="utf-8"))
    assert report["schema_version"] == "1.5"
    assert report["graph_intelligence"]["snapshot"]["nodes"]
    html = Path(result.report_reference.html_path).read_text(encoding="utf-8")
    assert "ANALYST VIEW" in html and "KEY ENTITIES" in html and "NEXT BEST PIVOTS" in html


def test_email_observation_materializes_multihop_domain_node_and_edge(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    graph = GraphStore(repo_root=repo, case_root=tmp_path / "cases", case_id="email-graph-001")
    email_manifest = create_case_manifest(
        case_id="email-graph-001", case_name="Synthetic email graph", authorized_by="fixture",
        purpose="Synthetic test", legal_note="Synthetic identifiers only",
        seeds=(SeedEntity(entity_type="EMAIL", value="Fixture.User@example.test"),),
        allow_passive_web=False, created_at=NOW,
    )
    observation = RawObservation(
        raw_status="VALID", value_reference="email:Fixture.User@example.test", evidence_ref="ev-email-domain",
        payload={"normalized_email": "Fixture.User@example.test", "domain": "example.test"},
    )
    record = SimpleNamespace(
        step=SimpleNamespace(collector_name="email_local_metadata", seed_reference="Fixture.User@example.test"),
        collector_version="1.0.0",
        result=SimpleNamespace(execution_id="run-email", finished_at=NOW, observations=(observation,)),
    )
    quality = evidence("ev-email-domain", "local-email")
    summary = IntelligenceSummary(
        evidence_quality=(quality,),
        evidence_quality_summary=EvidenceQualitySummary(evidence_count=1, independent_group_count=1,
                                                       average_quality_score=0.8),
    )
    GraphProjector().project(store=graph, manifest=email_manifest, executions=(record,), intelligence=summary,
                             run_id="run-email", started_at=NOW, finished_at=NOW)
    snapshot = graph.snapshot()
    assert {item["entity_type"] for item in snapshot["nodes"]} == {"EMAIL", "DOMAIN"}
    assert snapshot["edges"][0]["relation_type"] == "USES_DOMAIN"
