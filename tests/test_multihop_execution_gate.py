from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from osint_lab.agents import (
    Collector,
    CollectorRegistry,
    FindingCandidate,
    RawObservation,
    metadata_for,
)
from osint_lab.application import create_case_manifest
from osint_lab.case_manifest import SeedEntity
from osint_lab.case_runner import CaseRunner
from osint_lab.case_storage import CaseStore
from osint_lab.evidence import EvidenceVault
from osint_lab.graph import (
    EnricherRegistry,
    EnrichmentBus,
    GraphService,
    PivotBudget,
    build_default_enricher_registry,
)
from osint_lab.orchestrator.audit import AuditLog
from osint_lab.orchestrator.authorization_store import AuthorizationStore
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.reporting import ReportEngine
from osint_lab.schemas import FindingStatus
from osint_lab.sources import build_default_source_registry


NOW = datetime(2026, 9, 21, 9, 0, tzinfo=timezone.utc)
CASE = "multihop-fixture-001"
PHONE = "+48123456789"
SITE = "https://example.test/contact"
EMAIL = "fixture.user@example.test"


class SyntheticPathCollector(Collector):
    version = "1.0.0"

    def __init__(self, *, name, agent_type, source_class, observations, version="1.0.0"):
        self.agent_name = name
        self.agent_type = agent_type
        self.source_class = source_class
        self.version = version
        self.network_required = source_class is not SourceClass.LOCAL
        self._observations = observations
        super().__init__()

    def validate_input(self, seed_reference):
        if not isinstance(seed_reference, str) or not seed_reference.strip():
            raise ValueError("synthetic seed required")

    def _run(self, context, seed_reference):
        return tuple(self._observations(seed_reference))

    def normalize(self, observation):
        status = FindingStatus.UNKNOWN if observation.raw_status == "UNKNOWN" else FindingStatus.POSSIBLE
        return FindingCandidate(
            raw_status=observation.raw_status, normalized_status=status,
            value_reference=observation.value_reference, evidence_ref=observation.evidence_ref,
            notes="Synthetic Stage 15.1 fixture; no identity conclusion.",
        )

    def describe_capabilities(self):
        return {"network": self.network_required, "synthetic_fixture": True}


def observation(name, seed, raw_status, payload):
    digest = hashlib.sha256(f"{name}|{seed}".encode()).hexdigest()[:16]
    return RawObservation(
        raw_status=raw_status, value_reference=f"{name}:{digest}",
        evidence_ref=f"fixture-evidence:{name}:{digest}", payload=payload,
    )


def collectors(*, phone_has_data=True):
    def phone_public(seed):
        if not phone_has_data:
            return (observation("phone_public_web", seed, "UNKNOWN", {
                "target_verified": False, "discovered_entities": [], "failure_status": "UNKNOWN",
            }),)
        return (observation("phone_public_web", seed, "MATCH", {
            "target_verified": True,
            "discovered_entities": [{
                "entity_type": "WEBSITE", "value": SITE, "source_url": SITE,
                "evidence_ref": "fixture-site", "extraction_method": "fixture",
                "confidence": 0.9, "notes": "Synthetic public occurrence.",
            }],
        }),)

    values = (
        SyntheticPathCollector(
            name="phone_metadata", agent_type="PHONE", source_class=SourceClass.LOCAL,
            observations=lambda seed: (observation("phone_metadata", seed, "VALID", {}),),
        ),
        SyntheticPathCollector(
            name="phone_public_web", agent_type="PHONE", source_class=SourceClass.PASSIVE_WEB,
            observations=phone_public, version="1.1.0",
        ),
        SyntheticPathCollector(
            name="website_metadata", agent_type="WEBSITE", source_class=SourceClass.PASSIVE_WEB,
            observations=lambda seed: (observation("website_metadata", seed, "FOUND", {
                "final_url": SITE, "public_emails": [EMAIL], "public_phones": [], "organizations": [],
            }),),
        ),
        SyntheticPathCollector(
            name="email_local_metadata", agent_type="EMAIL", source_class=SourceClass.LOCAL,
            observations=lambda seed: (observation("email_local_metadata", seed, "VALID", {
                "normalized_email": EMAIL, "domain": "example.test",
            }),),
        ),
        SyntheticPathCollector(
            name="domain_dns", agent_type="DOMAIN", source_class=SourceClass.PASSIVE_WEB,
            observations=lambda seed: (observation("domain_dns", seed, "FOUND", {
                "query_type": "A", "records": ["192.0.2.10"],
            }),),
        ),
        SyntheticPathCollector(
            name="domain_rdap", agent_type="DOMAIN", source_class=SourceClass.PASSIVE_WEB,
            observations=lambda seed: (observation("domain_rdap", seed, "FOUND", {
                "registrar": "Fixture Registrar", "nameservers": [],
            }),),
        ),
    )
    return {item.agent_name: item for item in values}


def build_runner(tmp_path, *, phone_has_data=True, budget=None):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    case_root = tmp_path / "cases"
    audit = AuditLog(repo_root=repo, root=tmp_path / "audit")
    vault = EvidenceVault(repo_root=repo, root=case_root)
    collector_values = collectors(phone_has_data=phone_has_data)
    collector_registry = CollectorRegistry()
    for collector in collector_values.values():
        collector_registry.register(collector, metadata_for(
            collector, network_required=collector.network_required, provenance="Synthetic Stage 15.1 fixture",
        ))
    orchestrator = Orchestrator(
        audit_log=audit, authorization_store=AuthorizationStore(repo_root=repo, root=tmp_path / "auth"),
        collector_registry=collector_registry, evidence_vault=vault, clock=lambda: NOW,
    )
    enabled = set(collector_values)
    enrichers = EnricherRegistry()
    for definition in build_default_enricher_registry().definitions:
        if definition.enricher_id in enabled:
            enrichers.register(definition)
    sources = build_default_source_registry()
    selected_budget = budget or PivotBudget()
    graph_service = GraphService(
        repo_root=repo, case_root=case_root, audit_log=audit, enricher_registry=enrichers,
        source_registry=sources, budget=selected_budget,
    )
    bus = EnrichmentBus(
        registry=enrichers, orchestrator=orchestrator, collectors=collector_values, clock=lambda: NOW,
        source_registry=sources, budget=selected_budget,
    )
    store = CaseStore(repo_root=repo, root=case_root)
    runner = CaseRunner(
        orchestrator=orchestrator, registry=collector_registry, collectors=collector_values,
        case_store=store, report_engine=ReportEngine(evidence_vault=vault, case_root=case_root,
                                                     clock=lambda: NOW),
        audit_log=audit, clock=lambda: NOW, id_factory=lambda: "multihop-run",
        graph_service=graph_service, enrichment_bus=bus,
    )
    return runner, store


def run_case(tmp_path, *, phone_has_data=True, budget=None):
    runner, store = build_runner(tmp_path, phone_has_data=phone_has_data, budget=budget)
    manifest = create_case_manifest(
        case_id=CASE, case_name="Synthetic multi-hop", authorized_by="fixture",
        purpose="Stage 15.1 offline integration test", legal_note="Synthetic identifiers only",
        seeds=(SeedEntity(entity_type="PHONE", value=PHONE),), allow_passive_web=True, created_at=NOW,
    )
    store.create(manifest)
    return runner.run(manifest)


def test_phone_web_email_domain_executes_real_two_hop_path(tmp_path):
    result = run_case(tmp_path)
    names_and_hops = [(item.step.collector_name, item.hop) for item in result.executions]
    assert names_and_hops[:2] == [("phone_metadata", 0), ("phone_public_web", 0)]
    assert ("website_metadata", 1) in names_and_hops
    assert ("email_local_metadata", 1) in names_and_hops
    assert ("domain_dns", 2) in names_and_hops
    assert ("domain_rdap", 2) in names_and_hops
    assert result.multi_hop_summary is not None
    assert result.multi_hop_summary.auto_executions >= 4
    assert result.multi_hop_summary.hop_1_count == 2
    assert result.multi_hop_summary.hop_2_count >= 2
    assert result.multi_hop_summary.suppressed_duplicates >= 2

    graph = result.graph_bundle
    assert graph is not None
    assert {item["entity_type"] for item in graph["snapshot"]["nodes"]} >= {
        "PHONE", "WEBSITE", "EMAIL", "DOMAIN", "IP", "COMPANY",
    }
    assert graph["snapshot"]["edges"]
    assert graph["dossier"]["coverage_summary"]["executed_sources"] >= 4
    mappings = {item["collector_id"]: item for item in graph["source_mapping"]}
    assert mappings["phone_public_web"]["source_registry_id"] == "duckduckgo_html"
    assert "duckduckgo_html" in graph["dossier"]["executed_source_ids"]

    direct = graph["dossier"]["direct_sources"]
    downstream = graph["dossier"]["downstream_sources"]
    assert {item["collector_id"] for item in direct} == {"phone_metadata", "phone_public_web"}
    assert any(item["enricher_id"] == "website_metadata" and item["status"] == "EXECUTED"
               for item in downstream)
    report = json.loads(Path(result.report_reference.json_path).read_text(encoding="utf-8"))
    html = Path(result.report_reference.html_path).read_text(encoding="utf-8")
    assert report["investigation_execution_path"]["hop_2_count"] >= 2
    assert "INVESTIGATION EXECUTION PATH" in html
    assert "DIRECT SOURCES" in html and "DOWNSTREAM SOURCES" in html


def test_no_verified_phone_occurrence_stops_without_fabricated_pivots(tmp_path):
    result = run_case(tmp_path, phone_has_data=False)
    assert [item.step.collector_name for item in result.executions] == [
        "phone_metadata", "phone_public_web",
    ]
    assert result.multi_hop_summary.auto_executions == 0
    assert result.multi_hop_summary.stop_reason in {"NO_NEW_PIVOTS", "NO_NEW_INFORMATION"}
    assert {item["entity_type"] for item in result.graph_bundle["snapshot"]["nodes"]} == {"PHONE"}


def test_auto_pivot_and_request_budgets_stop_with_exact_reason(tmp_path):
    pivot_limited = run_case(tmp_path / "pivot", budget=PivotBudget(max_auto_pivots=1))
    assert pivot_limited.multi_hop_summary.auto_executions == 1
    assert pivot_limited.multi_hop_summary.stop_reason == "PIVOT_BUDGET"

    request_limited = run_case(
        tmp_path / "request", budget=PivotBudget(max_network_requests=10),
    )
    assert request_limited.multi_hop_summary.auto_executions == 0
    assert request_limited.multi_hop_summary.stop_reason == "REQUEST_BUDGET"
    assert request_limited.multi_hop_summary.blocked >= 1


def test_unknown_source_mapping_fails_closed_at_startup(tmp_path):
    definition = next(item for item in build_default_enricher_registry().definitions
                      if item.enricher_id == "phone_public_web")
    from dataclasses import replace
    registry = EnricherRegistry()
    registry.register(replace(definition, source_id="missing_source"))
    repo = tmp_path / "repo"
    repo.mkdir()
    try:
        GraphService(
            repo_root=repo, case_root=tmp_path / "cases", audit_log=AuditLog(repo_root=repo),
            enricher_registry=registry, source_registry=build_default_source_registry(),
        )
    except ValueError as error:
        assert "SOURCE_MAPPING_ERROR" in str(error)
    else:
        raise AssertionError("unknown source mapping must fail closed")
