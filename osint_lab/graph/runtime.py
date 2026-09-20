"""Case-level graph projection and analytical artifact orchestration."""

from datetime import datetime
import hashlib
from pathlib import Path
from typing import Iterable

from osint_lab.case_manifest import CaseManifest
from osint_lab.intelligence import IntelligenceSummary
from osint_lab.orchestrator.audit import AuditLog

from .analytics import (
    GraphAdversarialVerifier,
    GraphPathEngine,
    GraphPivotPlanner,
    build_dossier,
    build_identity_candidates,
    detect_circular_provenance,
)
from .enrichment import EnricherRegistry
from .export import GraphExporter
from .models import CaseEvent, CaseEventType, PivotBudget
from .projector import GraphProjector
from .store import GraphStore
from osint_lab.sources import SourceCoverage, SourceFailureStatus, SourceRegistry


class GraphService:
    def __init__(self, *, repo_root: Path, case_root: Path, audit_log: AuditLog,
                 enricher_registry: EnricherRegistry, budget: PivotBudget | None = None,
                 source_registry: SourceRegistry | None = None) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.case_root = Path(case_root).resolve()
        self.audit_log = audit_log
        self.registry = enricher_registry
        self.source_registry = source_registry
        self.budget = budget or PivotBudget()
        self.projector = GraphProjector(source_registry=source_registry)
        self.paths = GraphPathEngine()
        self.adversarial = GraphAdversarialVerifier()
        self.exporter = GraphExporter()
        self._validate_source_mappings()

    def _validate_source_mappings(self) -> None:
        if self.source_registry is None:
            return
        for definition in self.registry.definitions:
            if not definition.enabled or definition.source_id is None:
                continue
            try:
                source = self.source_registry.get(definition.source_id)
            except KeyError as error:
                raise ValueError(f"SOURCE_MAPPING_ERROR: {definition.enricher_id}") from error
            if source.source_class is not definition.source_class:
                raise ValueError(f"source class mismatch: {definition.enricher_id}")

    def project_batch(
        self,
        *,
        manifest: CaseManifest,
        executions: Iterable[object],
        intelligence: IntelligenceSummary,
        run_id: str,
        batch_id: str,
        started_at: datetime,
        finished_at: datetime,
    ) -> tuple[int, int]:
        return self.projector.project(
            store=self.store(manifest.case_id), manifest=manifest, executions=tuple(executions),
            intelligence=intelligence, run_id=f"{run_id}:projection:{batch_id}",
            started_at=started_at, finished_at=finished_at,
        )

    def plan_pivots(
        self,
        *,
        case_id: str,
        intelligence: IntelligenceSummary,
    ):
        store = self.store(case_id)
        return GraphPivotPlanner(registry=self.registry, budget=self.budget).plan(
            snapshot=store.snapshot(), store=store, contradictions=intelligence.contradictions,
            open_hypotheses=(item.to_dict() for item in intelligence.open_hypotheses),
        )

    def process(
        self,
        *,
        manifest: CaseManifest,
        executions: Iterable[object],
        intelligence: IntelligenceSummary,
        run_id: str,
        started_at: datetime,
        finished_at: datetime,
        project_executions: bool = True,
    ) -> dict[str, object]:
        store = self.store(manifest.case_id)
        execution_values = tuple(executions)
        if project_executions:
            version_before, _ = self.projector.project(
                store=store, manifest=manifest, executions=execution_values, intelligence=intelligence,
                run_id=run_id, started_at=started_at, finished_at=finished_at,
            )
        else:
            version_before = store.graph_version
        snapshot = store.snapshot()
        paths = self.paths.paths(snapshot, max_hops=self.budget.max_hops)
        planner = GraphPivotPlanner(registry=self.registry, budget=self.budget)
        pivots = planner.plan(snapshot=snapshot, store=store, contradictions=intelligence.contradictions,
                              open_hypotheses=(item.to_dict() for item in intelligence.open_hypotheses))
        pivot_events = tuple(CaseEvent(
            event_id="evt-" + hashlib.sha256(f"pivot|{item.pivot_id}".encode()).hexdigest()[:24],
            case_id=manifest.case_id, event_type=CaseEventType.PIVOT_PROPOSED, timestamp=finished_at,
            subject_id=item.pivot_id, evidence_refs=(), attributes={"enricher": item.proposed_enricher,
                                                                    "graph_value": item.graph_value},
        ) for item in pivots if item.status == "PROPOSED")
        if pivot_events:
            store.add_batch(events=pivot_events)
            snapshot = store.snapshot()
        reviews = self.adversarial.review(snapshot=snapshot, paths=paths)
        identities = build_identity_candidates(paths)
        graph_hypotheses = []
        for hypothesis in intelligence.open_hypotheses:
            evidence = set(hypothesis.evidence_for)
            supporting_paths = [item.path_id for item in paths if evidence & set(item.evidence_refs)]
            graph_hypotheses.append({**hypothesis.to_dict(), "supporting_graph_paths": supporting_paths,
                                     "graph_assessment": "PATH_SUPPORTED" if supporting_paths else "NO_GRAPH_PATH"})
        intelligence_payload = intelligence.to_dict()
        intelligence_payload["open_hypotheses"] = graph_hypotheses
        dossier = build_dossier(
            snapshot=snapshot, seeds=(item.to_dict() for item in manifest.seed_entities), paths=paths,
            intelligence=intelligence_payload, pivots=pivots,
        )
        source_coverage, coverage_details = self._source_coverage(snapshot, execution_values, manifest)
        dossier_payload = dossier.to_dict()
        dossier_payload["source_coverage"] = [item.to_dict() for item in source_coverage]
        dossier_payload["coverage_summary"].update({
            "eligible_sources": coverage_details["eligible_source_count"],
            "enabled_sources": coverage_details["enabled_source_count"],
            "executed_sources": coverage_details["executed_source_count"],
            "blocked_unavailable_sources": sum(item.blocked_sources + item.unknown_sources for item in source_coverage),
            "successful_sources": sum(item.successful_sources for item in source_coverage),
            "entities_discovered": len(snapshot.get("nodes", ())),
            "useful_pivots": sum(item.status == "PROPOSED" for item in pivots),
            "direct_source_count": len(coverage_details["direct_sources"]),
            "downstream_source_count": len(coverage_details["downstream_sources"]),
        })
        dossier_payload["direct_sources"] = coverage_details["direct_sources"]
        dossier_payload["downstream_sources"] = coverage_details["downstream_sources"]
        dossier_payload["executed_source_ids"] = coverage_details["executed_source_ids"]
        exports = self.exporter.export_all(snapshot=snapshot, directory=store.directory)
        return {
            "schema_version": snapshot["schema_version"], "graph_version_before": version_before,
            "graph_version_after": store.graph_version, "snapshot": snapshot,
            "correlation_paths": [item.to_dict() for item in paths],
            "circular_provenance_cycles": [list(item) for item in detect_circular_provenance(snapshot["edges"])],
            "adversarial_graph_reviews": list(reviews),
            "hypothesis_graph": graph_hypotheses,
            "identity_candidates": [item.to_dict() for item in identities],
            "recommended_pivots": [item.to_dict() for item in pivots],
            "source_coverage": [item.to_dict() for item in source_coverage],
            "source_mapping": coverage_details["execution_mappings"],
            "source_registry": ({"version": self.source_registry.version,
                                 "config_hash": self.source_registry.config_hash}
                                if self.source_registry is not None else None),
            "dossier": dossier_payload, "exports": exports,
        }

    def _source_coverage(self, snapshot, executions, manifest):
        if self.source_registry is None:
            return (), {
                "eligible_source_count": 0, "enabled_source_count": 0, "executed_source_count": 0,
                "executed_source_ids": [], "direct_sources": [], "downstream_sources": [],
                "execution_mappings": [],
            }
        executed: dict[str, list[str]] = {}
        evidence: dict[str, set[str]] = {}
        execution_mappings = []
        for record in executions:
            if record.result is None:
                continue
            source_registry_id = getattr(record, "source_registry_id", None)
            source_id = getattr(record, "source_id", None) or record.step.collector_name
            mapping = {
                "execution_id": record.result.execution_id,
                "collector_id": getattr(record, "collector_id", None) or record.step.collector_name,
                "enricher_id": getattr(record, "enricher_id", None) or record.step.collector_name,
                "source_id": source_id,
                "source_registry_id": source_registry_id,
                "hop": int(getattr(record, "hop", 0)),
                "phase": getattr(record, "execution_phase", "INITIAL"),
                "result_status": record.result_status,
            }
            execution_mappings.append(mapping)
            if record.result_status == "DENIED":
                continue
            if source_registry_id is None:
                if record.step.source_class.value != "LOCAL":
                    raise RuntimeError(f"SOURCE_MAPPING_ERROR: {record.step.collector_name}")
                continue
            try:
                self.source_registry.get(source_registry_id)
            except KeyError as error:
                raise RuntimeError(f"SOURCE_MAPPING_ERROR: {record.step.collector_name}") from error
            failure_values = []
            for observation in record.result.observations:
                failure_values.append(str(observation.payload.get("failure_status") or ""))
                if observation.evidence_ref:
                    evidence.setdefault(source_registry_id, set()).add(observation.evidence_ref)
            if record.result_status in {"SUCCESS", "PARTIAL"} and not any(failure_values):
                failure_values = [SourceFailureStatus.SUCCESS.value]
            executed.setdefault(source_registry_id, []).extend(failure_values or [SourceFailureStatus.UNKNOWN.value])
        node_types = {item.get("entity_type") for item in snapshot.get("nodes", ())}
        values = []
        for entity_type in (
            "PHONE", "EMAIL", "USERNAME", "DOMAIN", "WEBSITE", "COMPANY", "ORGANIZATION", "DOCUMENT",
        ):
            from .models import GraphEntityType
            graph_type = GraphEntityType(entity_type)
            definitions = self.source_registry.for_entity(graph_type)
            enabled = [item for item in definitions if item.enabled]
            relevant_ids = {item.source_id for item in definitions}
            executed_ids = relevant_ids & set(executed)
            failures = [value for source_id in executed_ids for value in executed[source_id]]
            success = {source_id for source_id in executed_ids
                       if SourceFailureStatus.SUCCESS.value in executed[source_id]}
            unknown_values = {SourceFailureStatus.UNKNOWN.value, SourceFailureStatus.PARSER_FAILURE.value,
                              SourceFailureStatus.TIMEOUT.value, SourceFailureStatus.RATE_LIMITED.value}
            values.append(SourceCoverage(
                entity_type=graph_type, eligible_sources=len(definitions) if entity_type in node_types else 0,
                enabled_sources=len(enabled) if entity_type in node_types else 0,
                executed_sources=len(executed_ids),
                blocked_sources=sum(not item.enabled for item in definitions) if entity_type in node_types else 0,
                unknown_sources=sum(item in unknown_values for item in failures),
                successful_sources=len(success),
                verified_evidence_count=sum(len(evidence.get(source_id, ())) for source_id in success),
                independent_evidence_groups=len({group for edge in snapshot.get("edges", ())
                                                 for group in edge.get("independence_groups", ())}),
            ))
        seed_types = {item.entity_type.strip().upper() for item in manifest.seed_entities}
        discovered_types = node_types - seed_types
        relevant = {item.source_id: item for graph_type in GraphEntityType
                    if graph_type.value in node_types for item in self.source_registry.for_entity(graph_type)}
        enabled = {key for key, item in relevant.items() if item.enabled}
        executed_ids = set(executed)
        direct_sources = []
        for mapping in execution_mappings:
            if mapping["phase"] != "INITIAL" or mapping["hop"] != 0:
                continue
            direct_sources.append({
                **mapping,
                "status": "EXECUTED" if mapping["result_status"] != "DENIED" else "BLOCKED",
            })
        downstream_by_enricher = {}
        for graph_type in GraphEntityType:
            if graph_type.value not in discovered_types:
                continue
            for definition in self.registry.for_entity(graph_type):
                downstream_by_enricher.setdefault(definition.enricher_id, {
                    "enricher_id": definition.enricher_id,
                    "source_id": definition.source_id or definition.enricher_id,
                    "source_registry_id": definition.source_id,
                    "entity_type": graph_type.value,
                    "status": "DOWNSTREAM_ELIGIBLE",
                })
        executed_enrichers = {item["enricher_id"] for item in execution_mappings if item["hop"] > 0}
        for enricher_id in executed_enrichers & set(downstream_by_enricher):
            downstream_by_enricher[enricher_id]["status"] = "EXECUTED"
        details = {
            "eligible_source_count": len(relevant),
            "enabled_source_count": len(enabled),
            "executed_source_count": len(executed_ids),
            "executed_source_ids": sorted(executed_ids),
            "direct_sources": direct_sources,
            "downstream_sources": [downstream_by_enricher[key] for key in sorted(downstream_by_enricher)],
            "execution_mappings": execution_mappings,
        }
        return tuple(values), details

    def record_report(self, *, case_id: str, run_id: str, timestamp: datetime,
                      evidence_refs: tuple[str, ...]) -> None:
        event = CaseEvent(
            event_id="evt-" + hashlib.sha256(f"report|{run_id}".encode()).hexdigest()[:24],
            case_id=case_id, event_type=CaseEventType.REPORT_GENERATED, timestamp=timestamp,
            subject_id=run_id, evidence_refs=evidence_refs, attributes={},
        )
        self.store(case_id).add_batch(events=(event,))

    def store(self, case_id: str) -> GraphStore:
        return GraphStore(repo_root=self.repo_root, case_root=self.case_root, case_id=case_id,
                          audit_log=self.audit_log)
