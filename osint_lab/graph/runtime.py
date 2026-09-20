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

    def process(
        self,
        *,
        manifest: CaseManifest,
        executions: Iterable[object],
        intelligence: IntelligenceSummary,
        run_id: str,
        started_at: datetime,
        finished_at: datetime,
    ) -> dict[str, object]:
        store = self.store(manifest.case_id)
        execution_values = tuple(executions)
        version_before, version_after = self.projector.project(
            store=store, manifest=manifest, executions=execution_values, intelligence=intelligence,
            run_id=run_id, started_at=started_at, finished_at=finished_at,
        )
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
        source_coverage = self._source_coverage(snapshot, execution_values)
        dossier_payload = dossier.to_dict()
        dossier_payload["source_coverage"] = [item.to_dict() for item in source_coverage]
        dossier_payload["coverage_summary"].update({
            "eligible_sources": sum(item.eligible_sources for item in source_coverage),
            "enabled_sources": sum(item.enabled_sources for item in source_coverage),
            "executed_sources": sum(item.executed_sources for item in source_coverage),
            "blocked_unavailable_sources": sum(item.blocked_sources + item.unknown_sources for item in source_coverage),
            "successful_sources": sum(item.successful_sources for item in source_coverage),
            "entities_discovered": len(snapshot.get("nodes", ())),
            "useful_pivots": sum(item.status == "PROPOSED" for item in pivots),
        })
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
            "source_registry": ({"version": self.source_registry.version,
                                 "config_hash": self.source_registry.config_hash}
                                if self.source_registry is not None else None),
            "dossier": dossier_payload, "exports": exports,
        }

    def _source_coverage(self, snapshot, executions) -> tuple[SourceCoverage, ...]:
        if self.source_registry is None:
            return ()
        executed: dict[str, list[str]] = {}
        evidence: dict[str, set[str]] = {}
        for record in executions:
            if record.result is None:
                continue
            for observation in record.result.observations:
                source_id = str(observation.payload.get("source_id") or record.step.collector_name)
                failure = str(observation.payload.get("failure_status") or observation.raw_status)
                executed.setdefault(source_id, []).append(failure)
                if observation.evidence_ref:
                    evidence.setdefault(source_id, set()).add(observation.evidence_ref)
        node_types = {item.get("entity_type") for item in snapshot.get("nodes", ())}
        values = []
        for entity_type in (
            "PHONE", "EMAIL", "USERNAME", "DOMAIN", "COMPANY", "DOCUMENT",
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
        return tuple(values)

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
