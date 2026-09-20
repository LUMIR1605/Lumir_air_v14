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


class GraphService:
    def __init__(self, *, repo_root: Path, case_root: Path, audit_log: AuditLog,
                 enricher_registry: EnricherRegistry, budget: PivotBudget | None = None) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.case_root = Path(case_root).resolve()
        self.audit_log = audit_log
        self.registry = enricher_registry
        self.budget = budget or PivotBudget()
        self.projector = GraphProjector()
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
        version_before, version_after = self.projector.project(
            store=store, manifest=manifest, executions=tuple(executions), intelligence=intelligence,
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
            "dossier": dossier.to_dict(), "exports": exports,
        }

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
