"""Shared composition root for CLI and Windows desktop adapters."""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from osint_lab.agents import build_default_registry
from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.case_runner import CaseRunner, build_default_collectors
from osint_lab.case_storage import CaseStore
from osint_lab.evidence import EvidenceVault
from osint_lab.graph import EnrichmentBus, GraphService, build_default_enricher_registry
from osint_lab.orchestrator.audit import AuditLog
from osint_lab.orchestrator.authorization_store import AuthorizationStore
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.reporting import ReportEngine
from osint_lab.sources import build_default_source_registry


@dataclass(frozen=True)
class ApplicationServices:
    case_store: CaseStore
    runner: CaseRunner
    audit_log: AuditLog


def build_application(*, repo_root: Path | None = None) -> ApplicationServices:
    root = (Path(__file__).resolve().parents[1] if repo_root is None else Path(repo_root)).resolve()
    clock = lambda: datetime.now(timezone.utc)
    case_store = CaseStore(repo_root=root)
    vault = EvidenceVault(repo_root=root, root=case_store.root)
    audit = AuditLog(repo_root=root)
    registry = build_default_registry()
    collectors = build_default_collectors()
    orchestrator = Orchestrator(
        audit_log=audit,
        authorization_store=AuthorizationStore(repo_root=root),
        collector_registry=registry,
        evidence_vault=vault,
        clock=clock,
    )
    reporter = ReportEngine(evidence_vault=vault, case_root=case_store.root, clock=clock)
    enricher_registry = build_default_enricher_registry()
    source_registry = build_default_source_registry()
    graph_service = GraphService(
        repo_root=root, case_root=case_store.root, audit_log=audit, enricher_registry=enricher_registry,
        source_registry=source_registry,
    )
    enrichment_bus = EnrichmentBus(
        registry=enricher_registry, orchestrator=orchestrator, collectors=collectors, clock=clock,
        source_registry=source_registry,
    )
    runner = CaseRunner(
        orchestrator=orchestrator,
        registry=registry,
        collectors=collectors,
        case_store=case_store,
        report_engine=reporter,
        audit_log=audit,
        clock=clock,
        graph_service=graph_service,
        enrichment_bus=enrichment_bus,
    )
    return ApplicationServices(case_store=case_store, runner=runner, audit_log=audit)


def create_case_manifest(
    *,
    case_id: str,
    case_name: str,
    authorized_by: str,
    purpose: str,
    legal_note: str,
    seeds: Iterable[SeedEntity],
    allow_passive_web: bool,
    retention_days: int = 30,
    notes: str = "",
    created_at: datetime | None = None,
) -> CaseManifest:
    seed_values = tuple(seeds)
    allowed_sources = {SourceClass.LOCAL}
    if allow_passive_web:
        allowed_sources.add(SourceClass.PASSIVE_WEB)
    allowed_agent_types = {
        seed.entity_type.strip().upper()
        for seed in seed_values
        if seed.entity_type.strip().upper() in {
            "PHONE", "DOMAIN", "USERNAME", "EMAIL", "WEBSITE", "COMPANY", "ORGANIZATION", "DOCUMENT"
        }
    }
    if any(seed.entity_type.strip().upper() == "EMAIL" for seed in seed_values):
        allowed_agent_types.add("DOMAIN")
    if allow_passive_web:
        # Passive-web consent covers the bounded transitive collector set used by the
        # reviewed AUTO pivot loop; PolicyGate still evaluates every execution.
        allowed_agent_types.update({"WEBSITE", "EMAIL", "DOMAIN", "COMPANY", "ORGANIZATION", "DOCUMENT"})
    return CaseManifest(
        case_id=case_id,
        case_name=case_name,
        created_at=created_at or datetime.now(timezone.utc),
        authorized_by=authorized_by,
        purpose=purpose,
        legal_basis_or_consent_note=legal_note,
        seed_entities=seed_values,
        allowed_source_classes=frozenset(allowed_sources),
        forbidden_source_classes=frozenset({
            SourceClass.THIRD_PARTY_API,
            SourceClass.TOR,
            SourceClass.DIRECT_TARGET,
        }),
        allowed_agent_types=frozenset(allowed_agent_types),
        retention_days=retention_days,
        notes=notes,
        status=CaseStatus.ACTIVE,
    )
