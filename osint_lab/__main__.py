"""Thin command-line interface for the OSINT LAB MVP case workflow."""

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Sequence

from osint_lab.agents import build_default_registry
from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.case_runner import CaseExecutionPlan, CaseRunner, build_default_collectors
from osint_lab.case_storage import CaseStore
from osint_lab.evidence import EvidenceVault
from osint_lab.orchestrator.audit import AuditLog, verify_audit_log
from osint_lab.orchestrator.authorization_store import AuthorizationStore
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.reporting import ReportEngine


@dataclass(frozen=True)
class CliApplication:
    case_store: CaseStore
    runner: CaseRunner
    audit_log: AuditLog


def build_application(*, repo_root: Path | None = None) -> CliApplication:
    root = (Path(__file__).resolve().parents[1] if repo_root is None else Path(repo_root)).resolve()
    clock = lambda: datetime.now(timezone.utc)
    case_store = CaseStore(repo_root=root)
    vault = EvidenceVault(repo_root=root, root=case_store.root)
    audit = AuditLog(repo_root=root)
    registry = build_default_registry()
    orchestrator = Orchestrator(
        audit_log=audit,
        authorization_store=AuthorizationStore(repo_root=root),
        collector_registry=registry,
        evidence_vault=vault,
        clock=clock,
    )
    reporter = ReportEngine(evidence_vault=vault, case_root=case_store.root, clock=clock)
    runner = CaseRunner(
        orchestrator=orchestrator,
        registry=registry,
        collectors=build_default_collectors(),
        case_store=case_store,
        report_engine=reporter,
        audit_log=audit,
        clock=clock,
    )
    return CliApplication(case_store=case_store, runner=runner, audit_log=audit)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m osint_lab")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("new-case", help="Create a private case manifest")
    create.add_argument("--case-id", required=True)
    create.add_argument("--case-name", required=True)
    create.add_argument("--purpose", required=True)
    create.add_argument("--authorized-by", required=True)
    create.add_argument("--legal-note", required=True)
    create.add_argument("--seed", action="append", required=True, metavar="TYPE=VALUE")
    create.add_argument("--allow-passive-web", action="store_true")
    create.add_argument("--retention-days", type=int, default=30)
    create.add_argument("--notes", default="")

    plan = commands.add_parser("plan", help="Build a dry execution plan")
    plan.add_argument("case_id")
    plan.add_argument("--no-email-domain-dns", action="store_true")

    run = commands.add_parser("run", help="Execute a case through the Orchestrator")
    run.add_argument("case_id")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--no-email-domain-dns", action="store_true")

    report = commands.add_parser("report", help="Regenerate reports from the latest private JSON report")
    report.add_argument("case_id")

    verify = commands.add_parser("verify-audit", help="Verify a case audit hash chain")
    verify.add_argument("case_id")
    return parser


def main(argv: Sequence[str] | None = None, *, application: CliApplication | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    app = application or build_application()
    try:
        if arguments.command == "new-case":
            seeds = tuple(_parse_seed(value) for value in arguments.seed)
            manifest = _manifest_from_arguments(arguments, seeds)
            path = app.case_store.create(manifest)
            _print_json({"case_id": manifest.case_id, "manifest_path": str(path)})
            return 0
        if arguments.command == "plan":
            manifest = app.case_store.load(arguments.case_id)
            plan = app.runner.plan(
                manifest,
                include_email_domain_dns=not arguments.no_email_domain_dns,
            )
            _print_json(plan.to_dict())
            return 0
        if arguments.command == "run":
            manifest = app.case_store.load(arguments.case_id)
            result = app.runner.run(
                manifest,
                dry_run=arguments.dry_run,
                include_email_domain_dns=not arguments.no_email_domain_dns,
            )
            _print_json(result.to_dict())
            if isinstance(result, CaseExecutionPlan):
                return 0
            return 0 if result.overall_status.value in {"SUCCESS", "PARTIAL", "DENIED"} else 1
        if arguments.command == "report":
            reference = app.runner.regenerate_latest_report(arguments.case_id)
            _print_json(reference.to_dict())
            return 0
        if arguments.command == "verify-audit":
            verification = verify_audit_log(app.audit_log, arguments.case_id)
            _print_json({
                "valid": verification.valid,
                "entry_count": verification.entry_count,
                "head_hash": verification.head_hash,
                "reason": verification.reason,
            })
            return 0 if verification.valid else 1
    except (FileExistsError, FileNotFoundError, OSError, ValueError, PermissionError) as error:
        parser.exit(2, f"error: {error}\n")
    raise RuntimeError("unhandled CLI command")


def _parse_seed(value: str) -> SeedEntity:
    if not isinstance(value, str) or "=" not in value:
        raise ValueError("seed must use TYPE=VALUE")
    entity_type, seed_value = value.split("=", 1)
    return SeedEntity(entity_type=entity_type.strip().upper(), value=seed_value.strip())


def _manifest_from_arguments(arguments, seeds: tuple[SeedEntity, ...]) -> CaseManifest:
    allowed_sources = {SourceClass.LOCAL}
    if arguments.allow_passive_web:
        allowed_sources.add(SourceClass.PASSIVE_WEB)
    allowed_agent_types = {seed.entity_type for seed in seeds if seed.entity_type in {"PHONE", "DOMAIN", "USERNAME", "EMAIL"}}
    if any(seed.entity_type == "EMAIL" for seed in seeds):
        allowed_agent_types.add("DOMAIN")
    return CaseManifest(
        case_id=arguments.case_id,
        case_name=arguments.case_name,
        created_at=datetime.now(timezone.utc),
        authorized_by=arguments.authorized_by,
        purpose=arguments.purpose,
        legal_basis_or_consent_note=arguments.legal_note,
        seed_entities=seeds,
        allowed_source_classes=frozenset(allowed_sources),
        forbidden_source_classes=frozenset({
            SourceClass.THIRD_PARTY_API,
            SourceClass.TOR,
            SourceClass.DIRECT_TARGET,
        }),
        allowed_agent_types=frozenset(allowed_agent_types),
        retention_days=arguments.retention_days,
        notes=arguments.notes,
        status=CaseStatus.ACTIVE,
    )


def _print_json(payload: dict[str, object]) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
