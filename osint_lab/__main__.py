"""Thin command-line interface for the OSINT LAB MVP case workflow."""

import argparse
import json
from typing import Sequence

from osint_lab.application import ApplicationServices, build_application, create_case_manifest
from osint_lab.case_manifest import CaseManifest, SeedEntity
from osint_lab.case_runner import CaseExecutionPlan
from osint_lab.orchestrator.audit import verify_audit_log


CliApplication = ApplicationServices


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


def main(argv: Sequence[str] | None = None, *, application: ApplicationServices | None = None) -> int:
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
    return create_case_manifest(
        case_id=arguments.case_id,
        case_name=arguments.case_name,
        authorized_by=arguments.authorized_by,
        purpose=arguments.purpose,
        legal_note=arguments.legal_note,
        seeds=seeds,
        allow_passive_web=arguments.allow_passive_web,
        retention_days=arguments.retention_days,
        notes=arguments.notes,
    )


def _print_json(payload: dict[str, object]) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
