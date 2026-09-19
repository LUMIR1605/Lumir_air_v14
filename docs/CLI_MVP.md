# OSINT LAB CLI MVP

## IMPLEMENTED

The entry point is `python -m osint_lab`. It is a thin adapter over `CaseStore`, `CaseRunner`, `ReportEngine`, and `AuditLog`.

Commands:

```text
python -m osint_lab new-case --case-id CASE --case-name NAME --purpose PURPOSE \
  --authorized-by OWNER --legal-note NOTE --seed TYPE=VALUE [--seed TYPE=VALUE] \
  [--allow-passive-web]
python -m osint_lab plan CASE
python -m osint_lab run CASE [--dry-run]
python -m osint_lab report CASE
python -m osint_lab verify-audit CASE
```

`new-case` writes a validated private manifest outside Git. `plan` and `run --dry-run` show planned, denied, skipped, and available collectors without executing them. `run` uses CaseRunner and always routes steps through the Orchestrator. `report` regenerates JSON/HTML from the latest private JSON report without rerunning collectors. `verify-audit` verifies the case hash chain.

`PASSIVE_WEB` is disabled unless `--allow-passive-web` is provided at case creation. Seed values use repeated `--seed TYPE=VALUE` arguments. Supported MVP types are `PHONE`, `DOMAIN`, `USERNAME`, and `EMAIL`; unknown types remain visible as skipped plan entries.

## PLANNED

- Human-friendly interactive prompts, explicit authorization management, and machine-readable exit-code documentation.
- Selectable run/report history and redacted export profiles.

## NOT IMPLEMENTED

- GUI, shell completion, background mode, scheduler, service daemon, remote execution, or automatic network authorization.
