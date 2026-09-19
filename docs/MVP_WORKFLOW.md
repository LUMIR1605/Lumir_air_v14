# MVP workflow

## NEW CASE

Create a validated private `CaseManifest` with lawful purpose, authorization note, retention, source classes, and one or more synthetic or authorized seeds. Case data are atomically stored outside Git under `%LOCALAPPDATA%\LumirOSINTLab\cases\<case_id>`.

## ADD SEEDS

Use `PHONE`, `DOMAIN`, `USERNAME`, or `EMAIL`. Duplicate seeds are retained in the manifest but deduplicated in the execution plan with an explicit warning. Unknown types are not guessed or repaired.

## PLAN

Run `python -m osint_lab plan <case_id>` or `run <case_id> --dry-run`. Registry identity, collector input, and PolicyGate decisions are checked. The plan lists planned, denied, skipped, dependencies, source classes, and available collectors. No collector, network, audit, receipt, or evidence publication occurs.

## RUN

Run `python -m osint_lab run <case_id>`. CaseRunner submits every eligible or policy-denied step through `Orchestrator.execute()`. The Orchestrator remains responsible for registry enforcement, PolicyGate, durable authorization when required, audit, single-use execution context, Evidence Vault, receipt, and fail-closed behavior.

For email, local metadata runs independently. Exposure and optional domain DNS are separate `PASSIVE_WEB` steps. No email collector calls DNS privately.

## VERIFY

Run `python -m osint_lab verify-audit <case_id>`. The tamper-evident JSONL chain returns validity, entry count, reason, and head hash. Receipts in the private report bind executions to evidence references and the corresponding audit head.

## REPORT

The normal run produces private JSON and HTML reports and stores evidence copies in the vault. Run `python -m osint_lab report <case_id>` to regenerate both formats from the latest private JSON model without rerunning collectors.

Reports distinguish technical metadata, possible candidates, unknowns, source-specific absence, and contradictions. They do not establish account ownership, merge identities, or produce AI verdicts.

## WINDOWS DESKTOP

Run `LUMIR_OSINT_LAB.cmd` or create the Desktop shortcut with `CREATE_DESKTOP_SHORTCUT.ps1`. The Tkinter adapter accepts any non-empty subset of phone, email, username, and domain, creates a private case automatically, and invokes the same application services and CaseRunner as the CLI. `PASSIVE_WEB` is off by default. The UI provides progress, a factual result summary, and validated actions to open the generated HTML report or private case folder.

## MVP boundary

IMPLEMENTED: local private cases, deterministic planning/dry-run, guarded sequential execution, evidence/receipts, finding counts, contradiction inclusion, JSON/HTML reporting, hashes, audit verification, a thin CLI, and a thin Tkinter Windows adapter with launcher and shortcut creation script.

PLANNED: review workflow, budgets/rate limits, redacted exports, encryption, and richer run history selection.

NOT IMPLEMENTED: PDF, installer/updater, Tor, Holehe, PhoneInfoga, HIBP, paid APIs, browser automation, persistent background workers, scheduler, distributed execution, AI verdicts, or automatic identity merging.
