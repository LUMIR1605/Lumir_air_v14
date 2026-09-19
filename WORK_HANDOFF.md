# LUMIR OSINT LAB — work handoff

## Current Status
Etap 9 MVP is implemented on `feature/osint-lab-v1`: private case storage, deterministic execution plans and dry-run, guarded CaseRunner execution, finding/receipt aggregation, contradiction inclusion, JSON/HTML reports, report hashes/evidence, audit verification, and `python -m osint_lab` CLI. No collector or Etap 4 enforcement path was replaced. SHIELD RC6 code was not changed.

## Last Verified Commit
Etap 8 baseline `d5ac7dd`; branch baseline `main`: `d881757`. Use `git log -1` for the latest Etap 9 commit after publication.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`, phonenumbers `9.0.34`, dnspython `2.8.0`, requests `2.34.2`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Final Etap 9 Windows verification: focused CaseRunner/Report/CLI suite PASS (`14 passed`); `python -m pytest -q` PASS (`192 passed in 7.90s`); `python test_shield.py` RC6 PASS (`5/5`, exit `0`); CLI help and `git diff --check` PASS. The end-to-end suite mocks DNS and all HTTP and requires no internet.

## What Works
The full authorized workflow now runs `CaseManifest -> Plan -> PolicyGate/Registry -> Orchestrator -> Collectors -> Evidence/Receipts -> Aggregation/Contradictions -> JSON/HTML Report -> Audit verification`. CaseRunner never calls `_run()` and separately plans email local, exposure, and domain DNS steps. Reports are private case artifacts, SHA-256 hashed, and stored in Evidence Vault before direct publication. Audit stores seed hashes rather than raw seeds.

## Known Problems
The runner is sequential and has no budgets, cancellation/resume, scheduler, or background workers. Reports are private and plaintext; encryption, redacted export, PDF, signatures, and external audit witnessing remain unimplemented. Contradictions are deterministic inclusions from explicit assertions, not automated resolution. Existing collector limitations remain: public signals and technical metadata do not establish owner or identity.

## Architecture Decisions
Plans are advisory and transparent, while Orchestrator enforcement remains authoritative at execution time. Policy-denied steps are submitted only to record the denial; their collectors do not run and source exposure remains zero. Email-derived DNS is a separate dependent step and is never invoked from an email collector. A report write or audit verification failure cannot return full `SUCCESS`.

## Current Task
CaseRunner, storage, plan/dry-run, report engine, CLI, offline end-to-end tests, documentation, final pytest, RC6, diff/privacy/case-data/shield checks, and logical commits are complete. Publish `feature/osint-lab-v1` without force push.

## Next Task
Exercise the private CLI workflow with an explicitly authorized synthetic case. Next product step should be review/redacted export and budgets/rate limits, not new collectors or identity automation.

## Files Changed
Etap 9 adds `case_runner.py`, `case_storage.py`, report engine, module CLI, offline MVP tests, and four workflow documents, and updates architecture/handoff. No file under `shield/` is modified.

## Safety Notes
End-to-end tests use only synthetic identifiers and reserved `.test` domains with mocked DNS/HTTP; no user case data or public request is used. Case manifests, plans, run summaries, reports, audit, authorization history, and evidence must remain outside Git under their configured `%LOCALAPPDATA%\LumirOSINTLab` roots. The private vault remains plaintext.
