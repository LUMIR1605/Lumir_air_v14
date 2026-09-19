# LUMIR OSINT LAB — work handoff

## Current Status
Foundation v3 is implemented on `feature/osint-lab-v1`: scoped RunAuthorization, mandatory PolicyGate enforcement in the Orchestrator, append-only local audit logging, single-use ExecutionContext, and Collector Contract v1. Only synthetic test collectors exist. SHIELD RC6 code was not changed.

## Last Verified Commit
Implementation and tests through `8f42ccb`; full suite verified before this documentation update. Branch baseline `main`: `d881757`. Use `git log -1` for the latest documentation commit.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Windows verification: foundation v2 baseline `40 passed`; foundation v3 `python -m pytest -q` PASS (`61 passed`, 21 new cases). `python test_shield.py` PASS (`5/5`, exit `0`). New tests cover LOCAL/PASSIVE_WEB allow paths, missing and mismatched risky-source approvals, expiry, revocation, case/agent/source binding, DENY/SUCCESS/FAILED audit events, append behavior, secret-like metadata rejection, `CONFIRMED` prevention, and public bypass attempts.

## What Works
The Orchestrator is the public collector execution path. It evaluates CaseManifest and PolicyGate, requires a matching unexpired approval for risky classes, writes audit decisions, issues a one-use context, executes the collector, normalizes non-final candidates, and records completion or failure. Raw request values are represented in audit metadata by SHA-256 hashes. No path under `shield/` differs from `main`.

## Known Problems
Approvals are in-memory objects without signatures, durable lookup, or trusted approver identity. JSONL is append-only through the API but not tamper-proof and has no hash chain or locking. Python contract controls are not a sandbox against hostile code importing private internals. Vault encryption, permission hardening, retention, graph persistence, production collectors, GUI and installer validation remain unimplemented.

## Architecture Decisions
Manifest permission and per-run approval are separate controls: authorization cannot override PolicyGate. LOCAL and allowed PASSIVE_WEB need no per-run record; THIRD_PARTY_API, TOR and DIRECT_TARGET require an exact approved record. Collector `run()` is inherited and context-guarded; subclasses implement protected `_run()`. Audit failure prevents context issuance. Synthetic collectors remain test-only.

## Current Task
Foundation v3 is implemented and locally verified. Run final pytest, RC6 smoke and diff checks, then publish `feature/osint-lab-v1` without force push.

## Next Task
Review the execution-control foundation before adding any real collector. Next design work should cover durable/signed approvals, audit integrity and locking, collector registry/provenance, process isolation, and Evidence Vault integration. Do not start PhoneMetadataCollector until those boundaries are accepted.

## Files Changed
Foundation v3 adds authorization, execution context, audit and orchestrator modules; replaces the legacy `collect()` contract with guarded Collector Contract v1; adds `tests/test_osint_orchestrator.py` and four focused documents; and updates architecture plus this handoff. No file under `shield/` is modified.

## Safety Notes
Only synthetic references and collectors were added. No test collector performs network access. Audit logs belong outside Git under `%LOCALAPPDATA%/LumirOSINTLab/audit` or another reviewed disjoint root and are not immutable. Existing vault data remains plaintext. Git history may retain an old revoked key: never reuse it and confirm rotation independently.
