# LUMIR OSINT LAB — work handoff

## Current Status
Etap 12 Phone Public Web Intelligence v1 is implemented on `feature/osint-lab-v1`. PHONE cases now plan local metadata plus a separately gated `PASSIVE_WEB` exact-match collector. Public occurrences feed conservative entity extraction, source-independence clustering, neutral correlations/hypotheses, and non-executing pivots. Private report schema is `1.3`; audit/receipt privacy and SHIELD remain unchanged.

## Last Verified Commit
Etap 11 published baseline: `6cebdbd`; branch baseline `main`: `d881757`. Use `git log -1` for the Etap 12 commit after publication.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`, phonenumbers `9.0.34`, dnspython `2.8.0`, requests `2.34.2`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Focused PhonePublicWeb/CaseRunner/Intelligence/GUI suite PASS (`69 passed in 3.76s`). Final verification: `python -m pytest -q` PASS (`247 passed in 18.04s`); `python test_shield.py` RC6 PASS (`5/5`, exit `0`); `git diff --check` PASS; scoped pyflakes PASS. All network behavior is tested with injected mock HTTP and reserved `.test` sources.

## What Works
The full authorized workflow now runs `Desktop/CLI -> CaseManifest -> Plan -> PolicyGate/Registry -> Orchestrator -> Collectors -> Evidence/Receipts -> Aggregation/Contradictions -> Intelligence Core -> JSON/HTML Report -> Audit verification`. Phone variants are bounded and deduplicated. Only exact public occurrences become MATCH. Same-domain, mirror, identical-content, and identical-payload results do not inflate corroboration. Discovered email/domain/username entities create recommendations only. PASSIVE_WEB remains off by default in the desktop form.

## Known Problems
The runner is sequential and has no budgets, cancellation/resume, scheduler, or persistent background jobs. Reports are private plaintext. The single default public provider can change markup, throttle, challenge, or return incomplete index coverage; those outcomes remain UNKNOWN. No target page fetch follows search results in v1, so extraction is limited to public result material. ReviewerDecision still has no durable store or UI. Scores remain explainable heuristics, not probability or truth.

## Architecture Decisions
Plans are advisory and transparent, while Orchestrator enforcement remains authoritative at execution time. Policy-denied steps are submitted only to record the denial; their collectors do not run and source exposure remains zero. Email-derived DNS is a separate dependent step and is never invoked from an email collector. A report write or audit verification failure cannot return full `SUCCESS`. Desktop and CLI construction plus manifest policy live in one shared application module; GUI status callbacks are observational and do not control execution.

## Current Task
Complete final Etap 12 verification, create logical commits, confirm a clean tree, and publish `feature/osint-lab-v1` without force push. Do not merge to `main`.

## Next Task
After Etap 12 publication, design durable append-only ReviewerDecision storage and a manual review workflow; do not add automatic identity inference or unsafe phone probing.

## Files Changed
Etap 12 adds PhonePublicWebCollector, phone variants/provider/parser/entity models, CaseRunner/Intelligence/Pivot/Report integration, offline mock tests, and three collector documents. No file under `shield/` is modified.

## Safety Notes
End-to-end tests use only synthetic identifiers and reserved `.test` domains with mocked DNS/HTTP; no user case data or public request is used. Case manifests, plans, run summaries, reports, audit, authorization history, and evidence must remain outside Git under their configured `%LOCALAPPDATA%\LumirOSINTLab` roots. The private vault remains plaintext.
