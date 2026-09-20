# LUMIR OSINT LAB — work handoff

## Current Status
Etap 11 Intelligence Core v1 is implemented on `feature/osint-lab-v1`. The deterministic post-collection pipeline assesses evidence quality and independence, proposes conservative correlations/hypotheses, challenges them adversarially, recommends non-executing pivots, creates an IntelligenceSummary, and renders private report schema `1.2`. Collector behavior, audit, receipts, PolicyGate/Registry/Orchestrator, and SHIELD remain unchanged.

## Last Verified Commit
Published Etap 10 plus Phone Report Details baseline: `c306059`; branch baseline `main`: `d881757`. Use `git log -1` for the Etap 11 commit after publication.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`, phonenumbers `9.0.34`, dnspython `2.8.0`, requests `2.34.2`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Focused Intelligence Core plus CaseRunner/report suite PASS (`35 passed`). Final verification: `python -m pytest -q` PASS (`226 passed in 14.56s`); `python test_shield.py` RC6 PASS (`5/5`, exit `0`); `git diff --check` PASS; scoped pyflakes PASS. Tests cover scoring explanations, copied-source clustering, contradiction penalties, reviewer-only promotion, deterministic adversarial challenges, pivot policy/costs, full CaseRunner integration, report separation, and overclaim guards.

## What Works
The full authorized workflow now runs `Desktop/CLI -> CaseManifest -> Plan -> PolicyGate/Registry -> Orchestrator -> Collectors -> Evidence/Receipts -> Aggregation/Contradictions -> Intelligence Core -> JSON/HTML Report -> Audit verification`. CaseRunner never calls `_run()`. Evidence copies do not inflate corroboration; hypotheses and correlations cannot self-promote to verified/confirmed; pivots never execute automatically. Reports remain private vault-backed artifacts. Audit stores seed hashes rather than raw seeds. PASSIVE_WEB is off by default in the desktop form.

## Known Problems
The runner is sequential and has no budgets, cancellation/resume, scheduler, or persistent background jobs. Reports are private plaintext. ReviewerDecision has validated data/gating but no durable review store or UI. V1 source clustering uses deterministic exact heuristics, not semantic ML. Scores are explainable heuristics, not probability or truth. Existing collector limitations remain: public signals and technical metadata do not establish owner or identity.

## Architecture Decisions
Plans are advisory and transparent, while Orchestrator enforcement remains authoritative at execution time. Policy-denied steps are submitted only to record the denial; their collectors do not run and source exposure remains zero. Email-derived DNS is a separate dependent step and is never invoked from an email collector. A report write or audit verification failure cannot return full `SUCCESS`. Desktop and CLI construction plus manifest policy live in one shared application module; GUI status callbacks are observational and do not control execution.

## Current Task
Commit the verified Etap 11 changes, confirm a clean tree, and publish `feature/osint-lab-v1` without force push.

## Next Task
Design durable append-only ReviewerDecision storage and a manual review workflow before any dossier/export layer. Do not add automatic identity inference.

## Files Changed
Etap 11 adds `osint_lab/intelligence/`, analytical report integration, focused deterministic tests, and the seven Intelligence Core documents. No collector, audit, receipt, or file under `shield/` is modified.

## Safety Notes
End-to-end tests use only synthetic identifiers and reserved `.test` domains with mocked DNS/HTTP; no user case data or public request is used. Case manifests, plans, run summaries, reports, audit, authorization history, and evidence must remain outside Git under their configured `%LOCALAPPDATA%\LumirOSINTLab` roots. The private vault remains plaintext.
