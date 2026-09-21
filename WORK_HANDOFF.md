# LUMIR OSINT LAB — work handoff

## Current Status
Stage 15.1 Real Multi-Hop Execution is implemented and verified on `feature/osint-lab-v1`. Initial collectors are projected before planning; eligible AUTO pivots execute through the unchanged PolicyGate, SourceRegistry, EnrichmentBus and Orchestrator path; every completed batch is projected before replanning. Real hop 1 and hop 2 executions are included in `CaseRunResult`, Evidence/receipts and the private report. Source coverage now uses explicit execution mappings and separates direct from downstream sources. Audit/receipt privacy and SHIELD remain unchanged.

## Last Verified Commit
Stage 15.1 runtime is recorded in `2948f92` and the offline integration gate in `66eefde`; the Stage 15 baseline was `361db51`. This documentation and handoff closeout is the current branch HEAD.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`, phonenumbers `9.0.34`, dnspython `2.8.0`, requests `2.34.2`, pypdf `6.19.0`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Focused Stage 15.1 integration/CaseRunner/Graph/Desktop regression PASS (`40 passed`). Final verification: `python -m pytest -q` PASS (`355 passed in 22.69s`); `python test_shield.py` RC6 PASS (`5/5`, exit `0`); `python -m pyflakes osint_lab tests` PASS; `git diff --check` PASS. The complete suite is offline: multi-hop tests use synthetic collectors, reserved `.test` domains and documentation-only identifiers.

## What Works
The runtime is `initial collection -> graph projection -> pivot planning -> eligible AUTO execution -> graph projection -> replanning -> final intelligence/dossier`. Every pivot remains `PolicyGate -> SourceRegistry -> EnrichmentBus -> CollectorRegistry/Orchestrator -> Evidence/Receipt`; there is no direct collector path. Automatic pivots are limited to reviewed LOCAL/PASSIVE_WEB sources, `max_hops=2`, `max_auto_pivots=6`, `max_network_requests=24`, privacy threshold `0.6` and durable fingerprints. Local derivation can remain on its current hop so WEBSITE -> EMAIL local metadata can expose a DOMAIN before hop 2. `MultiHopExecutionSummary`, HTML/JSON and Desktop show real counts and stop reason. Coverage uses stored collector/enricher/source IDs; `phone_public_web` maps to `duckduckgo_html` and downstream eligibility is not reported as direct execution.

## Known Problems
The runner and auto loop are sequential and have no cancellation/resume, scheduler, durable queue or automatic retry. Reports, cache, provider health, graph and Evidence Vault remain private plaintext. Request accounting uses conservative per-enricher reservations, not packet-level transport counters. The report path is private and therefore includes pivot inputs; audit and receipts remain reference/hash-only. DuckDuckGo HTML remains the only enabled general search discovery channel and may drift, challenge or return incomplete coverage; parser uncertainty becomes UNKNOWN. CT, generic public directories/company registries and Wayback CDX remain disabled pending source-specific review. PDF is text-only with no OCR. Exact normalization intentionally avoids fuzzy/ML entity merge. Benchmark Arena has 20 synthetic fixtures but no standalone CLI. Scores are explainable heuristics, not probability or truth.

## Architecture Decisions
`SourceDefinition` is versioned and hash-bound; unclear means disabled. Source role and reputation do not promote evidence. RDAP endpoint discovery starts at IANA and registrant redaction remains UNKNOWN. CT is discovery-only by design and currently disabled. Website/document access reuses Etap 13 SSRF, redirect, size and peer-IP controls. Documents execute no JavaScript, macro, archive or embedded file. Common Crawl provides historical candidates only. Company names are never aggressively merged; shared usernames never imply identity. The bus cannot invoke a collector outside the existing Orchestrator path. Raw identifiers stay in private evidence/report/cache, while audit and receipts retain references/hashes.

## Current Task
Stage 15.1 is verified locally for publication on `feature/osint-lab-v1` without force push. `shield/` is unchanged from `361db51`, no real user identifier or secret was added, all tests are offline, and no merge to `main` was performed.

## Next Task
Run an authorized synthetic/private acceptance case through the Windows Desktop and manually review the execution path and graph artifacts. A later explicit stage may add analyst execution of `MANUAL_REQUIRED` pivots, cancellation/resume or encryption-at-rest. Any additional provider still requires a new hard source review.

## Files Changed
Stage 15.1 changes CaseRunner/graph execution, source mapping/coverage, report/Desktop metrics, four focused documentation files and an offline multi-hop integration gate. No collector provider, GUI framework, graph model or file under `shield/` is added or modified.

## Safety Notes
All Etap 15 tests use synthetic identifiers, reserved `.test` domains, injected responses and local PDF/HTML fixtures; no live provider request or user case data is used. Login, signup/recovery, stolen breach datasets, Tor, CAPTCHA bypass, credentials, paid APIs and direct-target interaction are absent. Audit and receipts contain references/hashes rather than raw identifiers. Case manifests, provider health, cache, reports, graph, audit, authorization and Evidence Vault remain outside Git under the configured private case root. Private artifacts remain plaintext.
