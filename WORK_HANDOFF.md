# LUMIR OSINT LAB — work handoff

## Current Status
Etap 15 Source Expansion Pro v1 is implemented and verified on `feature/osint-lab-v1`. `SourceRegistry` contains 14 explicit reviewed candidates: 10 enabled and 4 conservatively disabled. New Orchestrator-only adapters cover exact public email occurrences, IANA-bootstrapped RDAP, SSRF-guarded website/TLS metadata, exact structured company pages, bounded PDF/TXT/HTML intelligence and Common Crawl temporal candidates. Source roles, reputation, diversity, corroboration, provider health, private bounded cache, per-case/provider/host request limits, controlled auto-pivot modes and per-entity coverage are integrated with Evidence, Knowledge Graph, dossier, HTML/JSON and Desktop summary. Audit/receipt privacy and SHIELD remain unchanged.

## Last Verified Commit
Etap 15 runtime controls are recorded in `126481a`, public adapters in `66ee509`, and coverage/benchmark regressions in `f48c536`; branch baseline for this stage was `063f5db`. This documentation and handoff closeout is the current branch HEAD.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`, phonenumbers `9.0.34`, dnspython `2.8.0`, requests `2.34.2`, pypdf `6.19.0`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Focused Etap 15 source expansion suite PASS (`26 passed`). Final verification: `python -m pytest -q` PASS (`351 passed in 18.77s`); `python test_shield.py` RC6 PASS (`5/5`, exit `0`); `python -m pyflakes osint_lab tests` PASS; `git diff --check` PASS. The complete suite is offline: source adapters use injected synthetic HTTP/RDAP/document fixtures, reserved `.test` domains and synthetic identifiers.

## What Works
The workflow is `SourceRegistry -> EnrichmentBus -> PolicyGate/CollectorRegistry -> Orchestrator -> Evidence/Receipt -> explicit graph adapters -> Correlation/Hypothesis/Adversarial Review -> Dossier`. Enabled sources must pass the hard public/no-login/automation/no-key/free/implemented review. Discovery never becomes evidence by itself. Accepted source observations create evidence-backed cross-type paths and `ENTITY_DISCOVERED` events; unknown/rejected observations create no positive edge. Source independence, reputation and age remain separate. Automatic pivots are limited to reviewed LOCAL/PASSIVE_WEB sources, `max_hops=2`, `max_auto_pivots=6`, bounded network requests, privacy threshold and durable duplicate fingerprints. Provider health and cache are private outside Git. GUI/report expose SOURCE COVERAGE.

## Known Problems
The runner is sequential and has no cancellation/resume, scheduler or background jobs. Reports, cache, provider health, graph and Evidence Vault remain private plaintext. Request accounting uses conservative per-enricher reservations, not packet-level transport counters. DuckDuckGo HTML remains the only enabled general search discovery channel and may drift, challenge or return incomplete coverage; parser uncertainty becomes UNKNOWN. GitHub/GitLab coverage remains deliberately limited to stable public profile signals. CT, generic public directories/company registries and Wayback CDX remain disabled pending source-specific review. PDF is text-only with no OCR. Exact normalization intentionally avoids fuzzy/ML entity merge. Benchmark Arena has 20 synthetic fixtures but no standalone CLI. Scores are explainable heuristics, not probability or truth.

## Architecture Decisions
`SourceDefinition` is versioned and hash-bound; unclear means disabled. Source role and reputation do not promote evidence. RDAP endpoint discovery starts at IANA and registrant redaction remains UNKNOWN. CT is discovery-only by design and currently disabled. Website/document access reuses Etap 13 SSRF, redirect, size and peer-IP controls. Documents execute no JavaScript, macro, archive or embedded file. Common Crawl provides historical candidates only. Company names are never aggressively merged; shared usernames never imply identity. The bus cannot invoke a collector outside the existing Orchestrator path. Raw identifiers stay in private evidence/report/cache, while audit and receipts retain references/hashes.

## Current Task
Etap 15 is verified for publication on `feature/osint-lab-v1` without force push. `shield/` is unchanged, no real user identifier or secret was added, all tests are offline, and no merge to `main` was performed.

## Next Task
Define the next stage explicitly. Safe priorities are a manual analyst UI for pivot/reviewer decisions, a frozen CLI benchmark runner and encryption-at-rest design. Any additional provider requires a new hard source review. Do not introduce autonomous identity verification, fuzzy entity merging, login/recovery probing, CAPTCHA bypass or collector bypasses.

## Files Changed
Etap 15 adds `osint_lab/sources`, six public source collectors/adapters, stricter TargetPageFetcher metadata support, graph projection/coverage/corroboration, provider health, request limits/cache, 10 additional benchmark fixtures, GUI/report coverage, offline regressions and source documentation. No file under `shield/` is modified.

## Safety Notes
All Etap 15 tests use synthetic identifiers, reserved `.test` domains, injected responses and local PDF/HTML fixtures; no live provider request or user case data is used. Login, signup/recovery, stolen breach datasets, Tor, CAPTCHA bypass, credentials, paid APIs and direct-target interaction are absent. Audit and receipts contain references/hashes rather than raw identifiers. Case manifests, provider health, cache, reports, graph, audit, authorization and Evidence Vault remain outside Git under the configured private case root. Private artifacts remain plaintext.
