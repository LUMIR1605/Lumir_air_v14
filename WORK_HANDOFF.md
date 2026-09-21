# LUMIR OSINT LAB — work handoff

## Current Status
Stage 15.2 Real Discovery Bootstrap PRO is implemented and verified on `feature/osint-lab-v1`. The production discovery path now has the official credential-gated Brave Search API plus independent DuckDuckGo HTML fallback under one bounded engine. PHONE, EMAIL, COMPANY and the optional USERNAME layer use entity-specific query matrices, per-request budgets, URL/domain/result deduplication and conservative target ordering. Search results remain non-evidence; the existing fetch, SSRF/redirect and exact target-validation path is unchanged. A synthetic multi-provider PHONE case executes real hop 1 and hop 2. Audit/receipt privacy and SHIELD remain unchanged.

## Last Verified Commit
The core provider/collector implementation is `76a0fd1`; discovery coverage, Case Events, report/GUI and E2E are `7d08868`. The Stage 15.1 baseline was `1fb6019`.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`, phonenumbers `9.0.34`, dnspython `2.8.0`, requests `2.34.2`, pypdf `6.19.0`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Focused multi-provider/provider-failure/PHONE E2E gate PASS (`20 passed`). Final verification: `python -m pytest -q` PASS (`371 passed in 8.90s`); `python test_shield.py` RC6 PASS (`5/5`, exit `0`); `python -m pyflakes osint_lab tests` PASS; `git diff --check` PASS. The complete suite is offline and uses injected JSON/HTML, reserved `.test` domains, documentation IP ranges and synthetic identifiers.

## What Works
The runtime remains `initial collection -> graph projection -> pivot planning -> eligible AUTO execution -> graph projection -> replanning -> final intelligence/dossier`. Every pivot remains `PolicyGate -> SourceRegistry -> EnrichmentBus -> CollectorRegistry/Orchestrator -> Evidence/Receipt`. Brave reads only `LUMIR_BRAVE_SEARCH_API_KEY`; missing/rejected credentials are `AUTH_REQUIRED`. DDG continues independently. Defaults are 8 queries/entity, 6/provider, 10 results/query, 30 candidates, 15 domains and 3 candidates/domain, with the existing 24-request case budget still authoritative. Coverage and the private report expose real provider/query/request/candidate counts, per-provider status and verified/rejected target counts. Case Events record query plan/execution, result hashes, provider failure and target verification without keys or raw query values.

## Known Problems
The runner and auto loop are sequential and have no cancellation/resume, scheduler or durable queue. Reports, cache, provider health, graph and Evidence Vault remain private plaintext. Brave needs a user-provisioned account/key and its external plan, quota, retention and availability can change; the implementation performs no retries or quota purchase. DDG HTML may drift, challenge or return incomplete coverage. Provider ranking only orders validation and is not truth/confidence. CT, generic public directories/company registries and Wayback CDX remain disabled. PDF is text-only with no OCR. Exact normalization avoids fuzzy/ML entity merge. Benchmark Arena has 21 synthetic fixtures but no standalone CLI.

## Architecture Decisions
`SourceDefinition` is versioned and hash-bound; Brave's configuration hash includes only `api_key_present`. Unclear means disabled and source role/reputation never promotes evidence. Search candidates are never evidence. Target access reuses Etap 13 SSRF, redirect, size and peer-IP controls. Company names are never aggressively merged and shared usernames never imply identity. Raw identifiers stay in private evidence/report/cache, while audit, receipts and Case Events retain references/hashes.

## Current Task
Stage 15.2 is verified locally for publication on `feature/osint-lab-v1` without force push. `shield/` is unchanged from `1fb6019`; no real user identifier, API key or secret was added; no live provider request is used by tests; no merge to `main` was performed.

## Next Task
Optionally configure `LUMIR_BRAVE_SEARCH_API_KEY` outside Git and run one explicitly authorized private acceptance case, then manually review provider quota/privacy status and verified target quality. A later explicit stage may add cancellation/resume, encryption-at-rest or another reviewed provider.

## Files Changed
Stage 15.2 adds the discovery engine and Brave/DDG adapters, integrates four entity paths, extends source registry/coverage, Case Events, report/Desktop metrics, one benchmark fixture, focused documentation and an offline multi-provider two-hop E2E. No GUI framework or file under `shield/` is modified.

## Safety Notes
All Etap 15.2 tests use synthetic identifiers, reserved `.test` domains, injected responses and local HTML/JSON fixtures; no live provider request or user case data is used. No API key is stored in Git, logs, audit, receipts or fixtures. Login, signup/recovery, stolen datasets, Tor, CAPTCHA bypass and direct-target interaction are absent. Brave and DDG receive a query only when actually executed in an authorized PASSIVE_WEB case. Private artifacts remain plaintext outside Git.
