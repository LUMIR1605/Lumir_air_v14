# LUMIR OSINT LAB — work handoff

## Current Status
Etap 14 Knowledge Graph + Enrichment Bus Pro v1 is implemented and verified on `feature/osint-lab-v1`. Each case can persist an exact-normalized, provenance-bearing SQLite graph outside Git. The Enrichment Bus routes eligible pivots through the existing PolicyGate, registry and Orchestrator; it cannot execute collectors directly. Multi-hop planning is bounded by hop, pivot and conservative network-request budgets, with durable loop fingerprints. Private report schema is `1.5` and includes the graph dossier, timeline, paths, hypotheses, contradictions and next pivots. JSON, GraphML and a minimal offline graph viewer are generated without exposing evidence bodies. Audit/receipt privacy and SHIELD remain unchanged.

## Last Verified Commit
Etap 14 implementation is recorded in `33aa1ef`, `95e5cdd` and `f43f1fe`, with architecture documentation in `628afea`; branch baseline for this stage was `56209c3`. This handoff closeout is the current branch HEAD.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`, phonenumbers `9.0.34`, dnspython `2.8.0`, requests `2.34.2`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Focused graph/enrichment/review/dossier/Desktop suite PASS (`34 passed in 2.08s`). Final verification: `python -m pytest -q` PASS (`325 passed in 26.24s`); `python test_shield.py` RC6 PASS (`5/5`, exit `0`); `python -m pyflakes osint_lab tests` PASS; `git diff --check` PASS. Graph and enrichment tests use synthetic inputs, reserved `.test` domains and injected collector behavior; they do not perform live discovery.

## What Works
The authorized workflow is now `Desktop/CLI -> CaseManifest -> Plan/EnrichmentBus -> PolicyGate/Registry -> Orchestrator -> Collectors -> Evidence/Receipts -> Intelligence Core -> Graph projection/analysis -> Dossier/JSON/HTML/GraphML/Viewer -> Audit verification`. Case seeds and accepted collector observations are projected through explicit adapters; rejected or unknown observations do not create positive relations. Entity deduplication is exact after type-aware normalization and never uses fuzzy auto-merge. Every positive relation carries evidence, source and independence references. Path confidence uses the weakest link plus transparent penalties for copied, circular, stale or contradictory support. `CONFIRMED` relations and `VERIFIED` identity candidates require an append-only reviewer decision. Case events, graph versions and reproducibility records preserve collector versions, provider/policy hashes, timestamps and evidence references. The Desktop can open the validated offline viewer.

## Known Problems
The runner is sequential and has no cancellation/resume, scheduler, persistent background jobs or durable provider health. Pivot proposals are not auto-approved or auto-executed; reviewer decisions have a durable append-only store but no dedicated review UI. Reports, the graph database and the Evidence Vault remain private plaintext. Network-request budgets reserve conservative per-enricher maxima and are not packet-level counters. Entity matching is exact and intentionally has no fuzzy/ML resolution. Benchmark Arena has ten synthetic fixtures and metric helpers but no standalone CLI. DuckDuckGo HTML remains the only enabled discovery provider and may change markup, throttle, challenge or return incomplete coverage. Scores remain explainable heuristics, not probability or truth; no cryptographic reviewer signatures are implemented.

## Architecture Decisions
The Enrichment Bus proposes and routes work but never bypasses Orchestrator enforcement. Policy-denied steps are submitted only to record the denial; their collectors do not run and source exposure remains zero. Persistent pivot fingerprints suppress loops across reloads. Graph writes use SQLite transactions, foreign keys, WAL/FULL synchronization, deterministic identifiers and append-only event/history tables. Accepted evidence adapters are explicit and conservative. Source independence is tracked separately from source count. Reviewer actions reference graph objects and evidence hashes without placing raw PII or review notes in audit. GraphML and the viewer contain graph metadata and evidence references, not Evidence Vault bodies. A graph/report write or audit verification failure cannot return full `SUCCESS`.

## Current Task
Etap 14 is verified for publication on `feature/osint-lab-v1` without force push. `shield/` is unchanged, no real user identifier or secret was added, and no merge to `main` was performed.

## Next Task
Define the next stage explicitly before implementation. Safe priorities are a manual analyst UI for pivot approval and reviewer decisions, plus a CLI benchmark runner. Do not introduce autonomous identity verification, fuzzy entity merging, collector bypasses or unsafe phone probing.

## Files Changed
Etap 14 adds graph models/normalization/storage, analytics, projection, enrichment routing, runtime, dossier/export/viewer generation, Benchmark Arena fixtures, report/GUI integration, architecture documentation and offline regressions. `CaseRunner`, application construction, reporting and Desktop integration are extended additively. No file under `shield/` is modified.

## Safety Notes
End-to-end tests use only synthetic identifiers and reserved `.test` domains with mocked collector behavior; no user case data or public request is used. Graph projection accepts only explicit supported observation semantics, and discovery snippets cannot become accepted evidence. Audit and receipt artifacts retain hashes/references rather than raw identifiers. Case manifests, plans, run summaries, reports, graph databases, audit, authorization history and evidence must remain outside Git under configured private case roots such as `%LOCALAPPDATA%\LumirOSINTLab`. The private graph and vault remain plaintext.
