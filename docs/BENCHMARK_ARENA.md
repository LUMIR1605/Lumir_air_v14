# Benchmark Arena Foundation v1

## IMPLEMENTED

`benchmarks/osint_lab/` contains twenty synthetic truth-labelled cases. The original ten cover clean phone/company, copied directories, username collision, stale relation, contradictory records, circular evidence, false numeric ID, multi-hop phone/web/email/domain, independent confirmations and no evidence. Etap 15 adds multi-source confirmation, first-party plus copied directories, stale archive versus current web, shared username collision, phone reuse over time, domain ownership change, conflicting email, old document contacts, zero results and provider failure. Fixtures use reserved `.test` domains and synthetic identifiers only.

`score_benchmark()` additionally reports verified evidence, unique source classes, useful entities/pivots, provider failure rate and network requests per useful finding. `compare_source_expansion()` requires higher coverage, no false-positive regression, non-decreasing independence and non-decreasing useful pivots. The synthetic A/B regression is `1 -> 2` verified evidence with `0 -> 0` false positives.

## PLANNED

- A command-line runner and frozen expected graph snapshots.

## NOT IMPLEMENTED

- Competitor superiority claims, production identifiers or live-network benchmark calls.
