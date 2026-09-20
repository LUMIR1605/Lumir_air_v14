# Benchmark Arena Foundation v1

## IMPLEMENTED

`benchmarks/osint_lab/` contains ten synthetic truth-labelled cases: clean phone/company, copied directories, username collision, stale relation, contradictory records, circular evidence, false numeric ID, multi-hop phone/web/email/domain, independent confirmations and no evidence. Fixtures use reserved `.test` domains and the synthetic phone fixture only.

`score_benchmark()` reports precision, false positives, rejected false positives, unknowns, relation/hypothesis accuracy, independent evidence count, pivot efficiency, graph size and execution time.

## PLANNED

- A command-line runner and frozen expected graph snapshots.

## NOT IMPLEMENTED

- Competitor superiority claims, production identifiers or live-network benchmark calls.
