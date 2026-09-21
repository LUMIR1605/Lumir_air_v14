# Multi-Hop Pivots v1

## IMPLEMENTED

`GraphPivotPlanner` scans all graph nodes and ranks eligible enrichers by expected information gain plus explainable graph value: isolated-cluster connection, open-hypothesis testing and contradiction resolution. Each proposal records privacy/network cost, duplication risk, hop and execution fingerprint.

Safe defaults limit hops, pivots, network requests, entities, relations, enrichments per entity and repeated provider queries. The bus reserves a conservative per-enricher request ceiling before network work; each collector retains its own tighter internal request limits. Persistent fingerprint history suppresses loops and identical input/provider work. Planning remains side-effect free; execution is owned by the bounded `EnrichmentExecutionLoop`.

## STAGE 15.1 — IMPLEMENTED

`CaseRunner` projects the initial batch, asks `GraphPivotPlanner` for proposals and executes only `AUTO` proposals through `PolicyGate -> SourceRegistry -> EnrichmentBus -> Orchestrator`. Each completed execution is appended to `CaseRunResult.executions` and projected before the next planning pass. Local derivation may remain on the current hop; network pivots advance the hop. The loop stops on no new work, `max_hops`, automatic pivot budget, request budget or policy blocking.

`MultiHopExecutionSummary` records initial/automatic counts, hop 0/1/2 counts, manual and blocked work, duplicate suppression, graph growth, executed sources, reserved requests, the stop reason and the private execution path.

## PLANNED

- Analyst approval UI, freshness-specific pivots and independent-source targeting.

## NOT IMPLEMENTED

- Infinite recursion, scheduler, background execution, automatic retry or “more results” ranking alone.

## ETAP 15 — IMPLEMENTED

Default limits are `max_hops=2`, `max_auto_pivots=6`, `max_network_requests=24`, one persistent fingerprint per entity/enricher/input and privacy threshold `0.6`. SAFE_LOCAL and reviewed PASSIVE_WEB work may be `AUTO`; higher privacy, credentials, paid/unreviewed or direct-target work is `MANUAL_REQUIRED` or `BLOCKED`. Request reservations also apply per provider and host.
