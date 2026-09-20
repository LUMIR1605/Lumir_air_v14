# Pivot Planner v1

## IMPLEMENTED

`PivotPlanner` returns recommendations only. Each `PivotCandidate` records source entity, proposed collector/input, source class, expected information gain, privacy cost, network cost, duplication risk, reason, and status. V1 recommends a public-web phone pivot only when `PASSIVE_WEB` is authorized, blocks it otherwise, recommends new local email metadata, and marks an identical completed DNS/email step `LOW_VALUE`.

The planner does not invoke collectors and cannot bypass CaseManifest, PolicyGate, Registry, Orchestrator, or authorization.

`GraphPivotPlanner` extends recommendations to every eligible graph node, ranks them by explainable graph value, enforces finite case budgets and marks fingerprints already present in persistent pivot history as `SUPPRESSED_DUPLICATE`. `EnrichmentBus` is the separate guarded execution adapter and still delegates to Orchestrator.

## PLANNED

- More entity-discovery rules and retry-later signals.
- Reviewer selection and persisted pivot disposition.

## NOT IMPLEMENTED

- Automatic execution, new network collectors, Tor, browser automation, Holehe, or PhoneInfoga.
