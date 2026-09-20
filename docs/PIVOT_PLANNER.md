# Pivot Planner v1

## IMPLEMENTED

`PivotPlanner` returns recommendations only. Each `PivotCandidate` records source entity, proposed collector/input, source class, expected information gain, privacy cost, network cost, duplication risk, reason, and status. V1 recommends a public-web phone pivot only when `PASSIVE_WEB` is authorized, blocks it otherwise, recommends new local email metadata, and marks an identical completed DNS/email step `LOW_VALUE`.

The planner does not invoke collectors and cannot bypass CaseManifest, PolicyGate, Registry, Orchestrator, or authorization.

## PLANNED

- More entity-discovery rules, retry-later signals, and budget-aware ranking.
- Reviewer selection and persisted pivot disposition.

## NOT IMPLEMENTED

- Automatic execution, new network collectors, Tor, browser automation, Holehe, or PhoneInfoga.
