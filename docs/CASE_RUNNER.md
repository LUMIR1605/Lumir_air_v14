# CaseRunner MVP

## IMPLEMENTED

`CaseRunner` is the application layer above the existing registry, PolicyGate, Orchestrator, audit, Evidence Vault, and receipts. It never calls `Collector._run()` and never creates an execution context. Every normal or denied collector step is submitted through `Orchestrator.execute()`; the Orchestrator repeats registry and policy enforcement before any collector can run.

The deterministic `CaseExecutionPlan` contains the case ID, creation time, requested seed types, planned/skipped/denied steps, warnings, and currently available registered collectors. Each executable step contains a stable order, seed reference/type, collector name, source class, reason, and dependencies.

MVP mapping:

- `PHONE -> phone_metadata -> phone_public_web`
- `DOMAIN -> domain_dns`
- `USERNAME -> username_lookup`
- `EMAIL -> email_local_metadata -> email_exposure`
- email domain -> `domain_dns` as a separate orchestration-level step dependent on local email validation

The phone public-web and email DNS follow-up steps are separately registry-validated and PolicyGate-evaluated. When `PASSIVE_WEB` is disabled, local phone metadata still runs while `phone_public_web` is recorded as `DENIED` without search or target HTTP. When enabled, the phone collector internally performs bounded discovery and target verification as one authorized execution. Desktop progress reports search, source verification, evidence analysis and report generation without changing enforcement.

Duplicate seeds are skipped deterministically. Unknown seed types, invalid inputs, and unavailable/unregistered collectors are explicit skipped steps with warnings. `dry_run=True` builds and optionally stores the plan without collector execution, audit events, network calls, evidence publication, or receipts.

`CaseRunResult` aggregates execution records, receipts, finding counts for every existing `FindingStatus`, contradiction results, warnings, audit verification, and the report reference. `PARTIAL` is used when successful work is mixed with denied/failed/unknown results. Infrastructure exceptions stop later execution and cannot produce `SUCCESS`.

## PLANNED

- Interactive approval UX for source classes that require durable per-run authorization.
- Explicit configurable budgets, rate limits, cancellation, and resume semantics.
- Reviewed plan signing/versioning and a stable machine-readable compatibility policy.

## NOT IMPLEMENTED

- Direct/private collector execution, background workers, scheduler, distributed execution, or automatic retries.
- Automatic identity merge, ownership inference, AI verdicts, or conversion of collector output to `CONFIRMED` identity.
- Holehe, PhoneInfoga, HIBP, Tor, browser automation, private/paid APIs, or login/recovery probes.
