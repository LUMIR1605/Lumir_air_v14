# OSINT LAB orchestrator

## IMPLEMENTED

`osint_lab.orchestrator.service.Orchestrator.execute()` is the public execution path for the collector contract. Its fixed order is:

`CaseManifest → PolicyGate → RunAuthorization check → AuditLog → ExecutionContext → Collector.run()`

`LOCAL` and manifest-allowed `PASSIVE_WEB` may proceed after PolicyGate returns `ALLOW`. `THIRD_PARTY_API`, `TOR`, and `DIRECT_TARGET` proceed only when PolicyGate returns `REQUIRE_EXPLICIT_APPROVAL` and an unexpired, approved, exact-scope `RunAuthorization` matches the case, collector name, and source class. A denied policy decision cannot be overridden by an authorization.

The orchestrator writes request, policy, authorization, allow/deny, start, and finish/failure events. Audit failure stops execution before a context is issued. Requester, purpose, and input references are logged only as SHA-256 hashes.

The orchestrator creates a single-use `ExecutionContext`. The collector's guarded `run()` consumes it before input validation and execution. Results use `SUCCESS`, `PARTIAL`, `FAILED`, or `DENIED`; exception payloads are not copied into the audit log.

## PLANNED

- Durable authorization lookup, collector registry, rate/budget limits, cancellation, and retry policy.
- Integration with the Evidence Vault for raw output and execution records.
- Concurrency controls and recovery semantics for interrupted runs.
- A reviewed external boundary for process isolation or sandboxing.

## NOT IMPLEMENTED

- No production collector, network call, Tor access, direct-target action, or SHIELD integration.
- No Python in-process mechanism can make deliberately malicious imported code impossible to call outside conventions; this foundation blocks the public contract path but is not a security sandbox.
- No automatic retry, scheduler, queue, distributed lock, or background worker.
