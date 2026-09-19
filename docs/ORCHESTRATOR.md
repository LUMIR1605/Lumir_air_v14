# OSINT LAB orchestrator

## IMPLEMENTED

`osint_lab.orchestrator.service.Orchestrator.execute()` is the public execution path for the collector contract. Its controlled path is:

`CollectorRegistry → CaseManifest → PolicyGate → AuthorizationStore lookup → AuditLog → ExecutionContext → Collector.run() → EvidenceVault → completion audit → ExecutionReceipt`

`LOCAL` and manifest-allowed `PASSIVE_WEB` may proceed after PolicyGate returns `ALLOW`. `THIRD_PARTY_API`, `TOR`, and `DIRECT_TARGET` proceed only when PolicyGate returns `REQUIRE_EXPLICIT_APPROVAL` and the durable store returns an unexpired, approved, exact-scope authorization for the case, collector name, and source class. A denied policy decision cannot be overridden by an authorization.

The orchestrator writes request, policy, authorization, allow/deny, start, and finish/failure events. Audit failure propagates and never returns a successful result. Requester, purpose, and input references are logged only as SHA-256 hashes.

The orchestrator creates a single-use `ExecutionContext`. The collector's guarded `run()` consumes it before input validation and execution. After a run, raw observations, normalized candidates, execution metadata, and references are stored in the Evidence Vault. The completion audit head is bound into a stored `ExecutionReceipt`. A required vault write failure returns only `FAILED` with no observations or receipt. Results use `SUCCESS`, `PARTIAL`, `FAILED`, or `DENIED`; exception payloads are not copied into the audit log.

## PLANNED

- Rate/budget limits, cancellation, and retry policy.
- Concurrency controls and recovery semantics for interrupted runs.
- A reviewed external boundary for process isolation or sandboxing.

## NOT IMPLEMENTED

- No production collector, network call, Tor access, direct-target action, or SHIELD integration.
- No Python in-process mechanism can make deliberately malicious imported code impossible to call outside conventions; this foundation blocks the public contract path but is not a security sandbox.
- No automatic retry, scheduler, queue, distributed lock, or background worker.
- Denied pre-execution requests do not create execution receipts because no collector ran.
