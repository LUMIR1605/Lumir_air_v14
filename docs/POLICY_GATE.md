# OSINT LAB PolicyGate

## IMPLEMENTED

`osint_lab.policies.gate.PolicyGate` is the central fail-closed decision point for future agents. It evaluates a validated case manifest, requested agent type, and requested source class without invoking a collector.

Decisions are `ALLOW`, `DENY`, and `REQUIRE_EXPLICIT_APPROVAL`.

Evaluation order:

1. Only `AUTHORIZED` or `ACTIVE` cases are runnable.
2. The agent type must be listed in `allowed_agent_types`.
3. The source class must not be forbidden and must be explicitly allowed.
4. Allowed `LOCAL` and `PASSIVE_WEB` requests return `ALLOW`.
5. `THIRD_PARTY_API`, `TOR`, and `DIRECT_TARGET` require their matching manifest boolean and return `REQUIRE_EXPLICIT_APPROVAL`.

The risky-source result is intentionally not `ALLOW`: a manifest flag records scope, while a future per-run approval mechanism must record the actual approval. Defaults deny all three risky source classes. Unknown types, invalid manifest objects, paused/closed cases, forbidden classes, and unlisted agents fail closed.

## PLANNED

- Orchestrator integration that calls the gate before every agent invocation.
- A durable, scoped, expiring per-run approval record and audit log.
- Rate, budget, stop-condition, and source-specific policy checks.
- Tests proving that future collectors cannot bypass the gate.

## NOT IMPLEMENTED

- No collector invocation, approval prompt, approval token, network call, Tor access, or direct-target operation.
- No bypass or automatic conversion of `REQUIRE_EXPLICIT_APPROVAL` to `ALLOW`.
- No runtime integration with SHIELD RC6.
