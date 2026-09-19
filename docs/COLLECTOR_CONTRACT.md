# OSINT LAB collector contract v1

## IMPLEMENTED

`osint_lab.agents.Collector` requires `agent_name`, `agent_type`, `source_class`, and `version`. A collector implements `validate_input()`, protected `_run()`, `normalize()`, and `describe_capabilities()`.

The inherited public `run()` cannot be overridden by subclasses. It requires a matching, single-use `ExecutionContext` created by the orchestrator, consumes that context, validates the input reference, and accepts only tuples of `RawObservation`.

Normalization returns `FindingCandidate`. Candidate construction rejects `FindingStatus.CONFIRMED`, so a collector cannot turn its own observation into a final identity verdict. The orchestrator wraps execution as `ExecutionResult` with execution ID, timezone-aware start/finish, status, safe errors, observations, and candidates.

`SyntheticLocalCollector` and the synthetic policy collector exist only in `tests/test_osint_orchestrator.py`. They use synthetic references, report `network: false`, and make no network calls.

## PLANNED

- Reviewed collector registration, package provenance, capability verification, and version compatibility rules.
- Process isolation, resource limits, deterministic fixtures, and contract conformance tests for future collectors.
- Evidence Vault integration and typed input-reference schemes.

## NOT IMPLEMENTED

- No real local or network collector is registered.
- No Sherlock, Holehe, PhoneInfoga, DNS, Tor, third-party API, or direct-target integration.
- Python type and metaclass controls are not a sandbox against deliberately hostile code importing private internals.
