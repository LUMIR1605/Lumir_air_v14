# OSINT LAB execution receipt

## IMPLEMENTED

After a collector run and required evidence publication, the Orchestrator creates an `ExecutionReceipt` containing:

- execution and case IDs;
- collector name and version;
- source class and authorization ID when required;
- timezone-aware start and finish times;
- result status and observation count;
- Evidence Vault references;
- the verified audit head hash produced by the completion event.

The receipt is returned with `ExecutionResult` and stored as a SHA-256-addressed Evidence Vault artifact under `reports/`. It answers what ran, when it ran, which durable authorization applied, and where the execution evidence is stored. Tests compare `audit_head_hash` with the verifier's current head after a successful run.

## PLANNED

- Receipt schema versioning, export, independent verification, and optional signatures backed by real key management.
- External head checkpoints and long-term archival policy.

## NOT IMPLEMENTED

- No receipt signature, trusted timestamp, remote attestation, or external witness.
- A receipt proves consistency with the local records available to the verifier; it does not prove that the host was uncompromised.
