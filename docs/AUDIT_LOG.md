# OSINT LAB audit log

## IMPLEMENTED

`osint_lab.orchestrator.audit.AuditLog` writes case-specific JSONL outside the repository. The Windows default is:

`%LOCALAPPDATA%\LumirOSINTLab\audit\<case_id>\audit.jsonl`

The configured root must be disjoint from the Git checkout. Each `AuditEntry` records audit, case, execution, and optional authorization IDs; collector name; source class; event type; decision; timezone-aware timestamp; message; and scalar metadata.

Event types are `RUN_REQUESTED`, `POLICY_EVALUATED`, `AUTHORIZATION_CHECKED`, `RUN_ALLOWED`, `RUN_DENIED`, `AGENT_STARTED`, `AGENT_FINISHED`, and `AGENT_FAILED`.

Writes use OS append mode and `fsync`; the API has no update or delete operation. Every record includes `previous_hash` and `entry_hash`. The SHA-256 chain uses canonical JSON and is verified before append. `verify_audit_log(...)` detects old-entry modification, damaged hashes, deletion from the middle, and reordering. Secret-like metadata keys such as password, token, API key, credential, or secret are rejected. Orchestrator request fields are represented by hashes rather than raw values.

The chain is tamper-evident and makes no immutability claim.

## PLANNED

- Signed or externally witnessed heads, verifier CLI, rotation, retention, locking, and crash tests.
- Access-control verification, secure export, and linkage to evidence integrity records.
- Structured redaction policy beyond key-name checks.

## NOT IMPLEMENTED

- The JSONL file is append-only through this API but is not immutable against filesystem access.
- No signature, trusted timestamp, remote witness, SIEM integration, or multi-process locking.
- Tail truncation requires an external head checkpoint to detect.
- Metadata filtering cannot prove that arbitrary string values contain no sensitive information.
