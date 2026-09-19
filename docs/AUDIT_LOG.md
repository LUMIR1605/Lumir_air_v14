# OSINT LAB audit log

## IMPLEMENTED

`osint_lab.orchestrator.audit.AuditLog` writes case-specific JSONL outside the repository. The Windows default is:

`%LOCALAPPDATA%\LumirOSINTLab\audit\<case_id>\audit.jsonl`

The configured root must be disjoint from the Git checkout. Each `AuditEntry` records audit, case, execution, and optional authorization IDs; collector name; source class; event type; decision; timezone-aware timestamp; message; and scalar metadata.

Event types are `RUN_REQUESTED`, `POLICY_EVALUATED`, `AUTHORIZATION_CHECKED`, `RUN_ALLOWED`, `RUN_DENIED`, `AGENT_STARTED`, `AGENT_FINISHED`, and `AGENT_FAILED`.

Writes use OS append mode and `fsync`; the API has no update or delete operation. Secret-like metadata keys such as password, token, API key, credential, or secret are rejected. Orchestrator request fields are represented by hashes rather than raw values.

## PLANNED

- Hash-chain or signed-log design, verification command, rotation, retention, locking, and crash tests.
- Access-control verification, secure export, and linkage to evidence integrity records.
- Structured redaction policy beyond key-name checks.

## NOT IMPLEMENTED

- The JSONL file is append-only through this API but is not immutable or tamper-proof against filesystem access.
- No signature, hash chain, trusted timestamp, remote witness, SIEM integration, or multi-process locking.
- Metadata filtering cannot prove that arbitrary string values contain no sensitive information.
