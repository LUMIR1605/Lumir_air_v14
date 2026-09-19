# OSINT LAB audit integrity

## IMPLEMENTED

Every persisted JSONL audit entry contains `previous_hash` and `entry_hash`. The genesis `previous_hash` is 64 zeroes. `entry_hash` is SHA-256 over the UTF-8 canonical JSON representation of the complete entry excluding `entry_hash` and including `previous_hash`; keys are sorted and compact separators are fixed.

`verify_audit_log(...)` and `AuditLog.verify(...)` replay the chain and return validity, entry count, verified head hash, and a reason. They detect changed entry contents, a damaged stored hash, deletion from the middle, and reordering. `AuditLog.append()` verifies the existing chain before appending and refuses to extend an invalid log.

This is tamper-evident and makes no immutability claim.

## PLANNED

- Multi-process locking and concurrency tests.
- External or signed head checkpoints, rotation rules, secure export, and retention.
- A CLI verifier and Windows permission review.

## NOT IMPLEMENTED

- No signature, trusted timestamp, remote witness, or append-only filesystem control.
- Truncation of the final entry cannot be detected without an independently stored prior head.
- A writer with filesystem access can replace the whole log and recompute a new chain.
