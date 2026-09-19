# OSINT LAB authorization store

## IMPLEMENTED

`AuthorizationStore` persists case-specific `RunAuthorization` decisions under `%LOCALAPPDATA%\LumirOSINTLab\authorizations` by default. The configured root must be outside and disjoint from the repository.

Each decision is a separate immutable JSON history event. Publication uses a flushed temporary file and an atomic no-replace filesystem link. Reload reconstructs and revalidates the typed authorization. The latest decision is selected by `decision_at`; expiry and revocation therefore remain effective after process restart. Existing authorization IDs cannot silently change their case, collector, source class, request time, requester, purpose, or scope.

The Orchestrator accepts an authorization ID, loads it from the store for the current case, and rechecks exact collector name, exact `SourceClass`, effective time, finite expiry, and decision. Missing, corrupt, cross-case, expired, denied, or revoked records fail closed.

Only the fixed authorization schema is stored. No API tokens, credentials, private keys, or other secret fields are supported.

## PLANNED

- Trusted approver identity and role validation.
- Reviewed file permissions, multi-process locking, retention, export, and recovery.
- Input-scope hashes and versioned decision schemas.

## NOT IMPLEMENTED

- Cryptographic signatures and key management are not implemented.
- `AuthorizationSignatureProvider` is an interface only; no fake signer is supplied or trusted.
- The local filesystem history is not immutable against an account with write access.
- Free-text purpose, scope, and notes are not proof of legal authorization and must not contain secrets.
