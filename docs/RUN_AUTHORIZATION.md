# OSINT LAB run authorization

## IMPLEMENTED

`osint_lab.orchestrator.authorization.RunAuthorization` is an immutable approval record scoped to one case, one collector name, and one `SourceClass`.

It records `authorization_id`, `case_id`, `requested_agent`, `requested_source_class`, timezone-aware request/decision/expiry timestamps, requester, purpose, decision, approver, scope, and notes. Decisions are `APPROVED`, `DENIED`, `EXPIRED`, and `REVOKED`.

Every authorization has a finite `expires_at` later than its decision. Wildcard agent or scope values are rejected. `check()` fails closed when the case, collector name, or source class differs; when the decision is not `APPROVED`; before the decision becomes effective; and at or after expiry. Revoked and expired records never authorize execution.

For risky source classes, a matching approved record is necessary but not sufficient: the case manifest and PolicyGate must also permit the request.

`AuthorizationStore` persists each decision as a separate atomic JSON history event outside Git. The Orchestrator performs case-specific lookup by authorization ID and revalidates the latest record after reload. Binding fields cannot be changed within an existing authorization history.

## PLANNED

- Signed approvals, trusted approver identities, revocation records, and renewal workflow.
- Explicit binding to a reviewed input-scope hash and purpose taxonomy.
- UI or CLI approval flow with least-privilege defaults.

## NOT IMPLEMENTED

- No global allow-all, standing approval, approval inheritance, or automatic renewal.
- No signature verification, identity provider, role model, or external authorization service.
- `AuthorizationSignatureProvider` is an interface only; signing and key management are NOT IMPLEMENTED.
- No claim that free-text purpose or scope proves legal authorization.
