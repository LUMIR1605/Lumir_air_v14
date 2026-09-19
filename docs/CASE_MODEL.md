# OSINT LAB case model

## IMPLEMENTED

`osint_lab.case_manifest.CaseManifest` is the validated authorization record for one case. It contains:

- `case_id`, `case_name`, timezone-aware `created_at`, `authorized_by`, `purpose`, and `legal_basis_or_consent_note`;
- one or more typed `seed_entities`;
- allowed and forbidden `SourceClass` sets and allowed agent type names;
- explicit booleans for third-party API, Tor, and direct-target access;
- `retention_days`, `notes`, and a typed case `status`.

Statuses are `DRAFT`, `AUTHORIZED`, `ACTIVE`, `PAUSED`, `CLOSED`, and `ARCHIVED`. Case identifiers are restricted to safe path-compatible values. Allowed and forbidden source classes cannot overlap. Time values must include a timezone, retention must be positive, and source-class values must use the declared enum.

The default manifest allows only `LOCAL`. `THIRD_PARTY_API`, `TOR`, and `DIRECT_TARGET` are forbidden and their booleans are `False`. Enabling one of these classes requires both an allowed-class entry and its matching explicit boolean; this does not itself authorize a run because the PolicyGate still returns `REQUIRE_EXPLICIT_APPROVAL`.

`CaseManifest.to_dict()` provides a JSON-compatible representation. `EvidenceVault.create_case()` writes it as `case.json` outside the repository.

## PLANNED

- Signed or otherwise independently auditable authorization records.
- Versioned manifest updates and an immutable authorization history.
- A loader that reconstructs and revalidates manifests from `case.json`.
- Retention review and case-state transition workflows.

## NOT IMPLEMENTED

- No UI, API, database, persistent registry administration, or automatic case scheduling.
- No proof that free-text authorization or legal-basis statements are legally sufficient.
- No automatic consent verification or identity verification.
- No secret storage in the manifest.
