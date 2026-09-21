# Source Registry PRO v1

## IMPLEMENTED

`SourceRegistry` is an immutable-at-runtime production factory containing 15 explicit `SourceDefinition` values and a registry version/configuration SHA-256. Each definition declares category, roles, supported/output entity types, source class, access method, public base URL, credential/payment flags, automation and terms review, privacy exposure, reputation, information gain, limits, parser version and implementation status.

An enabled source must be public, reviewed, automation-allowed and implemented. Credential/payment-gated sources additionally require an explicit runtime configuration bit. `brave_search_api` is enabled only when its environment key is present; otherwise it remains registered as `AUTH_REQUIRED`. No credential value enters the model or hash. Duplicate IDs and configuration hash mismatches fail closed. Ten credentialless definitions are enabled by default; four uncertain candidates remain disabled.

## PLANNED

- Signed registry releases after a separate key-management design.

## NOT IMPLEMENTED

- Dynamic remote registry updates or unreviewed provider activation.
