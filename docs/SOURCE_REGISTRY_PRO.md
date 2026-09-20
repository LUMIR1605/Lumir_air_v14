# Source Registry PRO v1

## IMPLEMENTED

`SourceRegistry` is an immutable-at-runtime production factory containing 14 explicit `SourceDefinition` values and a registry version/configuration SHA-256. Each definition declares category, roles, supported/output entity types, source class, access method, public base URL, credential/payment flags, automation and terms review, privacy exposure, reputation, information gain, limits, parser version and implementation status.

An enabled source must be public, reviewed, automation-allowed, free, credentialless and implemented. Duplicate IDs and configuration hash mismatches fail closed. Ten definitions are enabled; four uncertain candidates remain disabled.

## PLANNED

- Signed registry releases after a separate key-management design.

## NOT IMPLEMENTED

- Dynamic remote registry updates or unreviewed provider activation.
