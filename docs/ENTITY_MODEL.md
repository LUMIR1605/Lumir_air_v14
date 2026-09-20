# Entity Model v1

## IMPLEMENTED

`EntityNode` covers PHONE, EMAIL, USERNAME, DOMAIN, WEBSITE, COMPANY, ORGANIZATION, DOCUMENT, LOCATION, SOCIAL_PROFILE, IP, NAME and OTHER. It records canonical/display values, aliases, first/last seen, created/updated times, provenance, confidence, status and JSON-safe attributes. `NAME` is textual data, never a PERSON identity.

`EntityNormalizer` uses E.164, normalized email/domain, IDNA lowercase hosts, canonical URLs and username comparison forms. Company/organization/name receive whitespace-only light normalization. Exact canonical values deduplicate; fuzzy names never auto-merge.

## PLANNED

- Reviewer-controlled fuzzy `POSSIBLE_SAME_ENTITY` suggestions and locale-specific normalization.

## NOT IMPLEMENTED

- PERSON entity resolution, phonetic merge, biometric inference or automatic company-name equivalence.
