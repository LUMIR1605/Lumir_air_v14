# Relation Model v1

## IMPLEMENTED

`EntityRelation` supports MENTIONED_ON, MENTIONS, ASSOCIATED_WITH, USES_DOMAIN, USES_EMAIL, USES_PHONE, LINKS_TO, HOSTED_ON, REFERENCES, PUBLISHED_IN, LOCATED_AT, ALIAS_OF, POSSIBLE_SAME_ENTITY and OTHER. Every edge requires evidence refs, source refs, independence groups and explainable reasons.

Statuses are UNKNOWN, POSSIBLE, PROBABLE, CONFIRMED and REJECTED. CONFIRMED is structurally invalid without a ReviewerDecision reference. Edge events retain changes rather than replacing history.

## PLANNED

- Reviewer-governed relation vocabulary extensions and disappearance rules.

## NOT IMPLEMENTED

- Automatic ownership, employment, family or same-person assertions.
