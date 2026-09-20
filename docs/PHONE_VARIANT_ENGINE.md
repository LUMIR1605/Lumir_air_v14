# Phone Variant Engine v1

## IMPLEMENTED

`generate_phone_variants()` parses with explicit default region `PL`, retains canonical E.164, and returns deduplicated `PhoneVariant` records. The bounded set covers canonical E.164, national digits, national spaced, national hyphenated, international spaced, and country-code spaced forms. It does not generate arbitrary permutations.

Each variant has `canonical_e164`, `variant`, and `variant_type`. Exact matching applies digit boundaries and evaluates longer variants first so an international occurrence is not mislabeled as a shorter national substring.

## PLANNED

- Reviewed region-specific presentation rules when additional default regions are explicitly introduced.

## NOT IMPLEMENTED

- Country guessing for local numbers, vanity-number expansion, OCR correction, or combinatorial separator generation.
