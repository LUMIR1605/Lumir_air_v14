# Company Intelligence v1

## IMPLEMENTED

COMPANY and ORGANIZATION are supported graph/enrichment seed types. `CompanyPublicWebCollector` uses bounded Brave/DDG discovery but accepts only an exact normalized organization name in structured Organization/Corporation/LocalBusiness data. Matched first-party pages may yield evidence-backed WEBSITE, DOMAIN, EMAIL and PHONE relations.

Normalization is deliberately light. `ABC`, `ABC Sp. z o.o.` and `ABC Polska` are not automatically merged. Company names are never merged with people.

## NOT IMPLEMENTED

- A jurisdiction-specific official company registry; the generic candidate stays disabled pending explicit review.
