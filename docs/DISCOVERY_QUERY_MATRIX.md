# Discovery query matrix

## IMPLEMENTED

PHONE uses at most eight deduplicated queries: exact raw/presentation forms, Polish
`telefon/kontakt/firma/ogłoszenie` context, English `phone/contact` context and a document query.
EMAIL, COMPANY/ORGANIZATION and USERNAME use separate bounded exact/context matrices. DOMAIN keeps
first-party-oriented queries and is not redundantly injected into adapters that already have an
authoritative first-party path.

Queries are case-private. Case events, audit and receipts keep query identifiers/hashes, not raw
API credentials. A provider receives a raw query only when its configuration and case policy allow
the PASSIVE_WEB execution.

## NOT IMPLEMENTED

- Country guessing, fuzzy person lookup, owner inference or query expansion from private data.
