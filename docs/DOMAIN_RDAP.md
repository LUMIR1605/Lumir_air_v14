# Domain RDAP v1

## IMPLEMENTED

`DomainRdapCollector` obtains the authoritative HTTPS endpoint from the IANA DNS RDAP bootstrap registry, then performs one bounded public RDAP domain lookup through the existing SSRF/rebinding/redirect guard. It records statuses, registration events, nameservers, entities/roles, notices and links with response hash and endpoint provenance.

Redacted or absent registrant details remain `UNKNOWN`. A registrar role and single RDAP field never establish ownership.

## NOT IMPLEMENTED

- Authenticated/non-public registration data, reverse search or ownership inference.
