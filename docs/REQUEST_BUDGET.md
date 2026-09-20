# Request Budget, Rate Limiting and Cache v1

## IMPLEMENTED

`RateLimiter` performs serial atomic reservations per case, provider and host. Defaults are conservative and no aggressive retry/sleep loop exists. Enrichment also retains graph-wide request, hop and pivot budgets. The default automatic policy is `max_hops=2`, `max_auto_pivots=6`, bounded network requests and privacy cost at most `0.6`.

`PrivateSourceCache` is case-local outside Git, atomic and bounded. Entries contain timestamp, provider/parser version, request fingerprint, content hash and JSON-safe payload. Cached historical material must retain a stale warning and cannot silently become current evidence.

## NOT IMPLEMENTED

- Distributed quotas, cross-case cache sharing or packet-level request accounting.
