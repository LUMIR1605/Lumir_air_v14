# Discovery budget

## IMPLEMENTED

Defaults are: 8 queries/entity, 6/provider, 10 results/query, 30 unique candidates, 15 unique
domains and 3 candidates/domain. Each actual provider request passes through `RateLimiter`; the
existing case/provider/host limits remain authoritative. Exhaustion is explicit and stops further
requests without a retry loop.

Coverage records eligible/configured/executed/successful/failed providers, planned/executed
queries, raw and unique results, duplicate removal, unique domains, selected candidates, request
count and budget exhaustion. Target verification adds verified/rejected/unknown candidate counts,
verified phone occurrences and discovered entity totals at the report layer.

## NOT IMPLEMENTED

- Adaptive paid-budget increases or automatic quota purchases.
