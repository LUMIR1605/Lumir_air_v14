# Multi-provider discovery

## IMPLEMENTED

`MultiProviderDiscoveryEngine` executes reviewed providers independently. Brave is available when
configured; DuckDuckGo HTML remains the credentialless fallback/independent channel. One provider
failure is isolated and cannot suppress a successful result from another provider.

`DiscoveryResult` records provider/query provenance, title, canonical URL, snippet, provider rank,
timestamp, raw status and SHA-256. Canonical URL, domain and result hashes are deduplicated while
all discovery channels are retained. Ranking prioritizes contact/about/company/legal/directory and
document context and penalizes assets, long numeric slugs, CDN/tracking pages and generic homepages.
Ranking only controls verification order.

Search output is never evidence. Phone candidates still pass through bounded target fetch,
SSRF/redirect protection, exact semantic phone validation, extraction and Evidence/Graph.

## NOT IMPLEMENTED

- A claim that provider rank is truth or identity confidence.
- Parallel provider calls, retries or an unbounded provider plugin framework.
