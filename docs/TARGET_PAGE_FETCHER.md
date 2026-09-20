# Target Page Fetcher v1

## IMPLEMENTED

`TargetPageFetcher` performs bounded public `GET` requests for search-discovered target pages. It records requested/final URL, status, content type/length, redirect chain, timestamps, SHA-256, truncation and `SUCCESS`, `UNKNOWN`, `BLOCKED`, or `ERROR`.

Every hop is checked before and after the request. The actual peer IP is mandatory and must belong to both DNS answer sets; an unavailable or changed peer fails closed. Non-HTTP schemes, localhost, loopback, private/reserved/link-local/multicast/unspecified IPs, metadata hosts, `.onion`, private redirect targets, excessive redirects, login redirects, unsupported content, challenges, and oversized bodies cannot become evidence. The default limits are 4 redirects, 4/8 second connect/read timeouts, and 512 KiB. Only HTML, XHTML and plain text are accepted. Cookies, forms, browser automation and automatic redirects are not used.

URL canonicalization removes fragments and common tracking parameters while preserving content-affecting query parameters. Target requests are sequential, deduplicated and bounded per provider, case and host.

## PLANNED

- Configurable reviewed host budgets and persisted provider health metrics.
- Optional outbound proxy support with equally strict destination attestation.

## NOT IMPLEMENTED

- Spidering, robots bypass, paywall/login interaction, JavaScript execution, PDF/media/archive download or authenticated sessions.
