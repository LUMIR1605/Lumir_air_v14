# Phone Public Providers v1

## IMPLEMENTED

`PhonePublicProvider` declares provider ID/name, public search template, GET method, `PASSIVE_WEB`, mandatory exact-match policy, enabled flag, timeout, privacy notes, parser ID, no-match/challenge signals, homepage, and notes. Provider-specific configuration is outside collector control flow; parser dispatch is explicit and reviewed.

The default registry contains one enabled provider: DuckDuckGo HTML, DuckDuckGo's [official non-JavaScript search surface](https://duckduckgo.com/duckduckgo-help-pages/features/non-javascript) (`https://html.duckduckgo.com/html`). The provider receives quoted phone variants. Availability is not guaranteed: CAPTCHA, challenge, rate limiting, generic pages, or changed markup remain `UNKNOWN`; there is no bypass or fallback to unsafe probing.

Tests use only reserved `.test` providers and mock HTTP. They never contact DuckDuckGo or another public service.

## PLANNED

- Additional providers only after legal/privacy review, stable public access validation, parser fixtures, and false-positive tests.
- Explicit provider disablement/versioning when public markup or terms change.

## NOT IMPLEMENTED

- Scraping behind login, automated browser interaction, private social search, paid APIs, or forced provider coverage.
