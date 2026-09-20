# Phone Public Providers v1

## IMPLEMENTED

`PhonePublicProvider` declares provider ID/name, public search template, GET method, `PASSIVE_WEB`, enabled flag, review date, timeout, privacy and terms/limitations notes, parser ID, no-match/challenge signals, homepage, and notes. Provider-specific configuration is outside collector control flow; parser dispatch is explicit and reviewed. Providers discover candidates only and are not evidence sources.

The default registry contains one enabled provider: DuckDuckGo HTML, DuckDuckGo's [official non-JavaScript search surface](https://duckduckgo.com/duckduckgo-help-pages/features/non-javascript) (`https://html.duckduckgo.com/html`). It also records Mojeek as a disabled candidate because [Mojeek terms prohibit automated access without authorized API use](https://www.mojeek.com/about/terms.html), and the [official API requires an API key](https://www2.mojeek.com/support/api/search/request_parameters.html). Therefore v1 honestly has one active discovery channel, not active multi-source search.

Tests use only reserved `.test` providers and mock HTTP. They never contact DuckDuckGo or another public service.

## PLANNED

- Additional providers only after legal/privacy review, stable public access validation, parser fixtures, and false-positive tests.
- Explicit provider disablement/versioning when public markup or terms change.

## NOT IMPLEMENTED

- Scraping behind login, automated browser interaction, private social search, paid APIs, or forced provider coverage.
