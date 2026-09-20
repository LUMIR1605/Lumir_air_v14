# Search Discovery Model v1

## IMPLEMENTED

Search engines are discovery channels, not evidence sources. A discovery record keeps provider, reviewed configuration, query variant, result URL/title/snippet, timestamp and response hash. It cannot create correlation or high evidence quality. Candidates are canonicalized and deduplicated before bounded target fetch.

The registry contains one enabled public HTML channel, DuckDuckGo HTML, and one explicitly disabled independent-index candidate, Mojeek. Mojeek remains disabled because its [official terms prohibit automated access without authorized API use](https://www.mojeek.com/about/terms.html), while its [official Search API requires an API key and commercial plan](https://www2.mojeek.com/support/api/search/request_parameters.html). The system does not claim active multi-source coverage.

## PLANNED

- A second enabled provider only after explicit terms/privacy review, deterministic fixtures and stable no-login access.

## NOT IMPLEMENTED

- Paid/private search APIs, scraping contrary to provider terms, CAPTCHA bypass, login or browser automation.
