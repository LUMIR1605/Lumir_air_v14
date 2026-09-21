# Source Review Registry — 2026-09-21

## ENABLED

| Source | Role | Disclosure | Review basis |
| --- | --- | --- | --- |
| First-party public web | EVIDENCE / VERIFICATION | URL, IP, user agent to the host | HTTP GET plus per-target public/terms boundary |
| Public DNS | ENRICHMENT / VERIFICATION | domain to configured resolver | DNS protocol; bounded queries |
| IANA RDAP bootstrap | DISCOVERY | bootstrap request only | IANA RDAP DNS registry |
| Authoritative registry RDAP | ENRICHMENT / VERIFICATION | domain and IP to registry | ICANN RDAP public registration-data protocol |
| GitHub public profile | ENRICHMENT | username and IP | official public REST/web documentation; 60 unauthenticated requests/hour noted |
| GitLab.com public profile | ENRICHMENT | username and IP | official public-profile/rate-limit documentation |
| Gravatar public profile | ENRICHMENT | SHA-256 email identifier and IP | official unauthenticated Profiles API; 100/hour noted |
| DuckDuckGo HTML | DISCOVERY only | exact query and IP | existing low-volume reviewed discovery adapter; challenges become UNKNOWN |
| Brave Search API (configured only) | DISCOVERY only | query, API account and network metadata | official JSON API; key from process env only; bounded to six queries/provider; 429 is not retried |
| Common Crawl index | DISCOVERY / temporal ENRICHMENT | URL/domain and IP | official public index; exact/host query, limit 5, serial |
| First-party public document | EVIDENCE / ENRICHMENT | document URL and IP | bounded public GET; MIME and parser controls |

## DISABLED

Brave Search API remains registered as `AUTH_REQUIRED` and executes no request when
`LUMIR_BRAVE_SEARCH_API_KEY` is absent. Its public config hash records only `api_key_present`.

Certificate Transparency candidate: automation interface/terms not sufficiently established for production. Public company registry candidate: jurisdiction and interface not specified. Wayback CDX candidate: availability/automation review incomplete. Generic public directories: heterogeneous terms and unstable signals. Disabled sources execute no request.

## REVIEW RULE

Unclear means `DISABLED`. Search results are discovery, not evidence. First-party pages are evidence candidates, not guaranteed truth. No login, CAPTCHA bypass, password reset/signup probing, stolen datasets, Tor or hidden credentials are allowed.
