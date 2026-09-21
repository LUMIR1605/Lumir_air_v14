# Brave Search API provider

## IMPLEMENTED

`brave_search_api` is an official JSON search provider used only for `DISCOVERY` in
`PASSIVE_WEB`. It calls `https://api.search.brave.com/res/v1/web/search` with a bounded timeout,
explicit user agent and `X-Subscription-Token`. The credential is read only from
`LUMIR_BRAVE_SEARCH_API_KEY`; it is never written to configuration, logs, audit, fixtures,
Evidence Vault or reports. Public configuration and registry hashes contain only
`api_key_present`.

Missing or rejected credentials produce `AUTH_REQUIRED`, not a false `NO_RESULTS`. HTTP 429,
timeout, HTTP and JSON/parser failures have distinct statuses and do not stop other providers.
There are no automatic retries.

Review date: 2026-09-21. Official references: Brave Search API documentation, authentication,
rate-limit, plan/pricing and privacy pages. The reviewed plan requires an account/payment method;
current recurring credits can offset limited use but are not treated as a permanent free tier.
Brave states that API query records may be retained for up to 90 days for billing and
troubleshooting. When configured, each query is disclosed to Brave with normal network metadata.

## NOT IMPLEMENTED

- Credential provisioning, rotation or remote secret management.
- CAPTCHA/login bypass, bulk crawling or retry storms.
- Treating a search result as evidence.
