# UsernameCollector v1

## IMPLEMENTED

`UsernameCollector` checks public profile presence using provider-specific rules. It is a `PASSIVE_WEB` collector with `network_required: true`; each query discloses the username and requesting IP to the selected public provider.

Identity:

- `agent_name`: `username_lookup`
- `agent_type`: `USERNAME`
- `version`: `1.0.0`
- providers: GitHub and GitLab
- method: public `GET` only

Provider definitions are isolated in `username_providers.py` and declare URL templates, provider-specific claimed/available/error markers, reviewed status codes, timeouts, enablement, notes, and username rules. Their complete configuration is hashed into registry capabilities, so changing the provider set or rules causes a metadata mismatch unless explicitly registered.

The HTTP layer uses an explicit User-Agent, bounded timeout and response-body limit, TLS verification from `requests`, no authentication, no persistent cookies, no environment proxy, no browser, and no JavaScript. It does not bypass CAPTCHA, Cloudflare, rate limits, or login controls.

Technical statuses:

- `CLAIMED`: a provider-specific profile marker was found on a reviewed successful response.
- `AVAILABLE`: a provider-specific absence marker or explicitly reviewed 404 rule matched.
- `UNKNOWN`: evidence is insufficient, generic, challenged, redirected outside the profile, rate-limited, forbidden, timed out, or otherwise ambiguous.
- `ERROR`: the HTTP abstraction returned malformed data or raised an unexpected technical error.

HTTP 200 alone never produces `CLAIMED`. CAPTCHA, Cloudflare/JS challenge, 403, 429, timeout, server error, or generic landing content never produces `AVAILABLE`. Conflicting claimed/available signals are `UNKNOWN`.

Evidence stores username, provider/profile URL, HTTP status, sanitized signals, request method, collection timestamp, redirect/final URL metadata, collector version, and a SHA-256 of the bounded response body. Full HTML is not automatically archived. Audit stores only the input hash; ExecutionReceipt stores evidence references and the audit head.

Normalization is strictly technical: `CLAIMED → POSSIBLE`, `AVAILABLE → NOT_FOUND`, and `UNKNOWN/ERROR → UNKNOWN`. A claimed profile is a candidate using the same public username, not proof of a person or account owner.

## PLANNED

- Reviewed provider-rule maintenance with recorded live fixtures and change monitoring.
- Optional provider-specific response snippets only after privacy and retention review.
- Additional stable providers only when deterministic claimed/available signals can be documented.

## NOT IMPLEMENTED

- Identity confirmation, ownership proof, person correlation, or social graph.
- Login, credentials, private profiles, or authenticated scraping.
- CAPTCHA/challenge bypass, JavaScript execution, or browser automation.
- Instagram, TikTok, LinkedIn, Sherlock, Tor, proxy rotation, paid APIs, or rate-limit evasion.
- `PERSON → USERNAME`, `SAME_PERSON`, or `IDENTITY_CONFIRMED` relations.
