# LUMIR OSINT LAB — work handoff

## Current Status
Etap 8 is implemented on `feature/osint-lab-v1`. Email handling is split into `EmailLocalMetadataCollector` (`LOCAL`) and `EmailExposureCollector` (`PASSIVE_WEB`) so the one-source-class contract and separate PolicyGate decisions remain intact. The reviewed exposure provider is the unauthenticated Gravatar public profile endpoint using only a SHA-256 email identifier. All Etap 4 controls and prior Phone, DNS, and Username collectors remain in place. SHIELD RC6 code was not changed.

## Last Verified Commit
Etap 7 baseline `42aa506`; branch baseline `main`: `d881757`. Use `git log -1` for the latest Etap 8 commit after publication.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`, phonenumbers `9.0.34`, dnspython `2.8.0`, requests `2.34.2`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Final Windows verification after all Etap 8 changes: focused Email suite PASS (`37 passed`); `python -m pytest -q` PASS (`178 passed in 6.50s`); `python test_shield.py` RC6 PASS (`5/5`, exit `0`); `git diff --check` PASS. Email and Username HTTP responses are mocked; the full pytest suite requires no internet.

## What Works
`build_default_registry()` creates a fresh registry with five reviewed collectors; there is no global mutable registry. Email provider configuration and Username provider definitions are hash-bound. Email input preserves the local-part, normalizes the domain through IDNA, and records an orchestration-level DomainDNS dependency without executing it. The exposure collector uses explicit public GET rules and a bounded shared HTTP transport with no auth, persistent cookies, environment proxy, browser, JavaScript, or subprocess. Audit stores only the seed hash; the private vault stores execution evidence, and the receipt stores evidence references.

## Known Problems
A claimed Gravatar profile does not identify its owner or prove linkage to a person. Gravatar rules and profile JSON may change and conservatively degrade results to `UNKNOWN`; unauthenticated requests are externally rate-limited. Explicit provider lists are intentionally incomplete. Breach databases, HIBP, Holehe, login/signup/reset/recovery probing, private content, authenticated scraping, CAPTCHA bypass, browser automation, Tor, paid APIs, email ownership, and automatic person-email relations remain unimplemented. Vault encryption and external audit witnessing remain unimplemented.

## Architecture Decisions
Email local metadata declares `LOCAL` and cannot start a network run. Email exposure declares `PASSIVE_WEB` and `network_required = true`; a run discloses a provider-normalized email SHA-256 identifier and source IP to Gravatar. HTTP 200 alone is `UNKNOWN`. CAPTCHA/challenge, 403, 429, timeout, generic pages, malformed responses, and redirects cannot become `CLAIMED` or `AVAILABLE`; only provider-specific markers or reviewed status rules decide. `CLAIMED` normalizes to `POSSIBLE`, never `CONFIRMED`. Holehe is rejected because its documented register/login/recovery techniques and the existing subprocess adapter violate Etap 8 policy.

## Current Task
Email collector implementation, provider boundary, offline false-positive tests, documentation, full pytest, RC6, diff/privacy/subprocess/browser checks, and the `shield/` unchanged check are complete. Publish `feature/osint-lab-v1` with a normal non-force push.

## Next Task
Review Gravatar disclosure and provider rules. Next, add orchestration-level scheduling for the existing DomainDNS dependency only if it preserves a separate PolicyGate decision; do not add breach, reset/login/signup, or unstable providers merely to increase source count.

## Files Changed
Etap 8 adds `email_exposure.py`, registry exports/registrations, offline tests, and `docs/COLLECTOR_EMAIL_EXPOSURE.md`, and updates architecture/registry documentation. No file under `shield/` is modified.

## Safety Notes
Email tests use only synthetic local-parts and reserved `.test` domains; no user email or real case data is committed. The suite performs no public HTTP request. Full response content is not archived; only a body hash and detection signals are persisted. Local email evidence may contain raw email inside the private vault, while audit and receipt do not. Authorization, audit, and evidence roots must stay outside Git; the vault remains plaintext.
