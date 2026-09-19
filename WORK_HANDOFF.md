# LUMIR OSINT LAB — work handoff

## Current Status
Etap 7 is implemented on `feature/osint-lab-v1`: `UsernameCollector` v1 performs conservative provider-specific public checks for GitHub and GitLab as `PASSIVE_WEB`. Domain DNS remains `PASSIVE_WEB` and phone metadata remains `LOCAL`. All Etap 4 registry, PolicyGate, audit, context, vault, receipt, and fail-closed controls remain in place. SHIELD RC6 code was not changed.

## Last Verified Commit
Implementation and focused tests through `287def6`; branch baseline `main`: `d881757`. Use `git log -1` for the latest documentation commit.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`, phonenumbers `9.0.34`, dnspython `2.8.0`, requests `2.34.2`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Windows verification on the documentation state: `python -m pytest -q` PASS (`141 passed`); `python test_shield.py` RC6 PASS (`5/5`, exit `0`). Tests cover username false-positive rules, provider/HTTP failures, registry binding, PolicyGate, privacy, evidence, receipt, audit, and the full Domain/Phone/foundation regression. All username HTTP responses are mocked and require no internet.

## What Works
`build_default_registry()` creates a fresh registry with all three reviewed collectors; there is no global mutable registry. Username provider definitions and their hash are registry-bound. Public GET requests use explicit User-Agent/timeout, no auth, persistent cookies, environment proxy, browser, JavaScript, or subprocess. Audit stores only the username hash; the vault stores technical response metadata/body hash, and the receipt stores evidence references.

## Known Problems
A claimed public profile does not identify its owner or prove linkage to a person. Provider markup may change and conservatively degrade results to `UNKNOWN`. Login, private content, authenticated scraping, CAPTCHA bypass, browser automation, Tor, Instagram/TikTok/LinkedIn, paid APIs, and social graphs remain unimplemented. Vault encryption and external audit witnessing remain unimplemented.

## Architecture Decisions
Username checks declare `PASSIVE_WEB` and `network_required = true`; requests disclose the username and source IP to GitHub/GitLab. HTTP 200 alone is `UNKNOWN`. CAPTCHA/challenge, 403, 429, timeout, server errors, generic pages, and redirects outside the profile cannot become `AVAILABLE`; only provider-specific signals or reviewed status rules decide. `CLAIMED` normalizes to `POSSIBLE`, never `CONFIRMED`.

## Current Task
UsernameCollector implementation, offline false-positive tests, full pytest, RC6, and documentation are complete. Run final diff/privacy/subprocess/browser/shield checks and publish `feature/osint-lab-v1` without force push.

## Next Task
Review and accept provider rules, disclosure, and conservative UNKNOWN semantics. Maintain provider changes as reviewed configuration updates with offline fixtures; do not add unstable platforms only to increase source count.

## Files Changed
Etap 7 adds the provider model, bounded HTTP abstraction, `UsernameCollector`, registry binding, offline tests, and `docs/COLLECTOR_USERNAME.md`. No file under `shield/` is modified.

## Safety Notes
Username tests use only `fixture_user` and reserved `.test` URLs; no user username or real case data is committed. The suite performs no public HTTP request. Full response HTML is not archived; only a body hash and detection signals are persisted. Authorization, audit, and evidence roots must stay outside Git; the vault remains plaintext.
