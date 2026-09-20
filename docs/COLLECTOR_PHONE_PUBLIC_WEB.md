# PhonePublicWebCollector v1

## IMPLEMENTED

`PhonePublicWebCollector` (`phone_public_web`, version `1.0.0`) is a `PASSIVE_WEB` PHONE collector with `network_required = true`. It runs only through CaseManifest, Registry, PolicyGate, Orchestrator, Audit, Evidence Vault, ExecutionReceipt, Intelligence Core, and ReportEngine.

The collector performs public unauthenticated GET searches using reviewed providers and bounded phone variants. A result becomes `MATCH` only when an exact generated variant occurs in a parsed result snippet/body. Returned URLs alone never create a match. `NO_MATCH` requires an explicit reviewed provider no-results signal. CAPTCHA, JS challenge, 403, 429, timeout, homepage redirect, generic page, and inconclusive parsing produce `UNKNOWN`; technical client/parser failures produce `ERROR`.

Confirmed occurrences record canonical phone, matched variant/type, match location, snippet, result URL/domain, collection timestamp, content hash, explicit source date or `UNKNOWN`, and a warning for dates older than 24 months. Conservative extraction supports visible email/handle, URL/domain, structured organization/location, and document filename/type. Extraction confidence describes extraction quality only.

Audit and receipts omit the raw phone. The private vault/report may contain it. Findings are at most `POSSIBLE`; no result confirms subscriber, owner, person, or identity.

## PLANNED

- Additional individually reviewed public providers and parser fixtures.
- Provider health monitoring, per-provider budgets, and retry scheduling.
- Durable reviewer handling of public occurrence hypotheses.

## NOT IMPLEMENTED

- Login, signup, account recovery/password reset, CAPTCHA bypass, browser automation, Tor, paid/private APIs, breach databases, Truecaller, WhatsApp/Telegram probing, PhoneInfoga, or automatic identity resolution.
