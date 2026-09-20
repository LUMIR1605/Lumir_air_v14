# PhonePublicWebCollector v1

## IMPLEMENTED

`PhonePublicWebCollector` (`phone_public_web`, version `1.0.1`) is a `PASSIVE_WEB` PHONE collector with `network_required = true`. It runs only through CaseManifest, Registry, PolicyGate, Orchestrator, Audit, Evidence Vault, ExecutionReceipt, Intelligence Core, and ReportEngine.

The collector performs public unauthenticated GET searches using reviewed providers and bounded phone variants. Numeric normalization is only candidate detection. A result becomes `MATCH` only as `PHONE_CONTEXT_MATCH` (visible normalized number near an explicit phone/contact label) or `STRUCTURED_PHONE_MATCH` (`tel:`, schema/JSON-LD telephone, or vCard TEL). A plain `NUMERIC_MATCH` remains `UNKNOWN`. Digits occurring only as a URL/resource, image, product, article, listing, document, tracking, pagination, or similar identifier become `REJECTED_NUMERIC_ID`. `NO_MATCH` requires an explicit reviewed provider no-results signal. CAPTCHA, JS challenge, 403, 429, timeout, homepage redirect, generic page, and inconclusive parsing produce `UNKNOWN`; technical client/parser failures produce `ERROR`.

Accepted semantic occurrences record canonical phone, match level, matched variant/type, match location, snippet, result URL/domain, collection timestamp, content hash, explicit source date or `UNKNOWN`, and a warning for dates older than 24 months. Conservative extraction supports visible email/handle, URL/domain, structured organization/location, and document filename/type. Extraction confidence describes extraction quality only. Rejected numeric identifiers are retained as low-quality evidence with an explainable reason but cannot create entities, correlations, hypotheses, or derived pivots.

Audit and receipts omit the raw phone. The private vault/report may contain it. Findings are at most `POSSIBLE`; no result confirms subscriber, owner, person, or identity.

## PLANNED

- Additional individually reviewed public providers and parser fixtures.
- Provider health monitoring, per-provider budgets, and retry scheduling.
- Durable reviewer handling of public occurrence hypotheses.

## NOT IMPLEMENTED

- Login, signup, account recovery/password reset, CAPTCHA bypass, browser automation, Tor, paid/private APIs, breach databases, Truecaller, WhatsApp/Telegram probing, PhoneInfoga, or automatic identity resolution.
