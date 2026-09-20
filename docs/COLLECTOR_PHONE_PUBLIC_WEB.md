# PhonePublicWebCollector v1

## IMPLEMENTED

`PhonePublicWebCollector` (`phone_public_web`, version `1.1.0`) is a `PASSIVE_WEB` PHONE collector with `network_required = true`. It runs only through CaseManifest, Registry, PolicyGate, Orchestrator, Audit, Evidence Vault, ExecutionReceipt, Intelligence Core, and ReportEngine.

The collector separates search discovery from evidence. Reviewed search providers return bounded candidates; canonical target URLs are deduplicated, fetched through `TargetPageFetcher`, parsed and validated by `TargetPhoneValidator`. Search snippets never create evidence. A target becomes `MATCH` only as `PHONE_CONTEXT_MATCH` or `STRUCTURED_PHONE_MATCH`. `NUMERIC_MATCH_ONLY` remains `UNKNOWN`, while resource identifiers become `REJECTED_NUMERIC_ID`.

Accepted target occurrences record complete discovery-to-target provenance, final/canonical URL, target domain, body and normalized-text hashes, page role, structured signal or bounded visible context, source date/warning, and evidence reference. Conservative extraction supports visible email/handle, URL/domain, structured organization/location, and document links. Rejected or unavailable targets cannot create entities, correlations, hypotheses or derived pivots.

Audit and receipts omit the raw phone. The private vault/report may contain it. Findings are at most `POSSIBLE`; no result confirms subscriber, owner, person, or identity.

## PLANNED

- A second enabled provider after terms/privacy review and parser fixtures.
- Provider health monitoring, per-provider budgets, and retry scheduling.
- Durable reviewer handling of public occurrence hypotheses.

## NOT IMPLEMENTED

- Login, signup, account recovery/password reset, CAPTCHA bypass, browser automation, Tor, paid/private APIs, breach databases, Truecaller, WhatsApp/Telegram probing, PhoneInfoga, or automatic identity resolution.
