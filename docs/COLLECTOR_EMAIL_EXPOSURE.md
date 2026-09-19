# Email metadata and exposure collectors v1

## IMPLEMENTED

The single-source-class collector contract is preserved by two collectors:

- `EmailLocalMetadataCollector` v1.0.0: `EMAIL`, `LOCAL`, `network_required: false`;
- `EmailExposureCollector` v1.0.0: `EMAIL`, `PASSIVE_WEB`, `network_required: true`.

Both must enter through the existing Orchestrator and registry. PolicyGate evaluates each execution separately. Running the local collector never starts the network collector.

### Input and local metadata

Input is trimmed only at its outer boundary. The ASCII local-part is preserved exactly; the domain is lowercased and converted to IDNA. Empty input, a missing or repeated `@`, unsupported local syntax, invalid domain labels, an unqualified domain, and excessive length are rejected rather than repaired.

The local payload stores the normalized email, local-part, IDNA domain, syntax result, explicit-list metadata, and an orchestration-level reference to `domain_dns`. That reference does not call `DomainDNSCollector`; MX, SPF, and DMARC require a separate `PASSIVE_WEB` execution and its own PolicyGate evaluation.

The free-provider and disposable-provider lists are explicit, incomplete, and versioned as `2026-09-v1`. A match is a technical candidate. Absence from either list yields `null`, never a false certainty.

### Exposure provider

The reviewed v1 provider is the unauthenticated Gravatar public profile endpoint:

- public `GET https://api.gravatar.com/v3/profiles/{email_sha256}`;
- only the provider-normalized SHA-256 identifier and source IP are disclosed;
- HTTP 200 requires reviewed profile JSON markers and is otherwise `UNKNOWN`;
- reviewed HTTP 404 means `AVAILABLE` for this provider only;
- CAPTCHA/challenge signals, 403, 429, redirects, unexpected statuses, generic pages, timeout, and malformed responses cannot become `CLAIMED` or `AVAILABLE`;
- 5xx is a technical `ERROR`, normalized to `UNKNOWN`.

Gravatar documents SHA-256 email identifiers, unauthenticated limited profile access, 200 profile responses, 404 absence, and 429 rate limiting at <https://docs.gravatar.com/rest-api/> and <https://docs.gravatar.com/rest/hash/>. Provider configuration and detection rules are registry-bound by SHA-256. Tests mock all HTTP and run offline.

`CLAIMED` normalizes to `POSSIBLE`, `AVAILABLE` to `NOT_FOUND`, and `UNKNOWN`/`ERROR` to `UNKNOWN`. No collector result is `CONFIRMED`. The result is a service/profile candidate, not proof that a person controls the email or profile.

### Privacy and evidence

The audit contains the Orchestrator seed hash, not raw email. The private Evidence Vault may store raw local metadata and technical provider evidence. The ExecutionReceipt contains only execution metadata, evidence references, and the audit head hash. Exposure observations use an email SHA-256 reference and do not place raw email in the endpoint, payload, or value reference.

### Holehe decision

Holehe is not integrated. The existing `shield/holehe_scan.py` launches a subprocess, and Holehe's own provider catalog documents register, login, and password-recovery methods. Those behaviors conflict with this stage's no-subprocess and no-signup/login/reset policy. No SHIELD adapter is imported or executed by OSINT LAB. A future adapter boundary requires a provider-by-provider review and may still be rejected.

## PLANNED

- Orchestration scheduling that can explicitly queue `domain_dns` after operator approval, while retaining a separate PolicyGate decision.
- Reviewed provider lifecycle, rate-budget enforcement, caching, and provider fixture refresh procedures.
- Optional neutral `EMAIL -> DOMAIN` graph persistence if it can be added without identity inference or a broad graph redesign.

## NOT IMPLEMENTED

- Breach database queries or HIBP API access.
- Password-reset, forgot-password, login, signup, account-recovery, MFA, CAPTCHA, challenge, or credential-checking flows.
- Holehe execution, subprocesses, browser automation, authenticated scraping, private content, or credential stuffing.
- Identity ownership confirmation, person-email relations, automatic identity merge, or `CONFIRMED` identity findings.
- Tor, paid APIs, direct-target access, or secret-bearing provider configuration.
- Automatic execution of DNS intelligence from the local collector.

