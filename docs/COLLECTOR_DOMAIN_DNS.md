# DomainDNSCollector v1

## IMPLEMENTED

`DomainDNSCollector` is a controlled `PASSIVE_WEB` collector backed by the existing `dnspython` dependency.

Identity:

- `agent_name`: `domain_dns`
- `agent_type`: `DOMAIN`
- `version`: `1.0.0`
- `source_class`: `PASSIVE_WEB`
- `network_required`: `true`

The collector accepts a multi-label domain or host, trims outer whitespace, lowercases it, removes one final dot, and converts supported Unicode labels to IDNA ASCII. URLs, paths, ports, wildcards, IP addresses, empty labels, internal whitespace, and obviously invalid hostnames are rejected.

Supported v1 observations are `A`, `AAAA`, `MX`, `NS`, `TXT`, extracted `SPF`, and `_dmarc.<domain>` `DMARC`. Each JSON-safe payload records the normalized domain, query name/type, status, raw technical records, TTL, resolver label, and sanitized error code/reason. Full DNS evidence stays in the private Evidence Vault; audit stores only the input SHA-256 and the receipt stores evidence references.

The default collector creates an explicit system-configured resolver with bounded timeout/lifetime. Tests inject a deterministic fake resolver. No global resolver or registry singleton exists. DNS requests leave the computer and may disclose the queried hostname to the configured resolver.

Status semantics:

- `FOUND`: the requested record was returned.
- `NOT_FOUND`: a completed response safely contained no answer or no matching SPF/DMARC TXT value.
- `NXDOMAIN`: the queried name did not exist; this is preserved explicitly and is not silently generalized.
- `UNKNOWN`: timeout or no usable nameserver response.
- `ERROR`: an unexpected resolver or DNS protocol error.

SPF extraction keeps every TXT value beginning with `v=spf1`; it does not recursively analyze `include`. DMARC extraction preserves the raw record and extracts `p`, `sp`, `pct`, `rua`, and `ruf` without rating the policy. Candidates remain technical `POSSIBLE`, `NOT_FOUND`, or `UNKNOWN` facts and never confirm identity or ownership.

## PLANNED

- Resolver allowlists or explicit enterprise resolver profiles.
- DNSSEC validation and record freshness policy after separate review.
- Optional, separately marked live integration diagnostics outside the deterministic suite.

## NOT IMPLEMENTED

- WHOIS or RDAP.
- Reverse IP lookup, passive DNS history, or subdomain enumeration.
- HTTP probing, browser access, SSL/TLS inspection, or subprocess execution.
- Ownership, organization, person, or IP-owner inference.
- Commercial APIs, threat intelligence, reputation scoring, or policy safety ratings.
- Recursive SPF include evaluation or DMARC enforcement assessment.
