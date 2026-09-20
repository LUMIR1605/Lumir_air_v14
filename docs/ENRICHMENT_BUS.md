# Enrichment Bus v1

## IMPLEMENTED

`EnricherRegistry` describes supported/output entity types, source class, network requirement, cost/privacy/information-gain scores, version, enabled state and prerequisites. Default adapters cover phone_metadata, phone_public_web, email_local_metadata, email_exposure, username_lookup and domain_dns.

Production CaseRunner invokes allowed collector steps through `EnrichmentBus`. The bus repeats eligibility, PolicyGate and budgets, suppresses a persistent execution fingerprint, then delegates to the unchanged Orchestrator. Denied planned steps still go through Orchestrator so the established denial audit remains authoritative.

## PLANNED

- User-selected execution of recommended graph pivots and durable retry disposition.

## NOT IMPLEMENTED

- Bypass execution, autonomous crawling, background workers or new aggressive collectors.
