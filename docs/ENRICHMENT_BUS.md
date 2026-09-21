# Enrichment Bus v1

## IMPLEMENTED

`EnricherRegistry` describes supported/output entity types, source class, network requirement, cost/privacy/information-gain scores, version, enabled state and prerequisites. Default adapters cover phone_metadata, phone_public_web, email_local_metadata, email_exposure, username_lookup and domain_dns.

Production CaseRunner invokes allowed collector steps through `EnrichmentBus`. The bus repeats eligibility, PolicyGate and budgets, suppresses a persistent execution fingerprint, then delegates to the unchanged Orchestrator. Denied planned steps still go through Orchestrator so the established denial audit remains authoritative.

Stage 15.1 adds fail-closed startup validation for collector/enricher metadata and every non-local `EnricherDefinition.source_id`. Automatic execution additionally requires an enabled, reviewed, automation-allowed `SourceDefinition`. The bus exposes deterministic `collector_id`, `enricher_id`, logical `source_id` and `source_registry_id` mappings; coverage never reconstructs these IDs from an observation payload.

## PLANNED

- User-selected execution of `MANUAL_REQUIRED` pivots and durable retry disposition.

## NOT IMPLEMENTED

- Bypass execution, autonomous crawling, background workers or new aggressive collectors.

## ETAP 15 — IMPLEMENTED

The registry now also routes `email_public_web`, `domain_rdap`, `website_metadata`, `company_public_web`, `document_intelligence` and `public_archive`. Every adapter still delegates through PolicyGate, CollectorRegistry and Orchestrator. Pivots declare `AUTO` or `MANUAL_REQUIRED`; automatic execution requires an enabled reviewed source, allowed case policy, hop/pivot/request budgets, a new fingerprint and privacy cost at or below `0.6`. Each executed pivot is written to CaseEvent Bus.
