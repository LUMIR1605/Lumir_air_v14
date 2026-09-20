# Case Event Bus v1

## IMPLEMENTED

The local SQLite `case_events` table is append-only and records SEED_ADDED, ENTITY_CREATED/UPDATED, RELATION_CREATED, EVIDENCE_ADDED, PIVOT_PROPOSED/EXECUTED, HYPOTHESIS_CREATED/CHANGED, REVIEW_DECISION, CONTRADICTION_FOUND and REPORT_GENERATED event types. Current integration emits seed, evidence, relation, pivot, review and report events; unused types establish the stable schema for later producers.

## PLANNED

- Event replay API, hypothesis lifecycle emitters and cancellation/resume consumers.

## NOT IMPLEMENTED

- Kafka, distributed delivery, cross-machine ordering or background consumers.
