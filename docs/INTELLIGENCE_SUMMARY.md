# IntelligenceSummary v1

## IMPLEMENTED

After collection, `IntelligenceCore` creates an `IntelligenceSummary` with known technical facts, probable correlations, open/rejected hypotheses, contradictions, evidence-quality detail and summary, adversarial reviews, recommended pivots, and unresolved questions. The JSON representation carries explicit `FACT`, `CORRELATION`, `HYPOTHESIS`, and `VERIFICATION` layer labels.

CaseRunner stores the summary additively in the run record and passes it to the private report. Collector execution order and enforcement are unchanged.

## PLANNED

- Durable reviewer workflow and versioned re-analysis of an existing evidence set.
- Dossier export and explicitly approved redacted views.

## NOT IMPLEMENTED

- Public sharing, AI narrative generation, automatic identity merge, or cross-case intelligence.
