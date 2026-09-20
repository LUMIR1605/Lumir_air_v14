# Hypothesis Engine v1

## IMPLEMENTED

`Hypothesis` records its case, subject entities, evidence for/against/unknown, timestamps, confidence, reasons, unresolved questions, alternatives, and status. Scoring uses per-independence-group maxima rather than a simple average. Independent support raises confidence; opposition and temporal conflict weaken or reject it. Unsupported hypotheses remain `OPEN`.

The engine rejects unreviewed direct owner/person assertions. It never assigns `VERIFIED`; only a matching reviewer decision can do that.

## PLANNED

- More temporal-consistency rules and explicit evidence-unknown generation.
- Persisted hypothesis lifecycle and reviewer history.

## NOT IMPLEMENTED

- LLM-generated hypotheses, autonomous truth verdicts, automatic ownership, or automatic person linkage.
