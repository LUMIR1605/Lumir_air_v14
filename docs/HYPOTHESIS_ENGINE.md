# Hypothesis Engine v1

## IMPLEMENTED

`Hypothesis` records its case, subject entities, evidence for/against/unknown, timestamps, confidence, reasons, unresolved questions, alternatives, and status. Scoring uses per-independence-group maxima rather than a simple average. Independent support raises confidence; opposition and temporal conflict weaken or reject it. Unsupported hypotheses remain `OPEN`.

The engine rejects unreviewed direct owner/person assertions. It never assigns `VERIFIED`; only a matching reviewer decision can do that.

Graph-enabled runs attach supporting `CorrelationPath` IDs to hypotheses and expose `PATH_SUPPORTED` or `NO_GRAPH_PATH` without promoting status. The dossier preserves alternatives, contradictions and unresolved questions beside those paths.

## PLANNED

- More temporal-consistency rules and explicit evidence-unknown generation.
- Full persisted hypothesis event lifecycle and analyst editing UI.

## NOT IMPLEMENTED

- LLM-generated hypotheses, autonomous truth verdicts, automatic ownership, or automatic person linkage.
