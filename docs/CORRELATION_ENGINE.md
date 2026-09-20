# Correlation Engine v1

## IMPLEMENTED

`CorrelationEngine` produces `CorrelationCandidate` records for typed entity pairs. It records case ID, endpoints, relation type, evidence references, independent supporting/opposing source groups, confidence, reasons, and status. Exact email evidence is weighted more strongly than a username coincidence. Copies share one independence group, and opposing evidence reduces confidence.

Phone public correlations accept only target-page semantic evidence. Neutral relations are `PHONE MENTIONED_ON WEBSITE`, `WEBSITE MENTIONS EMAIL`, `WEBSITE ASSOCIATED_WITH COMPANY`, and `WEBSITE REFERENCES DOMAIN`. Search-result-only and rejected target observations cannot enter correlation input.

Automatic output is limited to `UNKNOWN`, `POSSIBLE`, `PROBABLE`, or `REJECTED`. `CONFIRMED` requires a matching `ReviewerDecision`.

Etap 14 persists correlation edges and builds `CorrelationPath` explanations across the graph. Path confidence is a weakest-link heuristic with evidence count, unique independence groups, contradiction and circular-provenance penalties; it is not a probability and never creates identity confirmation.

## PLANNED

- Additional conservative technical relation rules and threshold calibration against synthetic benchmarks.
- Reviewer-approved relation vocabulary and threshold calibration.

## NOT IMPLEMENTED

- Automatic identity merge, person resolution, ownership claims, AI verdicts, or cross-case correlation.
