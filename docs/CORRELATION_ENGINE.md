# Correlation Engine v1

## IMPLEMENTED

`CorrelationEngine` produces `CorrelationCandidate` records for typed entity pairs. It records case ID, endpoints, relation type, evidence references, independent supporting/opposing source groups, confidence, reasons, and status. Exact email evidence is weighted more strongly than a username coincidence. Copies share one independence group, and opposing evidence reduces confidence.

Automatic output is limited to `UNKNOWN`, `POSSIBLE`, `PROBABLE`, or `REJECTED`. `CONFIRMED` requires a matching `ReviewerDecision`.

## PLANNED

- Additional conservative technical relation rules and persisted correlation graph integration.
- Reviewer-approved relation vocabulary and threshold calibration.

## NOT IMPLEMENTED

- Automatic identity merge, person resolution, ownership claims, AI verdicts, or cross-case correlation.
