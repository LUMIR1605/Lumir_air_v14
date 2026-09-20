# Source Reputation v1

## IMPLEMENTED

Deterministic classes: `FIRST_PARTY`, `OFFICIAL_PUBLIC_REGISTRY`, `TECHNICAL_INFRASTRUCTURE`, `PUBLIC_PLATFORM`, `DIRECTORY`, `ARCHIVE`, `AGGREGATOR`, `UNKNOWN`. `source_reputation()` returns a documented base weight. First-party and official registry evidence receive higher initial evidence-quality weight than directories, while stale evidence receives an explicit time penalty.

The value is an evidence-quality input and coverage characteristic, never a truth, ownership or identity score.

## NOT IMPLEMENTED

- External reputation feeds, ML ranking or automatic truth verdicts.
