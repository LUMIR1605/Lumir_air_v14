# Evidence Quality Engine v1

## IMPLEMENTED

`EvidenceQualityEngine` assigns an explainable score from `0.0` to `1.0` to each `EvidenceItem`. Inputs cover source, source class, collection time, freshness, reproducibility, directness, corroboration, contradictions, independence group, and `quality_reasons`. Direct reproducible observations score above indirect inference; stale or contradictory evidence scores lower.

`SourceIndependenceEngine` deterministically clusters explicit parent references, content hashes, canonical URLs, JSON payload fingerprints, and domains. Copies in one cluster do not count as independent corroboration. Exact normalized payload fingerprints are the v1 near-identity heuristic.

## PLANNED

- Configurable time-decay profiles by source type.
- Persisted reviewer corrections to source grouping.
- Calibrated scoring against a larger synthetic evaluation set.

## NOT IMPLEMENTED

- ML similarity, semantic document comparison, external reputation services, or a truth score.
- A claim that quality score alone verifies identity or ownership.
