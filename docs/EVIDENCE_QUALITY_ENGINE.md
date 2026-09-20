# Evidence Quality Engine v1

## IMPLEMENTED

`EvidenceQualityEngine` assigns an explainable score from `0.0` to `1.0` to each `EvidenceItem`. Inputs cover source, source class, collection time, freshness, reproducibility, directness, corroboration, contradictions, match level, target page role, independence group, and `quality_reasons`. Search discovery is capped at `0.05`, rejected numeric IDs at `0.10`, numeric-only candidates at `0.25`, target visible phone context at `0.75`, and structured target telephone evidence at `0.90`. Directories/marketplaces/advertisements and old target pages receive explicit penalties.

`SourceIndependenceEngine` deterministically clusters explicit parent references, target body hashes, normalized visible-text hashes, canonical target URLs, JSON payload fingerprints, and target domains. Discovery providers do not create independence. Copies in one cluster do not count as independent corroboration.

## PLANNED

- Configurable time-decay profiles by source type.
- Persisted reviewer corrections to source grouping.
- Calibrated scoring against a larger synthetic evaluation set.

## NOT IMPLEMENTED

- ML similarity, semantic document comparison, external reputation services, or a truth score.
- A claim that quality score alone verifies identity or ownership.

## ETAP 15 — IMPLEMENTED

Source reputation and age are additional deterministic evidence-quality inputs. First-party/official/technical classes begin above directories/aggregators, while stale archive and document records remain visible with penalties. `SourceDiversityScore` is reported separately as coverage, never as truth. `CorroborationEngine` requires independent groups and distinct source classes instead of counting copied results.
