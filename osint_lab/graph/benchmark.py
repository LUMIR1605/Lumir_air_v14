"""Synthetic graph benchmark metrics; no real identifiers or comparative claims."""

from dataclasses import dataclass
from time import perf_counter
from typing import Iterable, Mapping


@dataclass(frozen=True)
class BenchmarkMetrics:
    precision: float
    false_positive_count: int
    rejected_false_positives: int
    unknown_count: int
    relation_accuracy: float
    hypothesis_accuracy: float
    independent_evidence_count: int
    pivot_efficiency: float
    graph_size: int
    execution_time: float
    verified_evidence_count: int
    unique_source_classes: int
    useful_entities_discovered: int
    useful_pivots_generated: int
    provider_failure_rate: float
    avg_network_requests_per_useful_finding: float

    def to_dict(self) -> dict[str, object]:
        return dict(self.__dict__)


def score_benchmark(*, predicted: Iterable[Mapping[str, object]], expected: Iterable[Mapping[str, object]],
                    started_at: float | None = None, pivot_count: int = 0, useful_pivots: int = 0,
                    network_requests: int = 0, provider_runs: int = 0, provider_failures: int = 0) -> BenchmarkMetrics:
    predicted_values = tuple(predicted)
    expected_values = tuple(expected)
    expected_map = {str(item["id"]): str(item["label"]) for item in expected_values}
    predicted_map = {str(item["id"]): str(item["label"]) for item in predicted_values}
    positives = {key for key, value in predicted_map.items() if value in {"TRUE", "PROBABLE", "CONFIRMED"}}
    true_positives = sum(expected_map.get(key) == "TRUE" for key in positives)
    false_positives = sum(expected_map.get(key) != "TRUE" for key in positives)
    precision = true_positives / max(1, true_positives + false_positives)
    relation_ids = {key for key in expected_map if key.startswith("relation:")}
    hypothesis_ids = {key for key in expected_map if key.startswith("hypothesis:")}
    accuracy = lambda ids: sum(predicted_map.get(key) == expected_map[key] for key in ids) / max(1, len(ids))
    elapsed = max(0.0, perf_counter() - started_at) if started_at is not None else 0.0
    return BenchmarkMetrics(
        precision=round(precision, 4), false_positive_count=false_positives,
        rejected_false_positives=sum(value == "REJECTED" for value in predicted_map.values()),
        unknown_count=sum(value == "UNKNOWN" for value in predicted_map.values()),
        relation_accuracy=round(accuracy(relation_ids), 4), hypothesis_accuracy=round(accuracy(hypothesis_ids), 4),
        independent_evidence_count=len({str(item.get("independence_group")) for item in predicted_values
                                        if item.get("independence_group")}),
        pivot_efficiency=round(useful_pivots / max(1, pivot_count), 4),
        graph_size=len(predicted_values), execution_time=round(elapsed, 6),
        verified_evidence_count=sum(bool(item.get("verified")) for item in predicted_values),
        unique_source_classes=len({str(item.get("source_class")) for item in predicted_values
                                   if item.get("source_class")}),
        useful_entities_discovered=sum(bool(item.get("useful_entity")) for item in predicted_values),
        useful_pivots_generated=useful_pivots,
        provider_failure_rate=round(provider_failures / max(1, provider_runs), 4),
        avg_network_requests_per_useful_finding=round(
            network_requests / max(1, true_positives), 4
        ),
    )


def compare_source_expansion(*, before: BenchmarkMetrics, after: BenchmarkMetrics) -> dict[str, object]:
    return {
        "coverage_improved": after.verified_evidence_count > before.verified_evidence_count
        or after.useful_entities_discovered > before.useful_entities_discovered,
        "false_positive_rate_not_worse": after.false_positive_count <= before.false_positive_count,
        "independent_corroboration_improved": (
            after.independent_evidence_count >= before.independent_evidence_count
        ),
        "useful_pivots_improved": after.useful_pivots_generated >= before.useful_pivots_generated,
        "success": (
            (after.verified_evidence_count > before.verified_evidence_count
             or after.useful_entities_discovered > before.useful_entities_discovered)
            and after.false_positive_count <= before.false_positive_count
            and after.independent_evidence_count >= before.independent_evidence_count
            and after.useful_pivots_generated >= before.useful_pivots_generated
        ),
    }
