"""Explainable evidence quality and source-independence heuristics."""

from dataclasses import replace
from datetime import datetime
import hashlib
from urllib.parse import urlsplit, urlunsplit

from .models import Directness, EvidenceItem, EvidenceQualitySummary


class SourceIndependenceEngine:
    """Group copied or derived observations so repetition is not corroboration."""

    @staticmethod
    def canonical_url(value: str | None) -> str | None:
        if not value:
            return None
        parsed = urlsplit(value.strip())
        if not parsed.scheme or not parsed.netloc:
            return value.strip().casefold().rstrip("/")
        return urlunsplit((parsed.scheme.casefold(), parsed.netloc.casefold(), parsed.path.rstrip("/"), parsed.query, ""))

    def cluster(self, items: tuple[EvidenceItem, ...]) -> tuple[EvidenceItem, ...]:
        parents = list(range(len(items)))

        def find(index: int) -> int:
            while parents[index] != index:
                parents[index] = parents[parents[index]]
                index = parents[index]
            return index

        def union(left: int, right: int) -> None:
            left_root, right_root = find(left), find(right)
            if left_root != right_root:
                parents[right_root] = left_root

        first_by_key: dict[str, int] = {}
        keys_by_index: list[set[str]] = []
        for index, item in enumerate(items):
            keys = self._cluster_keys(item)
            keys_by_index.append(keys)
            for key in keys:
                previous = first_by_key.setdefault(key, index)
                union(index, previous)
        component_keys: dict[int, set[str]] = {}
        for index, keys in enumerate(keys_by_index):
            component_keys.setdefault(find(index), set()).update(keys)
        assigned: list[EvidenceItem] = []
        for index, item in enumerate(items):
            digest_source = "|".join(sorted(component_keys[find(index)]))
            digest = hashlib.sha256(digest_source.encode("utf-8")).hexdigest()[:16]
            assigned.append(replace(item, independence_group=f"group-{digest}"))
        return tuple(assigned)

    def _cluster_keys(self, item: EvidenceItem) -> set[str]:
        keys: set[str] = set()
        if item.parent_source_ref:
            keys.add(f"parent:{item.parent_source_ref.casefold()}")
        if item.content_hash:
            keys.add(f"content:{item.content_hash.casefold()}")
        if item.payload_fingerprint:
            keys.add(f"payload:{item.payload_fingerprint.casefold()}")
        canonical = self.canonical_url(item.canonical_url)
        if canonical:
            keys.add(f"url:{canonical}")
        if item.domain:
            keys.add(f"domain:{item.domain.casefold()}")
        return keys or {f"source:{item.source_name.casefold()}"}


class EvidenceQualityEngine:
    """Assign conservative, deterministic scores with human-readable reasons."""

    def __init__(self, independence_engine: SourceIndependenceEngine | None = None) -> None:
        self._independence = independence_engine or SourceIndependenceEngine()

    def assess(
        self,
        items: tuple[EvidenceItem, ...],
        *,
        now: datetime,
    ) -> tuple[tuple[EvidenceItem, ...], EvidenceQualitySummary]:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must include a timezone")
        clustered = self._independence.cluster(items)
        claims: dict[str, set[str]] = {}
        claim_values: dict[str, set[str]] = {}
        for item in clustered:
            if item.claim_key:
                claims.setdefault(item.claim_key, set()).add(item.independence_group)
                if item.claim_value is not None:
                    claim_values.setdefault(item.claim_key, set()).add(item.claim_value)

        assessed: list[EvidenceItem] = []
        for item in clustered:
            age_days = max(0, (now - item.collected_at).days)
            freshness = 1.0 if age_days <= 30 else 0.85 if age_days <= 365 else 0.65 if age_days <= 730 else 0.4
            groups = claims.get(item.claim_key or "", set())
            corroboration_count = max(0, len(groups) - 1)
            values = claim_values.get(item.claim_key or "", set())
            contradiction_count = max(0, len(values) - 1)
            reasons: list[str] = [f"freshness={freshness:.2f} for age {age_days} days"]
            score = 0.45 + (freshness * 0.15)
            if item.directness is Directness.DIRECT:
                score += 0.2
                reasons.append("direct technical observation")
            elif item.directness is Directness.INFERENCE:
                score -= 0.15
                reasons.append("inference is weaker than a direct observation")
            else:
                reasons.append("indirect observation")
            if item.reproducible:
                score += 0.1
                reasons.append("reproducible with the recorded collector")
            else:
                score -= 0.05
                reasons.append("not marked reproducible")
            if corroboration_count:
                score += min(0.15, corroboration_count * 0.075)
                reasons.append(f"corroborated by {corroboration_count} independent group(s)")
            else:
                reasons.append("no independent corroboration")
            if contradiction_count:
                score -= min(0.3, contradiction_count * 0.15)
                reasons.append(f"{contradiction_count} contradictory claim value(s)")
            assessed.append(replace(
                item,
                freshness=freshness,
                corroboration_count=corroboration_count,
                contradiction_count=contradiction_count,
                quality_score=round(max(0.0, min(1.0, score)), 3),
                quality_reasons=tuple(reasons),
            ))

        average = round(sum(item.quality_score or 0.0 for item in assessed) / len(assessed), 3) if assessed else 0.0
        summary = EvidenceQualitySummary(
            evidence_count=len(assessed),
            independent_group_count=len({item.independence_group for item in assessed}),
            average_quality_score=average,
        )
        return tuple(assessed), summary
