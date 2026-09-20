"""Coverage, diversity and independent corroboration calculations."""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable, Mapping
from urllib.parse import urlsplit

from .models import ReliabilityClass, SourceDiversityScore, SourceReputation


_WEIGHTS = {
    ReliabilityClass.FIRST_PARTY: 0.85,
    ReliabilityClass.OFFICIAL_PUBLIC_REGISTRY: 0.82,
    ReliabilityClass.TECHNICAL_INFRASTRUCTURE: 0.78,
    ReliabilityClass.PUBLIC_PLATFORM: 0.65,
    ReliabilityClass.DIRECTORY: 0.45,
    ReliabilityClass.ARCHIVE: 0.55,
    ReliabilityClass.AGGREGATOR: 0.4,
    ReliabilityClass.UNKNOWN: 0.3,
}


def source_reputation(source_id: str, reputation_class: ReliabilityClass) -> SourceReputation:
    return SourceReputation(
        source_id=source_id, reputation_class=reputation_class, base_weight=_WEIGHTS[reputation_class],
        reasons=("Deterministic source class weight; it is not a truth score.",),
    )


def stale_penalty(*, observed_at: datetime, now: datetime | None = None) -> float:
    current = now or datetime.now(timezone.utc)
    if observed_at.tzinfo is None or current.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    days = max(0, (current - observed_at).days)
    if days <= 180:
        return 0.0
    if days <= 730:
        return 0.15
    return 0.35


def diversity_score(evidence: Iterable[Mapping[str, object]]) -> SourceDiversityScore:
    values = tuple(evidence)
    classes = {str(item.get("source_class", "UNKNOWN")) for item in values}
    domains = {urlsplit(str(item.get("source_url", ""))).hostname for item in values}
    domains.discard(None)
    reputations = {str(item.get("reputation_class", "UNKNOWN")) for item in values}
    first_party = ReliabilityClass.FIRST_PARTY.value in reputations
    archived = ReliabilityClass.ARCHIVE.value in reputations
    technical = bool(reputations & {
        ReliabilityClass.TECHNICAL_INFRASTRUCTURE.value,
        ReliabilityClass.OFFICIAL_PUBLIC_REGISTRY.value,
    })
    textual = bool(reputations & {
        ReliabilityClass.FIRST_PARTY.value, ReliabilityClass.PUBLIC_PLATFORM.value,
        ReliabilityClass.DIRECTORY.value, ReliabilityClass.ARCHIVE.value,
    })
    score = min(1.0, 0.16 * len(classes) + 0.12 * len(domains)
                + 0.12 * first_party + 0.08 * archived + 0.08 * technical + 0.08 * textual)
    return SourceDiversityScore(
        score=round(score, 3), independent_source_classes=len(classes),
        independent_domains=len(domains), first_party_present=first_party, archived_present=archived,
        technical_present=technical, textual_present=textual,
        reasons=("Coverage metric only; copied evidence must share an independence group.",),
    )


class CorroborationEngine:
    """Groups matching claims while keeping copied sources non-independent."""

    def evaluate(self, evidence: Iterable[Mapping[str, object]]) -> tuple[dict[str, object], ...]:
        groups: dict[tuple[str, str, str], list[Mapping[str, object]]] = defaultdict(list)
        for item in evidence:
            key = (str(item.get("subject")), str(item.get("relation")), str(item.get("object")))
            groups[key].append(item)
        output = []
        for key, values in sorted(groups.items()):
            independent = {str(item.get("independence_group", "UNASSESSED")) for item in values}
            classes = {str(item.get("reputation_class", "UNKNOWN")) for item in values}
            output.append({
                "subject": key[0], "relation": key[1], "object": key[2],
                "evidence_count": len(values), "independent_groups": len(independent),
                "cross_type": len({str(item.get("subject_type")) for item in values}
                                  | {str(item.get("object_type")) for item in values}) > 1,
                "corroborated": len(independent) >= 2 and len(classes) >= 2,
                "reasons": ["Independent groups and reputation classes are counted; raw result count is not."],
            })
        return tuple(output)
