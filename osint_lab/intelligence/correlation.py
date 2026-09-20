"""Conservative deterministic entity-correlation scoring."""

import hashlib

from .models import CorrelationCandidate, CorrelationStatus, EntityRef, EvidenceItem


class CorrelationEngine:
    def correlate(
        self,
        *,
        case_id: str,
        left: EntityRef,
        right: EntityRef,
        relation_type: str,
        match_kind: str,
        supporting: tuple[EvidenceItem, ...],
        opposing: tuple[EvidenceItem, ...] = (),
    ) -> CorrelationCandidate:
        token = "|".join((case_id, left.entity_type.value, left.value_reference, right.entity_type.value,
                          right.value_reference, relation_type))
        correlation_id = "corr-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
        independent = len({item.independence_group for item in supporting})
        support_strength = sum(max(0.0, item.quality_score or 0.0) for item in supporting)
        opposition_strength = sum(max(0.0, item.quality_score or 0.0) for item in opposing)
        base = {
            "exact_email": 0.42,
            "exact_domain": 0.35,
            "exact_username": 0.22,
            "exact_phone_public": 0.45,
            "public_extraction": 0.3,
        }.get(match_kind, 0.15)
        confidence = round(max(0.0, min(0.94, base + min(0.36, support_strength * 0.18)
                                         + min(0.12, max(0, independent - 1) * 0.08)
                                         - min(0.5, opposition_strength * 0.25))), 3)
        reasons = [f"match kind: {match_kind}", f"independent support groups: {independent}"]
        if opposing:
            reasons.append("opposing evidence reduces confidence")
        if not supporting:
            status = CorrelationStatus.UNKNOWN
            reasons.append("no supporting evidence")
        elif opposing and opposition_strength >= support_strength:
            status = CorrelationStatus.REJECTED
            reasons.append("opposing evidence is at least as strong as supporting evidence")
        elif confidence >= 0.7 and independent >= 2:
            status = CorrelationStatus.PROBABLE
        else:
            status = CorrelationStatus.POSSIBLE
        return CorrelationCandidate(
            correlation_id=correlation_id,
            case_id=case_id,
            left_entity=left,
            right_entity=right,
            relation_type=relation_type,
            evidence_refs=tuple(item.evidence_id for item in (*supporting, *opposing)),
            supporting_sources=tuple(sorted({item.independence_group for item in supporting})),
            opposing_sources=tuple(sorted({item.independence_group for item in opposing})),
            confidence=confidence,
            reasons=tuple(reasons),
            status=status,
        )
