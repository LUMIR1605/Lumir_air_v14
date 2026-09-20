"""Deterministic hypothesis assessment without identity overclaims."""

import re

from .models import EvidenceItem, Hypothesis, HypothesisStatus


_IDENTITY_ASSERTION = re.compile(
    r"\b(?:belongs\s+to|należy\s+do|is\s+(?:the\s+)?(?:owner|person)|jest\s+(?:właścicielem|osobą))\b",
    re.IGNORECASE,
)


class HypothesisEngine:
    def assess(
        self,
        hypothesis: Hypothesis,
        *,
        supporting: tuple[EvidenceItem, ...],
        opposing: tuple[EvidenceItem, ...] = (),
    ) -> Hypothesis:
        if _IDENTITY_ASSERTION.search(hypothesis.statement):
            raise ValueError("unverified ownership or person assertion is not permitted")
        grouped_support: dict[str, float] = {}
        for item in supporting:
            grouped_support[item.independence_group] = max(grouped_support.get(item.independence_group, 0.0),
                                                            item.quality_score or 0.0)
        grouped_opposition: dict[str, float] = {}
        for item in opposing:
            grouped_opposition[item.independence_group] = max(grouped_opposition.get(item.independence_group, 0.0),
                                                               item.quality_score or 0.0)
        support = sum(grouped_support.values())
        opposition = sum(grouped_opposition.values())
        temporal_conflict = any(item.contradiction_count > 0 for item in supporting)
        confidence = round(max(0.0, min(0.94, 0.2 + support * 0.2 - opposition * 0.25)), 3)
        reasons = [f"{len(grouped_support)} independent supporting group(s)",
                   f"{len(grouped_opposition)} independent opposing group(s)"]
        if not supporting:
            status = HypothesisStatus.OPEN
            confidence = 0.15
            reasons.append("hypothesis remains unsupported")
        elif opposition >= support and opposing:
            status = HypothesisStatus.REJECTED
            reasons.append("opposition is at least as strong as support")
        elif opposing or temporal_conflict:
            status = HypothesisStatus.WEAKENED
            if opposing:
                reasons.append("material opposing evidence exists")
            if temporal_conflict:
                confidence = round(max(0.0, confidence - 0.15), 3)
                reasons.append("contradictory claim values indicate a temporal or factual conflict")
        elif confidence >= 0.6 and len(grouped_support) >= 2:
            status = HypothesisStatus.SUPPORTED
        else:
            status = HypothesisStatus.OPEN
        return Hypothesis(
            hypothesis_id=hypothesis.hypothesis_id,
            case_id=hypothesis.case_id,
            statement=hypothesis.statement,
            subject_entities=hypothesis.subject_entities,
            evidence_for=tuple(item.evidence_id for item in supporting),
            evidence_against=tuple(item.evidence_id for item in opposing),
            evidence_unknown=hypothesis.evidence_unknown,
            status=status,
            confidence=confidence,
            created_at=hypothesis.created_at,
            updated_at=max((hypothesis.updated_at, *(item.collected_at for item in (*supporting, *opposing)))),
            alternative_explanations=hypothesis.alternative_explanations,
            reasons=tuple(reasons),
            unresolved_questions=hypothesis.unresolved_questions,
        )
