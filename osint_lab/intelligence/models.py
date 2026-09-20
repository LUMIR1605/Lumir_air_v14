"""Validated, JSON-safe models for deterministic intelligence analysis."""

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum


def _text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


def _score(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise ValueError(f"{name} must be between 0 and 1")


def _strings(name: str, values: tuple[str, ...]) -> None:
    if not isinstance(values, tuple) or any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValueError(f"{name} must contain non-empty strings")


class EntityType(str, Enum):
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    USERNAME = "USERNAME"
    DOMAIN = "DOMAIN"
    WEBSITE = "WEBSITE"
    COMPANY = "COMPANY"
    DOCUMENT = "DOCUMENT"
    SOCIAL_PROFILE = "SOCIAL_PROFILE"
    LOCATION = "LOCATION"
    OTHER = "OTHER"


class Directness(str, Enum):
    DIRECT = "DIRECT"
    INDIRECT = "INDIRECT"
    INFERENCE = "INFERENCE"


class CorrelationStatus(str, Enum):
    POSSIBLE = "POSSIBLE"
    PROBABLE = "PROBABLE"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


class HypothesisStatus(str, Enum):
    OPEN = "OPEN"
    SUPPORTED = "SUPPORTED"
    WEAKENED = "WEAKENED"
    REJECTED = "REJECTED"
    VERIFIED = "VERIFIED"


class AdversarialResult(str, Enum):
    UNTESTED = "UNTESTED"
    SURVIVES = "SURVIVES"
    WEAKENED = "WEAKENED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class PivotStatus(str, Enum):
    RECOMMENDED = "RECOMMENDED"
    OPTIONAL = "OPTIONAL"
    LOW_VALUE = "LOW_VALUE"
    BLOCKED = "BLOCKED"


class ReviewerDecisionType(str, Enum):
    CONFIRM = "CONFIRM"
    REJECT = "REJECT"
    KEEP_OPEN = "KEEP_OPEN"


class ReviewTargetType(str, Enum):
    CORRELATION = "CORRELATION"
    HYPOTHESIS = "HYPOTHESIS"


@dataclass(frozen=True, kw_only=True)
class EntityRef:
    entity_type: EntityType
    value_reference: str

    def __post_init__(self) -> None:
        if not isinstance(self.entity_type, EntityType):
            raise ValueError("entity_type must be an EntityType")
        _text("value_reference", self.value_reference)

    def to_dict(self) -> dict[str, str]:
        return {"entity_type": self.entity_type.value, "value_reference": self.value_reference}


@dataclass(frozen=True, kw_only=True)
class EvidenceItem:
    evidence_id: str
    source_name: str
    source_class: str
    collected_at: datetime
    freshness: float = 0.0
    independence_group: str = "UNASSESSED"
    reproducible: bool = False
    directness: Directness = Directness.INDIRECT
    corroboration_count: int = 0
    contradiction_count: int = 0
    quality_score: float | None = None
    quality_reasons: tuple[str, ...] = ()
    canonical_url: str | None = None
    domain: str | None = None
    content_hash: str | None = None
    payload_fingerprint: str | None = None
    parent_source_ref: str | None = None
    claim_key: str | None = None
    claim_value: str | None = None
    match_level: str | None = None

    def __post_init__(self) -> None:
        for name in ("evidence_id", "source_name", "source_class", "independence_group"):
            _text(name, getattr(self, name))
        _aware("collected_at", self.collected_at)
        _score("freshness", self.freshness)
        if not isinstance(self.reproducible, bool) or not isinstance(self.directness, Directness):
            raise ValueError("invalid evidence classification")
        if self.corroboration_count < 0 or self.contradiction_count < 0:
            raise ValueError("evidence counts cannot be negative")
        if self.quality_score is not None:
            _score("quality_score", self.quality_score)
            if not self.quality_reasons:
                raise ValueError("assessed evidence must explain its quality score")
        if self.match_level is not None:
            _text("match_level", self.match_level)
        _strings("quality_reasons", self.quality_reasons)

    @property
    def reasons(self) -> tuple[str, ...]:
        return self.quality_reasons

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "source_name": self.source_name,
            "source_class": self.source_class,
            "collected_at": self.collected_at.isoformat(),
            "freshness": self.freshness,
            "independence_group": self.independence_group,
            "reproducible": self.reproducible,
            "directness": self.directness.value,
            "corroboration_count": self.corroboration_count,
            "contradiction_count": self.contradiction_count,
            "quality_score": self.quality_score,
            "quality_reasons": list(self.quality_reasons),
            "match_level": self.match_level,
        }


@dataclass(frozen=True, kw_only=True)
class CorrelationCandidate:
    correlation_id: str
    case_id: str
    left_entity: EntityRef
    right_entity: EntityRef
    relation_type: str
    evidence_refs: tuple[str, ...]
    supporting_sources: tuple[str, ...]
    opposing_sources: tuple[str, ...]
    confidence: float
    reasons: tuple[str, ...]
    status: CorrelationStatus
    verification_decision_id: str | None = None

    def __post_init__(self) -> None:
        _text("correlation_id", self.correlation_id)
        _text("case_id", self.case_id)
        _text("relation_type", self.relation_type)
        if not isinstance(self.left_entity, EntityRef) or not isinstance(self.right_entity, EntityRef):
            raise ValueError("correlation endpoints must be EntityRef values")
        if not isinstance(self.status, CorrelationStatus):
            raise ValueError("invalid correlation status")
        _score("confidence", self.confidence)
        for name in ("evidence_refs", "supporting_sources", "opposing_sources", "reasons"):
            _strings(name, getattr(self, name))
        if self.status is CorrelationStatus.CONFIRMED and not self.verification_decision_id:
            raise ValueError("CONFIRMED requires an explicit reviewer decision")

    @property
    def left(self) -> EntityRef:
        return self.left_entity

    @property
    def right(self) -> EntityRef:
        return self.right_entity

    @property
    def supporting_evidence(self) -> tuple[str, ...]:
        return self.evidence_refs

    @property
    def opposing_evidence(self) -> tuple[str, ...]:
        return self.opposing_sources

    def to_dict(self) -> dict[str, object]:
        return {
            "correlation_id": self.correlation_id,
            "case_id": self.case_id,
            "left_entity": self.left_entity.to_dict(),
            "right_entity": self.right_entity.to_dict(),
            "relation_type": self.relation_type,
            "evidence_refs": list(self.evidence_refs),
            "supporting_sources": list(self.supporting_sources),
            "opposing_sources": list(self.opposing_sources),
            "status": self.status.value,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
            "verification_decision_id": self.verification_decision_id,
        }


@dataclass(frozen=True, kw_only=True)
class Hypothesis:
    hypothesis_id: str
    case_id: str
    statement: str
    subject_entities: tuple[EntityRef, ...]
    evidence_for: tuple[str, ...]
    evidence_against: tuple[str, ...]
    evidence_unknown: tuple[str, ...]
    status: HypothesisStatus
    confidence: float
    created_at: datetime
    updated_at: datetime
    reasons: tuple[str, ...]
    unresolved_questions: tuple[str, ...]
    alternative_explanations: tuple[str, ...] = ()
    verification_decision_id: str | None = None

    def __post_init__(self) -> None:
        _text("hypothesis_id", self.hypothesis_id)
        _text("case_id", self.case_id)
        _text("statement", self.statement)
        if not isinstance(self.subject_entities, tuple) or any(not isinstance(item, EntityRef) for item in self.subject_entities):
            raise ValueError("subject_entities must contain EntityRef values")
        if not isinstance(self.status, HypothesisStatus):
            raise ValueError("invalid hypothesis status")
        _score("confidence", self.confidence)
        _aware("created_at", self.created_at)
        _aware("updated_at", self.updated_at)
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        for name in ("evidence_for", "evidence_against", "evidence_unknown", "alternative_explanations",
                     "reasons", "unresolved_questions"):
            _strings(name, getattr(self, name))
        if self.status is HypothesisStatus.VERIFIED and not self.verification_decision_id:
            raise ValueError("VERIFIED requires an explicit reviewer decision")

    @property
    def supporting_evidence(self) -> tuple[str, ...]:
        return self.evidence_for

    @property
    def opposing_evidence(self) -> tuple[str, ...]:
        return self.evidence_against

    def to_dict(self) -> dict[str, object]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "case_id": self.case_id,
            "statement": self.statement,
            "subject_entities": [item.to_dict() for item in self.subject_entities],
            "status": self.status.value,
            "confidence": self.confidence,
            "evidence_for": list(self.evidence_for),
            "evidence_against": list(self.evidence_against),
            "evidence_unknown": list(self.evidence_unknown),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "alternative_explanations": list(self.alternative_explanations),
            "reasons": list(self.reasons),
            "unresolved_questions": list(self.unresolved_questions),
            "verification_decision_id": self.verification_decision_id,
        }


@dataclass(frozen=True, kw_only=True)
class AdversarialReview:
    review_id: str
    hypothesis_id: str
    counter_questions: tuple[str, ...]
    opposing_evidence_refs: tuple[str, ...]
    ambiguity_reasons: tuple[str, ...]
    alternative_explanations: tuple[str, ...]
    result: AdversarialResult

    def __post_init__(self) -> None:
        _text("review_id", self.review_id)
        _text("hypothesis_id", self.hypothesis_id)
        if not isinstance(self.result, AdversarialResult):
            raise ValueError("invalid adversarial result")
        for name in ("counter_questions", "opposing_evidence_refs", "ambiguity_reasons", "alternative_explanations"):
            _strings(name, getattr(self, name))

    @property
    def target_id(self) -> str:
        return self.hypothesis_id

    @property
    def challenges(self) -> tuple[str, ...]:
        return (*self.counter_questions, *self.alternative_explanations)

    def to_dict(self) -> dict[str, object]:
        return {"review_id": self.review_id, "hypothesis_id": self.hypothesis_id,
                "counter_questions": list(self.counter_questions),
                "opposing_evidence_refs": list(self.opposing_evidence_refs),
                "ambiguity_reasons": list(self.ambiguity_reasons),
                "alternative_explanations": list(self.alternative_explanations), "result": self.result.value}


@dataclass(frozen=True, kw_only=True)
class PivotCandidate:
    pivot_id: str
    from_entity: EntityRef
    proposed_collector: str
    proposed_input: str
    source_class: str
    expected_information_gain: float
    privacy_cost: float
    network_cost: float
    duplication_risk: float
    reason: str
    status: PivotStatus

    def __post_init__(self) -> None:
        for name in ("pivot_id", "proposed_collector", "proposed_input", "source_class", "reason"):
            _text(name, getattr(self, name))
        if not isinstance(self.from_entity, EntityRef):
            raise ValueError("from_entity must be an EntityRef")
        if not isinstance(self.status, PivotStatus):
            raise ValueError("invalid pivot status")
        _score("expected_information_gain", self.expected_information_gain)
        _score("privacy_cost", self.privacy_cost)
        _score("network_cost", self.network_cost)
        _score("duplication_risk", self.duplication_risk)

    @property
    def action(self) -> str:
        return self.proposed_collector

    @property
    def cost(self) -> float:
        return round((self.privacy_cost + self.network_cost) / 2, 3)

    def to_dict(self) -> dict[str, object]:
        return {"pivot_id": self.pivot_id, "from_entity": self.from_entity.to_dict(),
                "proposed_collector": self.proposed_collector, "proposed_input": self.proposed_input,
                "source_class": self.source_class, "expected_information_gain": self.expected_information_gain,
                "privacy_cost": self.privacy_cost, "network_cost": self.network_cost,
                "duplication_risk": self.duplication_risk, "reason": self.reason, "status": self.status.value}


@dataclass(frozen=True, kw_only=True)
class ReviewerDecision:
    decision_id: str
    target_type: ReviewTargetType
    target_id: str
    decision: ReviewerDecisionType
    reviewer: str
    timestamp: datetime
    notes: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("decision_id", "target_id", "reviewer", "notes"):
            _text(name, getattr(self, name))
        if not isinstance(self.target_type, ReviewTargetType) or not isinstance(self.decision, ReviewerDecisionType):
            raise ValueError("invalid reviewer decision")
        _aware("timestamp", self.timestamp)
        _strings("evidence_refs", self.evidence_refs)

    def to_dict(self) -> dict[str, object]:
        return {"decision_id": self.decision_id, "target_type": self.target_type.value,
                "target_id": self.target_id, "decision": self.decision.value, "reviewer": self.reviewer,
                "timestamp": self.timestamp.isoformat(), "notes": self.notes,
                "evidence_refs": list(self.evidence_refs)}


@dataclass(frozen=True, kw_only=True)
class KnownFact:
    statement: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _text("statement", self.statement)
        _strings("evidence_refs", self.evidence_refs)

    def to_dict(self) -> dict[str, object]:
        return {"statement": self.statement, "evidence_refs": list(self.evidence_refs), "label": "FACT"}


@dataclass(frozen=True, kw_only=True)
class EvidenceQualitySummary:
    evidence_count: int
    independent_group_count: int
    average_quality_score: float

    def __post_init__(self) -> None:
        if self.evidence_count < 0 or self.independent_group_count < 0:
            raise ValueError("evidence summary counts cannot be negative")
        _score("average_quality_score", self.average_quality_score)

    def to_dict(self) -> dict[str, object]:
        return {"evidence_count": self.evidence_count, "independent_group_count": self.independent_group_count,
                "average_quality_score": self.average_quality_score}


@dataclass(frozen=True, kw_only=True)
class IntelligenceSummary:
    known_facts: tuple[KnownFact, ...] = ()
    probable_correlations: tuple[CorrelationCandidate, ...] = ()
    open_hypotheses: tuple[Hypothesis, ...] = ()
    rejected_hypotheses: tuple[Hypothesis, ...] = ()
    contradictions: tuple[str, ...] = ()
    evidence_quality: tuple[EvidenceItem, ...] = ()
    evidence_quality_summary: EvidenceQualitySummary = field(
        default_factory=lambda: EvidenceQualitySummary(evidence_count=0, independent_group_count=0,
                                                       average_quality_score=0.0)
    )
    adversarial_reviews: tuple[AdversarialReview, ...] = ()
    recommended_pivots: tuple[PivotCandidate, ...] = ()
    unresolved_questions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _strings("contradictions", self.contradictions)
        _strings("unresolved_questions", self.unresolved_questions)

    @property
    def correlations(self) -> tuple[CorrelationCandidate, ...]:
        return self.probable_correlations

    @property
    def hypotheses(self) -> tuple[Hypothesis, ...]:
        return self.open_hypotheses

    def to_dict(self) -> dict[str, object]:
        alternatives = sorted({item for hypothesis in self.open_hypotheses for item in hypothesis.alternative_explanations})
        alternatives.extend(
            challenge for review in self.adversarial_reviews for challenge in review.challenges
            if challenge not in alternatives
        )
        return {
            "known_technical_facts": [item.to_dict() for item in self.known_facts],
            "probable_correlations": [item.to_dict() for item in self.probable_correlations],
            "open_hypotheses": [item.to_dict() for item in self.open_hypotheses],
            "rejected_hypotheses": [item.to_dict() for item in self.rejected_hypotheses],
            "contradictions": list(self.contradictions),
            "contradictory_evidence": list(self.contradictions),
            "evidence_quality": [item.to_dict() for item in self.evidence_quality],
            "evidence_quality_summary": self.evidence_quality_summary.to_dict(),
            "alternative_explanations": alternatives,
            "adversarial_reviews": [item.to_dict() for item in self.adversarial_reviews],
            "recommended_next_pivots": [item.to_dict() for item in self.recommended_pivots],
            "unresolved_questions": list(self.unresolved_questions),
            "layer_labels": ["FACT", "CORRELATION", "HYPOTHESIS", "VERIFICATION"],
        }


def replace_correlation(value: CorrelationCandidate, **changes: object) -> CorrelationCandidate:
    return replace(value, **changes)


def replace_hypothesis(value: Hypothesis, **changes: object) -> Hypothesis:
    return replace(value, **changes)
