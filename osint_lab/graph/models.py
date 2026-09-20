"""Validated models for the persistent case knowledge graph."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Mapping

from osint_lab.case_manifest import validate_case_id


def _text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


def _score(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise ValueError(f"{name} must be between 0 and 1")


def _texts(name: str, values: tuple[str, ...], *, required: bool = False) -> None:
    if not isinstance(values, tuple) or any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValueError(f"{name} must contain non-empty strings")
    if required and not values:
        raise ValueError(f"{name} must not be empty")


class GraphEntityType(str, Enum):
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    USERNAME = "USERNAME"
    DOMAIN = "DOMAIN"
    WEBSITE = "WEBSITE"
    COMPANY = "COMPANY"
    ORGANIZATION = "ORGANIZATION"
    DOCUMENT = "DOCUMENT"
    LOCATION = "LOCATION"
    SOCIAL_PROFILE = "SOCIAL_PROFILE"
    IP = "IP"
    NAME = "NAME"
    OTHER = "OTHER"


class GraphRelationType(str, Enum):
    MENTIONED_ON = "MENTIONED_ON"
    MENTIONS = "MENTIONS"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    USES_DOMAIN = "USES_DOMAIN"
    USES_EMAIL = "USES_EMAIL"
    USES_PHONE = "USES_PHONE"
    LINKS_TO = "LINKS_TO"
    HOSTED_ON = "HOSTED_ON"
    REFERENCES = "REFERENCES"
    PUBLISHED_IN = "PUBLISHED_IN"
    LOCATED_AT = "LOCATED_AT"
    ALIAS_OF = "ALIAS_OF"
    POSSIBLE_SAME_ENTITY = "POSSIBLE_SAME_ENTITY"
    OTHER = "OTHER"


class GraphStatus(str, Enum):
    POSSIBLE = "POSSIBLE"
    PROBABLE = "PROBABLE"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


class TimelineEventType(str, Enum):
    FIRST_SEEN = "FIRST_SEEN"
    LAST_SEEN = "LAST_SEEN"
    RELATION_APPEARED = "RELATION_APPEARED"
    RELATION_DISAPPEARED = "RELATION_DISAPPEARED"
    ATTRIBUTE_CHANGED = "ATTRIBUTE_CHANGED"
    CONFLICT_DETECTED = "CONFLICT_DETECTED"
    SOURCE_UPDATED = "SOURCE_UPDATED"
    OTHER = "OTHER"


class CaseEventType(str, Enum):
    SEED_ADDED = "SEED_ADDED"
    ENTITY_CREATED = "ENTITY_CREATED"
    ENTITY_UPDATED = "ENTITY_UPDATED"
    RELATION_CREATED = "RELATION_CREATED"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    PIVOT_PROPOSED = "PIVOT_PROPOSED"
    PIVOT_EXECUTED = "PIVOT_EXECUTED"
    HYPOTHESIS_CREATED = "HYPOTHESIS_CREATED"
    HYPOTHESIS_CHANGED = "HYPOTHESIS_CHANGED"
    REVIEW_DECISION = "REVIEW_DECISION"
    CONTRADICTION_FOUND = "CONTRADICTION_FOUND"
    REPORT_GENERATED = "REPORT_GENERATED"
    ENTITY_DISCOVERED = "ENTITY_DISCOVERED"
    AUTO_PIVOT_RECORDED = "AUTO_PIVOT_RECORDED"


class ReviewDecisionValue(str, Enum):
    CONFIRM = "CONFIRM"
    REJECT = "REJECT"
    KEEP_OPEN = "KEEP_OPEN"


class ReviewTarget(str, Enum):
    RELATION = "RELATION"
    HYPOTHESIS = "HYPOTHESIS"
    IDENTITY_CANDIDATE = "IDENTITY_CANDIDATE"


class IdentityStatus(str, Enum):
    OPEN = "OPEN"
    PLAUSIBLE = "PLAUSIBLE"
    WEAKENED = "WEAKENED"
    REJECTED = "REJECTED"
    VERIFIED = "VERIFIED"


class ProfessionalFailureState(str, Enum):
    NO_DATA = "NO_DATA"
    NO_VERIFIED_DATA = "NO_VERIFIED_DATA"
    SOURCE_BLOCKED = "SOURCE_BLOCKED"
    SOURCE_UNKNOWN = "SOURCE_UNKNOWN"
    INSUFFICIENT_INDEPENDENCE = "INSUFFICIENT_INDEPENDENCE"
    CONTRADICTORY = "CONTRADICTORY"
    STALE_ONLY = "STALE_ONLY"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    POLICY_BLOCKED = "POLICY_BLOCKED"


@dataclass(frozen=True, kw_only=True)
class EntityNode:
    entity_id: str
    case_id: str
    entity_type: GraphEntityType
    canonical_value: str
    display_value: str
    aliases: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    source_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    confidence: float
    status: GraphStatus
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("entity_id", "canonical_value", "display_value"):
            _text(name, getattr(self, name))
        validate_case_id(self.case_id)
        if not isinstance(self.entity_type, GraphEntityType) or not isinstance(self.status, GraphStatus):
            raise ValueError("invalid entity classification")
        for name in ("first_seen", "last_seen", "created_at", "updated_at"):
            _aware(name, getattr(self, name))
        if self.last_seen < self.first_seen or self.updated_at < self.created_at:
            raise ValueError("entity timestamps are inconsistent")
        _texts("aliases", self.aliases)
        _texts("source_refs", self.source_refs, required=True)
        _texts("evidence_refs", self.evidence_refs, required=True)
        _score("confidence", self.confidence)
        if not isinstance(self.attributes, Mapping):
            raise ValueError("attributes must be a mapping")

    def to_dict(self) -> dict[str, object]:
        return {
            "entity_id": self.entity_id, "case_id": self.case_id, "entity_type": self.entity_type.value,
            "canonical_value": self.canonical_value, "display_value": self.display_value,
            "aliases": list(self.aliases), "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(), "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(), "source_refs": list(self.source_refs),
            "evidence_refs": list(self.evidence_refs), "confidence": self.confidence,
            "status": self.status.value, "attributes": dict(self.attributes),
        }


@dataclass(frozen=True, kw_only=True)
class EntityRelation:
    relation_id: str
    case_id: str
    source_entity_id: str
    target_entity_id: str
    relation_type: GraphRelationType
    first_seen: datetime
    last_seen: datetime
    evidence_refs: tuple[str, ...]
    source_refs: tuple[str, ...]
    independence_groups: tuple[str, ...]
    confidence: float
    status: GraphStatus
    reasons: tuple[str, ...]
    reviewer_decision_id: str | None = None
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("relation_id", "source_entity_id", "target_entity_id"):
            _text(name, getattr(self, name))
        validate_case_id(self.case_id)
        if self.source_entity_id == self.target_entity_id:
            raise ValueError("relation endpoints must differ")
        if not isinstance(self.relation_type, GraphRelationType) or not isinstance(self.status, GraphStatus):
            raise ValueError("invalid relation classification")
        _aware("first_seen", self.first_seen)
        _aware("last_seen", self.last_seen)
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        _texts("evidence_refs", self.evidence_refs, required=True)
        _texts("source_refs", self.source_refs, required=True)
        _texts("independence_groups", self.independence_groups, required=True)
        _texts("reasons", self.reasons, required=True)
        _score("confidence", self.confidence)
        if self.status is GraphStatus.CONFIRMED and not self.reviewer_decision_id:
            raise ValueError("CONFIRMED relation requires ReviewerDecision")

    def to_dict(self) -> dict[str, object]:
        return {
            "relation_id": self.relation_id, "case_id": self.case_id,
            "source_entity_id": self.source_entity_id, "target_entity_id": self.target_entity_id,
            "relation_type": self.relation_type.value, "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(), "evidence_refs": list(self.evidence_refs),
            "source_refs": list(self.source_refs), "independence_groups": list(self.independence_groups),
            "confidence": self.confidence, "status": self.status.value, "reasons": list(self.reasons),
            "reviewer_decision_id": self.reviewer_decision_id, "attributes": dict(self.attributes),
        }


@dataclass(frozen=True, kw_only=True)
class TimelineEvent:
    event_id: str
    case_id: str
    entity_ids: tuple[str, ...]
    relation_ids: tuple[str, ...]
    event_type: TimelineEventType
    timestamp: datetime
    timestamp_source: str
    evidence_refs: tuple[str, ...]
    confidence: float
    description: str

    def to_dict(self) -> dict[str, object]:
        return {"event_id": self.event_id, "case_id": self.case_id, "entity_ids": list(self.entity_ids),
                "relation_ids": list(self.relation_ids), "event_type": self.event_type.value,
                "timestamp": self.timestamp.isoformat(), "timestamp_source": self.timestamp_source,
                "evidence_refs": list(self.evidence_refs), "confidence": self.confidence,
                "description": self.description}


@dataclass(frozen=True, kw_only=True)
class CorrelationPath:
    path_id: str
    entity_sequence: tuple[str, ...]
    relation_sequence: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    confidence: float
    explanation: str
    reasons: tuple[str, ...]
    independent_groups: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"path_id": self.path_id, "entity_sequence": list(self.entity_sequence),
                "relation_sequence": list(self.relation_sequence), "evidence_refs": list(self.evidence_refs),
                "confidence": self.confidence, "explanation": self.explanation,
                "reasons": list(self.reasons), "independent_groups": list(self.independent_groups)}


@dataclass(frozen=True, kw_only=True)
class IdentityCandidate:
    identity_candidate_id: str
    entity_ids: tuple[str, ...]
    supporting_paths: tuple[str, ...]
    opposing_paths: tuple[str, ...]
    confidence: float
    status: IdentityStatus
    reasons: tuple[str, ...]
    unresolved_questions: tuple[str, ...]
    reviewer_decision_id: str | None = None

    def __post_init__(self) -> None:
        _text("identity_candidate_id", self.identity_candidate_id)
        _texts("entity_ids", self.entity_ids, required=True)
        _score("confidence", self.confidence)
        if self.status is IdentityStatus.VERIFIED and not self.reviewer_decision_id:
            raise ValueError("VERIFIED identity requires ReviewerDecision")

    def to_dict(self) -> dict[str, object]:
        return {"identity_candidate_id": self.identity_candidate_id, "entity_ids": list(self.entity_ids),
                "supporting_paths": list(self.supporting_paths), "opposing_paths": list(self.opposing_paths),
                "confidence": self.confidence, "status": self.status.value, "reasons": list(self.reasons),
                "unresolved_questions": list(self.unresolved_questions),
                "reviewer_decision_id": self.reviewer_decision_id}


@dataclass(frozen=True, kw_only=True)
class ReviewerDecisionEvent:
    decision_id: str
    case_id: str
    reviewer: str
    timestamp: datetime
    target_type: ReviewTarget
    target_id: str
    decision: ReviewDecisionValue
    notes: str
    evidence_refs: tuple[str, ...]
    previous_decision_ref: str | None = None

    def __post_init__(self) -> None:
        for name in ("decision_id", "reviewer", "target_id", "notes"):
            _text(name, getattr(self, name))
        validate_case_id(self.case_id)
        _aware("timestamp", self.timestamp)
        _texts("evidence_refs", self.evidence_refs, required=True)

    def to_dict(self) -> dict[str, object]:
        return {"decision_id": self.decision_id, "case_id": self.case_id, "reviewer": self.reviewer,
                "timestamp": self.timestamp.isoformat(), "target_type": self.target_type.value,
                "target_id": self.target_id, "decision": self.decision.value, "notes": self.notes,
                "evidence_refs": list(self.evidence_refs), "previous_decision_ref": self.previous_decision_ref}


@dataclass(frozen=True, kw_only=True)
class CaseEvent:
    event_id: str
    case_id: str
    event_type: CaseEventType
    timestamp: datetime
    subject_id: str
    evidence_refs: tuple[str, ...]
    attributes: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {"event_id": self.event_id, "case_id": self.case_id, "event_type": self.event_type.value,
                "timestamp": self.timestamp.isoformat(), "subject_id": self.subject_id,
                "evidence_refs": list(self.evidence_refs), "attributes": dict(self.attributes)}


@dataclass(frozen=True, kw_only=True)
class PivotBudget:
    max_hops: int = 2
    max_pivots: int = 16
    max_auto_pivots: int = 6
    max_network_requests: int = 24
    max_entities: int = 500
    max_relations: int = 1000
    max_enrichments_per_entity: int = 4
    max_repeated_provider_queries: int = 1
    max_privacy_cost: float = 0.6

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if name == "max_privacy_cost":
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
                    raise ValueError("max_privacy_cost must be between 0 and 1")
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True, kw_only=True)
class GraphPivot:
    pivot_id: str
    case_id: str
    source_entity_id: str
    proposed_enricher: str
    proposed_input: str
    expected_information_gain: float
    privacy_cost: float
    network_cost: float
    duplication_risk: float
    graph_value: float
    reason: str
    status: str
    execution_fingerprint: str
    hop: int
    execution_mode: str = "MANUAL_REQUIRED"

    def to_dict(self) -> dict[str, object]:
        return dict(self.__dict__)


@dataclass(frozen=True, kw_only=True)
class CaseDossier:
    case_summary: Mapping[str, object]
    seeds: tuple[Mapping[str, object], ...]
    key_entities: tuple[Mapping[str, object], ...]
    key_relations: tuple[Mapping[str, object], ...]
    important_paths: tuple[Mapping[str, object], ...]
    hypotheses: tuple[Mapping[str, object], ...]
    verified_findings: tuple[Mapping[str, object], ...]
    rejected_findings: tuple[Mapping[str, object], ...]
    contradictions: tuple[str, ...]
    timeline: tuple[Mapping[str, object], ...]
    evidence_quality: tuple[Mapping[str, object], ...]
    unresolved_questions: tuple[str, ...]
    recommended_pivots: tuple[Mapping[str, object], ...]
    reviewer_decisions: tuple[Mapping[str, object], ...]
    coverage_summary: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {key: list(value) if isinstance(value, tuple) else dict(value)
                for key, value in self.__dict__.items()}
