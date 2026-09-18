"""Validated relation graph that never merges identities automatically."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from osint_lab.case_manifest import validate_case_id


class NodeType(str, Enum):
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    USERNAME = "USERNAME"
    DOMAIN = "DOMAIN"
    WEBSITE = "WEBSITE"
    COMPANY = "COMPANY"
    DOCUMENT = "DOCUMENT"
    IMAGE = "IMAGE"
    SOCIAL_PROFILE = "SOCIAL_PROFILE"
    IP = "IP"
    LOCATION = "LOCATION"
    OTHER = "OTHER"


class RelationType(str, Enum):
    OWNS = "OWNS"
    USES = "USES"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    MENTIONS = "MENTIONS"
    HOSTED_ON = "HOSTED_ON"
    REGISTERED_TO = "REGISTERED_TO"
    LINKS_TO = "LINKS_TO"
    SAME_IDENTIFIER = "SAME_IDENTIFIER"
    POSSIBLE_MATCH = "POSSIBLE_MATCH"
    CONTRADICTS = "CONTRADICTS"
    DERIVED_FROM = "DERIVED_FROM"


class RelationStatus(str, Enum):
    PROPOSED = "PROPOSED"
    SUPPORTED = "SUPPORTED"
    DISPUTED = "DISPUTED"
    REJECTED = "REJECTED"


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


@dataclass(frozen=True, kw_only=True)
class RelationNode:
    node_id: str
    case_id: str
    node_type: NodeType
    value: str
    created_at: datetime
    notes: str = ""

    def __post_init__(self) -> None:
        _require_text("node_id", self.node_id)
        validate_case_id(self.case_id)
        if not isinstance(self.node_type, NodeType):
            raise ValueError("node_type must be a NodeType")
        _require_text("value", self.value)
        _require_aware("created_at", self.created_at)
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")


@dataclass(frozen=True, kw_only=True)
class Relation:
    relation_id: str
    case_id: str
    source_node: str
    target_node: str
    relation_type: RelationType
    confidence: float | None
    status: RelationStatus
    evidence_refs: tuple[str, ...]
    created_at: datetime
    notes: str = ""

    def __post_init__(self) -> None:
        for name in ("relation_id", "source_node", "target_node"):
            _require_text(name, getattr(self, name))
        validate_case_id(self.case_id)
        if self.source_node == self.target_node:
            raise ValueError("relation endpoints must be different nodes")
        if not isinstance(self.relation_type, RelationType):
            raise ValueError("relation_type must be a RelationType")
        if self.confidence is not None and (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not 0 <= self.confidence <= 1
        ):
            raise ValueError("confidence must be in [0, 1] or unknown")
        if not isinstance(self.status, RelationStatus):
            raise ValueError("status must be a RelationStatus")
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs or any(
            not isinstance(item, str) or not item.strip() for item in self.evidence_refs
        ):
            raise ValueError("evidence_refs must be a non-empty tuple")
        _require_aware("created_at", self.created_at)
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")


class RelationGraph:
    """In-memory graph with explicit nodes and evidence-backed relations."""

    def __init__(self, case_id: str) -> None:
        self.case_id = validate_case_id(case_id)
        self._nodes: dict[str, RelationNode] = {}
        self._relations: dict[str, Relation] = {}

    @property
    def nodes(self) -> tuple[RelationNode, ...]:
        return tuple(self._nodes.values())

    @property
    def relations(self) -> tuple[Relation, ...]:
        return tuple(self._relations.values())

    def add_node(self, node: RelationNode) -> None:
        if not isinstance(node, RelationNode):
            raise ValueError("RelationNode required")
        if node.case_id != self.case_id:
            raise ValueError("node belongs to another case")
        if node.node_id in self._nodes:
            raise ValueError("duplicate node_id")
        self._nodes[node.node_id] = node

    def add_relation(self, relation: Relation) -> None:
        if not isinstance(relation, Relation):
            raise ValueError("Relation required")
        if relation.case_id != self.case_id:
            raise ValueError("relation belongs to another case")
        if relation.relation_id in self._relations:
            raise ValueError("duplicate relation_id")
        if relation.source_node not in self._nodes or relation.target_node not in self._nodes:
            raise ValueError("relation endpoints must already exist")
        self._relations[relation.relation_id] = relation
