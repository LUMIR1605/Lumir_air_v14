"""Provenance-preserving finding; collector output never verifies ownership."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from osint_lab.policies import SourceClass


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    UNKNOWN = "UNKNOWN"
    NOT_FOUND = "NOT_FOUND"
    FALSE_POSITIVE = "FALSE_POSITIVE"


def initial_status(raw_status: str) -> FindingStatus:
    """Conservative classification of a raw collector observation."""
    if raw_status.upper() == "FOUND":
        return FindingStatus.POSSIBLE
    return FindingStatus.UNKNOWN


@dataclass(frozen=True, kw_only=True)
class Finding:
    case_id: str
    entity_type: str
    value: str
    relation: str
    source_name: str
    source_url: str | None
    source_class: SourceClass
    collection_method: str
    collected_at: datetime
    raw_status: str
    normalized_status: FindingStatus
    confidence: float | None
    evidence_ref: str | None
    artifact_hash: str | None
    notes: str

    def __post_init__(self) -> None:
        for name in ("case_id", "entity_type", "value", "relation", "source_name", "collection_method", "raw_status"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"{name} must be non-empty")
        if not isinstance(self.source_class, SourceClass):
            raise ValueError("invalid source_class")
        if not isinstance(self.normalized_status, FindingStatus):
            raise ValueError("invalid normalized_status")
        if not isinstance(self.collected_at, datetime) or self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("collected_at must include a timezone")
        if self.confidence is not None and (isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)) or not 0 <= self.confidence <= 1):
            raise ValueError("confidence must be in [0, 1] or unknown")
        if self.artifact_hash is not None and (len(self.artifact_hash) != 64 or any(c not in "0123456789abcdef" for c in self.artifact_hash)):
            raise ValueError("artifact_hash must be lowercase SHA-256")
        if self.raw_status.upper() == "FOUND" and self.normalized_status is FindingStatus.CONFIRMED:
            raise ValueError("FOUND requires independent verification before confirmation")
