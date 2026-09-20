"""Structured public-phone discovery models."""

from dataclasses import dataclass
from enum import Enum


class DiscoveredEntityType(str, Enum):
    EMAIL = "EMAIL"
    DOMAIN = "DOMAIN"
    USERNAME = "USERNAME"
    COMPANY = "COMPANY"
    LOCATION = "LOCATION"
    DOCUMENT = "DOCUMENT"
    WEBSITE = "WEBSITE"
    OTHER = "OTHER"


@dataclass(frozen=True, kw_only=True)
class DiscoveredEntity:
    entity_type: DiscoveredEntityType
    value: str
    source_url: str
    evidence_ref: str
    extraction_method: str
    confidence: float
    notes: str

    def __post_init__(self) -> None:
        if not isinstance(self.entity_type, DiscoveredEntityType):
            raise ValueError("entity_type must be a DiscoveredEntityType")
        for name in ("value", "source_url", "evidence_ref", "extraction_method", "notes"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise ValueError("confidence must be numeric")
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, object]:
        return {
            "entity_type": self.entity_type.value,
            "value": self.value,
            "source_url": self.source_url,
            "evidence_ref": self.evidence_ref,
            "extraction_method": self.extraction_method,
            "confidence": self.confidence,
            "notes": self.notes,
        }
