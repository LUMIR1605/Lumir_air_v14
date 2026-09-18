"""Validated authorization manifest for one OSINT LAB case."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re
from typing import Any

from osint_lab.policies.sources import SourceClass


_SAFE_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RISKY_SOURCE_CLASSES = frozenset({
    SourceClass.THIRD_PARTY_API,
    SourceClass.TOR,
    SourceClass.DIRECT_TARGET,
})


class CaseStatus(str, Enum):
    DRAFT = "DRAFT"
    AUTHORIZED = "AUTHORIZED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


def validate_case_id(case_id: str) -> str:
    if not isinstance(case_id, str) or not _SAFE_CASE_ID.fullmatch(case_id):
        raise ValueError("case_id must be a safe 1-128 character identifier")
    return case_id


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


@dataclass(frozen=True, kw_only=True)
class SeedEntity:
    entity_type: str
    value: str

    def __post_init__(self) -> None:
        _require_text("entity_type", self.entity_type)
        _require_text("value", self.value)

    def to_dict(self) -> dict[str, str]:
        return {"entity_type": self.entity_type, "value": self.value}


@dataclass(frozen=True, kw_only=True)
class CaseManifest:
    case_id: str
    case_name: str
    created_at: datetime
    authorized_by: str
    purpose: str
    legal_basis_or_consent_note: str
    seed_entities: tuple[SeedEntity, ...]
    allowed_source_classes: frozenset[SourceClass] = frozenset({SourceClass.LOCAL})
    forbidden_source_classes: frozenset[SourceClass] = _RISKY_SOURCE_CLASSES
    allowed_agent_types: frozenset[str] = frozenset()
    third_party_api_allowed: bool = False
    tor_allowed: bool = False
    direct_target_allowed: bool = False
    retention_days: int = 30
    notes: str = ""
    status: CaseStatus = CaseStatus.DRAFT

    def __post_init__(self) -> None:
        validate_case_id(self.case_id)
        for name in ("case_name", "authorized_by", "purpose", "legal_basis_or_consent_note"):
            _require_text(name, getattr(self, name))
        _require_aware("created_at", self.created_at)
        if not isinstance(self.seed_entities, tuple) or not self.seed_entities:
            raise ValueError("seed_entities must be a non-empty tuple")
        if any(not isinstance(item, SeedEntity) for item in self.seed_entities):
            raise ValueError("seed_entities must contain only SeedEntity values")
        for name in ("allowed_source_classes", "forbidden_source_classes"):
            values = getattr(self, name)
            if not isinstance(values, frozenset) or any(not isinstance(item, SourceClass) for item in values):
                raise ValueError(f"{name} must contain only SourceClass values")
        if self.allowed_source_classes & self.forbidden_source_classes:
            raise ValueError("allowed and forbidden source classes must not overlap")
        if not isinstance(self.allowed_agent_types, frozenset) or any(
            not isinstance(item, str) or not item.strip() for item in self.allowed_agent_types
        ):
            raise ValueError("allowed_agent_types must contain non-empty strings")
        for name in ("third_party_api_allowed", "tor_allowed", "direct_target_allowed"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be boolean")
        if isinstance(self.retention_days, bool) or not isinstance(self.retention_days, int) or self.retention_days <= 0:
            raise ValueError("retention_days must be a positive integer")
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")
        if not isinstance(self.status, CaseStatus):
            raise ValueError("status must be a CaseStatus")
        self._validate_risky_source(SourceClass.THIRD_PARTY_API, self.third_party_api_allowed)
        self._validate_risky_source(SourceClass.TOR, self.tor_allowed)
        self._validate_risky_source(SourceClass.DIRECT_TARGET, self.direct_target_allowed)

    def _validate_risky_source(self, source_class: SourceClass, enabled: bool) -> None:
        if enabled and source_class not in self.allowed_source_classes:
            raise ValueError(f"{source_class.value} flag requires the source class to be allowed")
        if source_class in self.allowed_source_classes and not enabled:
            raise ValueError(f"{source_class.value} requires its explicit manifest flag")

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "created_at": self.created_at.isoformat(),
            "authorized_by": self.authorized_by,
            "purpose": self.purpose,
            "legal_basis_or_consent_note": self.legal_basis_or_consent_note,
            "seed_entities": [item.to_dict() for item in self.seed_entities],
            "allowed_source_classes": sorted(item.value for item in self.allowed_source_classes),
            "forbidden_source_classes": sorted(item.value for item in self.forbidden_source_classes),
            "allowed_agent_types": sorted(self.allowed_agent_types),
            "third_party_api_allowed": self.third_party_api_allowed,
            "tor_allowed": self.tor_allowed,
            "direct_target_allowed": self.direct_target_allowed,
            "retention_days": self.retention_days,
            "notes": self.notes,
            "status": self.status.value,
        }
