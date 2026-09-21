"""Reviewed source definitions and deterministic source-quality models."""

from dataclasses import dataclass
from datetime import date
from enum import Enum
import hashlib
import json
from typing import Mapping

from osint_lab.graph.models import GraphEntityType
from osint_lab.policies import SourceClass


class SourceCategory(str, Enum):
    SEARCH_ENGINE = "SEARCH_ENGINE"
    PUBLIC_DIRECTORY = "PUBLIC_DIRECTORY"
    FIRST_PARTY_WEB = "FIRST_PARTY_WEB"
    PUBLIC_DOCUMENT_INDEX = "PUBLIC_DOCUMENT_INDEX"
    PUBLIC_CODE_HOSTING = "PUBLIC_CODE_HOSTING"
    PUBLIC_DOMAIN_DATA = "PUBLIC_DOMAIN_DATA"
    PUBLIC_DNS = "PUBLIC_DNS"
    PUBLIC_PROFILE = "PUBLIC_PROFILE"
    PUBLIC_COMPANY_DATA = "PUBLIC_COMPANY_DATA"
    PUBLIC_ARCHIVE = "PUBLIC_ARCHIVE"
    OTHER = "OTHER"


class SourceRole(str, Enum):
    DISCOVERY = "DISCOVERY"
    EVIDENCE = "EVIDENCE"
    ENRICHMENT = "ENRICHMENT"
    VERIFICATION = "VERIFICATION"


class ReliabilityClass(str, Enum):
    FIRST_PARTY = "FIRST_PARTY"
    OFFICIAL_PUBLIC_REGISTRY = "OFFICIAL_PUBLIC_REGISTRY"
    TECHNICAL_INFRASTRUCTURE = "TECHNICAL_INFRASTRUCTURE"
    PUBLIC_PLATFORM = "PUBLIC_PLATFORM"
    DIRECTORY = "DIRECTORY"
    ARCHIVE = "ARCHIVE"
    AGGREGATOR = "AGGREGATOR"
    UNKNOWN = "UNKNOWN"


class ImplementationStatus(str, Enum):
    IMPLEMENTED = "IMPLEMENTED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    PLANNED = "PLANNED"
    DISABLED_TERMS = "DISABLED_TERMS"
    DISABLED_CREDENTIALS = "DISABLED_CREDENTIALS"
    DISABLED_UNSTABLE = "DISABLED_UNSTABLE"


class SourceFailureStatus(str, Enum):
    SUCCESS = "SUCCESS"
    NO_DATA = "NO_DATA"
    NO_MATCH = "NO_MATCH"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    PAID_ONLY = "PAID_ONLY"
    TERMS_DISABLED = "TERMS_DISABLED"
    PARSER_FAILURE = "PARSER_FAILURE"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED = "UNSUPPORTED"


class ExecutionMode(str, Enum):
    AUTO = "AUTO"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"
    BLOCKED = "BLOCKED"


def source_config_hash(payload: Mapping[str, object]) -> str:
    clean = {key: value for key, value in payload.items() if key != "config_hash"}
    return hashlib.sha256(
        json.dumps(clean, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, kw_only=True)
class SourceDefinition:
    source_id: str
    name: str
    category: SourceCategory
    roles: tuple[SourceRole, ...]
    supported_entity_types: tuple[GraphEntityType, ...]
    output_entity_types: tuple[GraphEntityType, ...]
    source_class: SourceClass
    access_method: str
    base_url: str
    authentication_required: bool
    api_key_required: bool
    paid: bool
    automation_allowed: bool
    terms_reviewed: bool
    terms_review_url: str
    privacy_notes: str
    reliability_class: ReliabilityClass
    expected_information_gain: float
    rate_limit_notes: str
    enabled: bool
    reviewed_at: str
    implementation_status: ImplementationStatus
    parser_version: str
    config_hash: str
    api_key_present: bool = False

    def __post_init__(self) -> None:
        for name in (
            "source_id", "name", "access_method", "base_url", "terms_review_url",
            "privacy_notes", "rate_limit_notes", "reviewed_at", "parser_version", "config_hash",
        ):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"{name} must be non-empty")
        date.fromisoformat(self.reviewed_at)
        if not self.roles or not self.supported_entity_types or not self.output_entity_types:
            raise ValueError("roles and entity types must not be empty")
        if isinstance(self.expected_information_gain, bool) or not 0 <= self.expected_information_gain <= 1:
            raise ValueError("expected_information_gain must be between 0 and 1")
        if self.enabled and (
            not self.terms_reviewed
            or not self.automation_allowed
            or ((self.authentication_required or self.api_key_required or self.paid)
                and not self.api_key_present)
            or self.implementation_status is not ImplementationStatus.IMPLEMENTED
        ):
            raise ValueError("enabled source did not pass the hard source review")
        expected = source_config_hash(self.to_dict(include_hash=False))
        if self.config_hash != expected:
            raise ValueError("source config_hash mismatch")

    def to_dict(self, *, include_hash: bool = True) -> dict[str, object]:
        value = {
            "source_id": self.source_id, "name": self.name, "category": self.category.value,
            "roles": [item.value for item in self.roles],
            "supported_entity_types": [item.value for item in self.supported_entity_types],
            "output_entity_types": [item.value for item in self.output_entity_types],
            "source_class": self.source_class.value, "access_method": self.access_method,
            "base_url": self.base_url, "authentication_required": self.authentication_required,
            "api_key_required": self.api_key_required, "paid": self.paid,
            "automation_allowed": self.automation_allowed, "terms_reviewed": self.terms_reviewed,
            "terms_review_url": self.terms_review_url, "privacy_notes": self.privacy_notes,
            "reliability_class": self.reliability_class.value,
            "expected_information_gain": self.expected_information_gain,
            "rate_limit_notes": self.rate_limit_notes, "enabled": self.enabled,
            "reviewed_at": self.reviewed_at, "implementation_status": self.implementation_status.value,
            "parser_version": self.parser_version,
            "api_key_present": self.api_key_present,
        }
        if include_hash:
            value["config_hash"] = self.config_hash
        return value


def make_source_definition(**values) -> SourceDefinition:
    values = dict(values)
    values["config_hash"] = source_config_hash({
        key: ([item.value for item in value] if isinstance(value, tuple) and value and isinstance(value[0], Enum)
              else value.value if isinstance(value, Enum) else value)
        for key, value in values.items()
    })
    return SourceDefinition(**values)


@dataclass(frozen=True, kw_only=True)
class SourceReputation:
    source_id: str
    reputation_class: ReliabilityClass
    base_weight: float
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.source_id or not self.reasons or not 0 <= self.base_weight <= 1:
            raise ValueError("invalid SourceReputation")


@dataclass(frozen=True, kw_only=True)
class SourceDiversityScore:
    score: float
    independent_source_classes: int
    independent_domains: int
    first_party_present: bool
    archived_present: bool
    technical_present: bool
    textual_present: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class SourceCoverage:
    entity_type: GraphEntityType
    eligible_sources: int
    enabled_sources: int
    executed_sources: int
    blocked_sources: int
    unknown_sources: int
    successful_sources: int
    verified_evidence_count: int
    independent_evidence_groups: int

    def to_dict(self) -> dict[str, object]:
        return {"entity_type": self.entity_type.value, **{
            key: value for key, value in self.__dict__.items() if key != "entity_type"
        }}
