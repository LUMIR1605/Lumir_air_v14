"""Deterministic contradiction checks without identity or AI verdicts."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Iterable

from osint_lab.case_manifest import validate_case_id


class ContradictionSeverity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


_SEVERITY_RANK = {
    ContradictionSeverity.NONE: 0,
    ContradictionSeverity.LOW: 1,
    ContradictionSeverity.MEDIUM: 2,
    ContradictionSeverity.HIGH: 3,
}
_HIGH_ATTRIBUTES = frozenset({
    "identifier",
    "email",
    "phone",
    "domain",
    "organization",
    "company",
    "profile_url",
})
_MEDIUM_ATTRIBUTES = frozenset({"name", "location", "created_at", "raw_status", "status"})


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


@dataclass(frozen=True, kw_only=True)
class ContradictionAssertion:
    assertion_id: str
    case_id: str
    subject_id: str
    attribute: str
    value: str
    source_name: str
    evidence_ref: str
    collected_at: datetime

    def __post_init__(self) -> None:
        for name in ("assertion_id", "subject_id", "attribute", "value", "source_name", "evidence_ref"):
            _require_text(name, getattr(self, name))
        validate_case_id(self.case_id)
        _require_aware("collected_at", self.collected_at)


@dataclass(frozen=True)
class ContradictionResult:
    severity: ContradictionSeverity
    reasons: tuple[str, ...]
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.severity, ContradictionSeverity):
            raise ValueError("severity must be a ContradictionSeverity")
        if not isinstance(self.reasons, tuple) or any(not isinstance(item, str) for item in self.reasons):
            raise ValueError("reasons must be a tuple of strings")
        if not isinstance(self.evidence_refs, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.evidence_refs
        ):
            raise ValueError("evidence_refs must be a tuple of non-empty strings")


def detect_contradictions(assertions: Iterable[ContradictionAssertion]) -> ContradictionResult:
    groups: dict[tuple[str, str, str], list[ContradictionAssertion]] = {}
    for assertion in assertions:
        if not isinstance(assertion, ContradictionAssertion):
            raise ValueError("all assertions must be ContradictionAssertion values")
        key = (assertion.case_id, assertion.subject_id, assertion.attribute.strip().casefold())
        groups.setdefault(key, []).append(assertion)

    highest = ContradictionSeverity.NONE
    reasons: list[str] = []
    evidence_refs: set[str] = set()
    for (_, subject_id, attribute), values in sorted(groups.items()):
        distinct = {item.value.strip().casefold() for item in values}
        if len(distinct) <= 1:
            continue
        severity = _attribute_severity(attribute, distinct)
        if _SEVERITY_RANK[severity] > _SEVERITY_RANK[highest]:
            highest = severity
        rendered_values = sorted({item.value.strip() for item in values})
        reasons.append(
            f"{severity.value}: conflicting {attribute} values for {subject_id}: "
            + " | ".join(rendered_values)
        )
        evidence_refs.update(item.evidence_ref for item in values)

    return ContradictionResult(highest, tuple(reasons), tuple(sorted(evidence_refs)))


def _attribute_severity(attribute: str, values: set[str]) -> ContradictionSeverity:
    if attribute == "raw_status" and {"found", "not_found"}.issubset(values):
        return ContradictionSeverity.MEDIUM
    if attribute in _HIGH_ATTRIBUTES:
        return ContradictionSeverity.HIGH
    if attribute in _MEDIUM_ATTRIBUTES:
        return ContradictionSeverity.MEDIUM
    return ContradictionSeverity.LOW
