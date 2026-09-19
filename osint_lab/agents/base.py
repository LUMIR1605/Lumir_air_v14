"""Collector contract whose public run path requires an orchestrator context."""

from abc import ABC, ABCMeta, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
from types import MappingProxyType
from typing import TYPE_CHECKING, Mapping, final

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus

if TYPE_CHECKING:
    from osint_lab.orchestrator.receipt import ExecutionReceipt


class ExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    DENIED = "DENIED"


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


@dataclass(frozen=True, kw_only=True)
class RawObservation:
    raw_status: str
    value_reference: str
    evidence_ref: str | None = None
    notes: str = ""
    payload: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_text("raw_status", self.raw_status)
        _require_text("value_reference", self.value_reference)
        if self.evidence_ref is not None:
            _require_text("evidence_ref", self.evidence_ref)
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")
        if not isinstance(self.payload, Mapping):
            raise ValueError("payload must be a mapping")
        if any(not isinstance(key, str) or not key.strip() for key in self.payload):
            raise ValueError("payload keys must be non-empty strings")
        try:
            copied = json.loads(json.dumps(dict(self.payload), ensure_ascii=False, allow_nan=False))
        except (TypeError, ValueError) as error:
            raise ValueError("payload must contain only JSON-safe values") from error
        object.__setattr__(self, "payload", MappingProxyType(copied))


@dataclass(frozen=True, kw_only=True)
class FindingCandidate:
    raw_status: str
    normalized_status: FindingStatus
    value_reference: str
    evidence_ref: str | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        _require_text("raw_status", self.raw_status)
        _require_text("value_reference", self.value_reference)
        if not isinstance(self.normalized_status, FindingStatus):
            raise ValueError("normalized_status must be a FindingStatus")
        if self.normalized_status is FindingStatus.CONFIRMED:
            raise ValueError("collector output cannot be CONFIRMED")
        if self.evidence_ref is not None:
            _require_text("evidence_ref", self.evidence_ref)
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")


@dataclass(frozen=True, kw_only=True)
class ExecutionResult:
    execution_id: str
    started_at: datetime
    finished_at: datetime
    status: ExecutionStatus
    errors: tuple[str, ...]
    observations: tuple[RawObservation, ...]
    finding_candidates: tuple[FindingCandidate, ...] = ()
    receipt: "ExecutionReceipt | None" = None

    def __post_init__(self) -> None:
        _require_text("execution_id", self.execution_id)
        _require_aware("started_at", self.started_at)
        _require_aware("finished_at", self.finished_at)
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")
        if not isinstance(self.status, ExecutionStatus):
            raise ValueError("status must be an ExecutionStatus")
        if not isinstance(self.errors, tuple) or any(not isinstance(item, str) for item in self.errors):
            raise ValueError("errors must be a tuple of strings")
        if not isinstance(self.observations, tuple) or any(
            not isinstance(item, RawObservation) for item in self.observations
        ):
            raise ValueError("observations must contain only RawObservation values")
        if not isinstance(self.finding_candidates, tuple) or any(
            not isinstance(item, FindingCandidate) for item in self.finding_candidates
        ):
            raise ValueError("finding_candidates must contain only FindingCandidate values")


class _CollectorMeta(ABCMeta):
    def __new__(mcls, name, bases, namespace, **kwargs):
        if any(isinstance(base, _CollectorMeta) for base in bases) and "run" in namespace:
            raise TypeError("collectors must not override the policy-controlled run method")
        return super().__new__(mcls, name, bases, namespace, **kwargs)


class Collector(ABC, metaclass=_CollectorMeta):
    agent_name: str
    agent_type: str
    source_class: SourceClass
    version: str

    def __init__(self) -> None:
        for name in ("agent_name", "agent_type", "version"):
            _require_text(name, getattr(self, name, None))
        if self.agent_name.strip() == "*" or self.agent_type.strip() == "*":
            raise ValueError("wildcard collector identity is not permitted")
        if not isinstance(self.source_class, SourceClass):
            raise ValueError("source_class must be a SourceClass")

    @abstractmethod
    def validate_input(self, seed_reference: str) -> None:
        """Reject invalid input before collection begins."""

    @abstractmethod
    def _run(self, context: ExecutionContext, seed_reference: str) -> tuple[RawObservation, ...]:
        """Return raw observations; called only through the guarded run method."""

    @abstractmethod
    def normalize(self, observation: RawObservation) -> FindingCandidate:
        """Map a raw observation to a non-final candidate."""

    @abstractmethod
    def describe_capabilities(self) -> Mapping[str, object]:
        """Describe the collector without executing it."""

    @final
    def run(self, context: ExecutionContext, seed_reference: str) -> tuple[RawObservation, ...]:
        if not isinstance(context, ExecutionContext):
            raise PermissionError("collector execution requires an orchestrator-issued context")
        context._consume_for(
            agent_name=self.agent_name,
            source_class=self.source_class,
            seed_reference=seed_reference,
        )
        self.validate_input(seed_reference)
        observations = self._run(context, seed_reference)
        if not isinstance(observations, tuple) or any(
            not isinstance(item, RawObservation) for item in observations
        ):
            raise ValueError("collector run must return a tuple of RawObservation values")
        return observations


Agent = Collector
Observation = RawObservation
