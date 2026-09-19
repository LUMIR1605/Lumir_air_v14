"""Receipt describing one completed collector execution."""

from dataclasses import dataclass
from datetime import datetime

from osint_lab.agents.base import ExecutionStatus
from osint_lab.case_manifest import validate_case_id
from osint_lab.policies import SourceClass


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


@dataclass(frozen=True, kw_only=True)
class ExecutionReceipt:
    execution_id: str
    case_id: str
    collector: str
    collector_version: str
    source_class: SourceClass
    authorization_id: str | None
    started_at: datetime
    finished_at: datetime
    result_status: ExecutionStatus
    observation_count: int
    evidence_refs: tuple[str, ...]
    audit_head_hash: str

    def __post_init__(self) -> None:
        for name in ("execution_id", "collector", "collector_version"):
            _require_text(name, getattr(self, name))
        validate_case_id(self.case_id)
        if not isinstance(self.source_class, SourceClass):
            raise ValueError("source_class must be a SourceClass")
        if self.authorization_id is not None:
            _require_text("authorization_id", self.authorization_id)
        _require_aware("started_at", self.started_at)
        _require_aware("finished_at", self.finished_at)
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")
        if not isinstance(self.result_status, ExecutionStatus):
            raise ValueError("result_status must be an ExecutionStatus")
        if isinstance(self.observation_count, bool) or not isinstance(self.observation_count, int) or self.observation_count < 0:
            raise ValueError("observation_count must be a non-negative integer")
        if not isinstance(self.evidence_refs, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.evidence_refs
        ):
            raise ValueError("evidence_refs must be a tuple of non-empty strings")
        if len(self.audit_head_hash) != 64 or any(
            character not in "0123456789abcdef" for character in self.audit_head_hash
        ):
            raise ValueError("audit_head_hash must be a lowercase SHA-256 digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "execution_id": self.execution_id,
            "case_id": self.case_id,
            "collector": self.collector,
            "collector_version": self.collector_version,
            "source_class": self.source_class.value,
            "authorization_id": self.authorization_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "result_status": self.result_status.value,
            "observation_count": self.observation_count,
            "evidence_refs": list(self.evidence_refs),
            "audit_head_hash": self.audit_head_hash,
        }
