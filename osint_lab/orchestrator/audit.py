"""Append-only local JSONL audit log for orchestrator events."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import json
import os
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from osint_lab.case_manifest import validate_case_id
from osint_lab.policies import SourceClass


class AuditEventType(str, Enum):
    RUN_REQUESTED = "RUN_REQUESTED"
    POLICY_EVALUATED = "POLICY_EVALUATED"
    AUTHORIZATION_CHECKED = "AUTHORIZATION_CHECKED"
    RUN_ALLOWED = "RUN_ALLOWED"
    RUN_DENIED = "RUN_DENIED"
    AGENT_STARTED = "AGENT_STARTED"
    AGENT_FINISHED = "AGENT_FINISHED"
    AGENT_FAILED = "AGENT_FAILED"


_SENSITIVE_KEY_PARTS = ("password", "secret", "token", "api_key", "credential")


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


def _is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def default_audit_root(environment: Mapping[str, str] | None = None) -> Path:
    values = os.environ if environment is None else environment
    local_app_data = values.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("LOCALAPPDATA is required for the default Windows audit log")
    return Path(local_app_data) / "LumirOSINTLab" / "audit"


@dataclass(frozen=True, kw_only=True)
class AuditEntry:
    audit_id: str
    case_id: str
    execution_id: str
    authorization_id: str | None
    agent_name: str
    source_class: SourceClass
    event_type: AuditEventType
    decision: str
    timestamp: datetime
    message: str
    metadata: Mapping[str, str | int | float | bool | None]

    def __post_init__(self) -> None:
        for name in ("audit_id", "execution_id", "agent_name", "decision", "message"):
            _require_text(name, getattr(self, name))
        validate_case_id(self.case_id)
        if self.authorization_id is not None:
            _require_text("authorization_id", self.authorization_id)
        if not isinstance(self.source_class, SourceClass):
            raise ValueError("source_class must be a SourceClass")
        if not isinstance(self.event_type, AuditEventType):
            raise ValueError("event_type must be an AuditEventType")
        _require_aware("timestamp", self.timestamp)
        if not isinstance(self.metadata, Mapping):
            raise ValueError("metadata must be a mapping")
        copied: dict[str, str | int | float | bool | None] = {}
        for key, value in self.metadata.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("metadata keys must be non-empty strings")
            lowered = key.casefold()
            if any(part in lowered for part in _SENSITIVE_KEY_PARTS):
                raise ValueError("secret-like metadata keys are not permitted")
            if value is not None and not isinstance(value, (str, int, float, bool)):
                raise ValueError("metadata values must be JSON scalar values")
            copied[key] = value
        object.__setattr__(self, "metadata", MappingProxyType(copied))

    def to_dict(self) -> dict[str, object]:
        return {
            "audit_id": self.audit_id,
            "case_id": self.case_id,
            "execution_id": self.execution_id,
            "authorization_id": self.authorization_id,
            "agent_name": self.agent_name,
            "source_class": self.source_class.value,
            "event_type": self.event_type.value,
            "decision": self.decision,
            "timestamp": self.timestamp.isoformat(),
            "message": self.message,
            "metadata": dict(self.metadata),
        }


class AuditLog:
    """Append JSONL events outside Git; external tamper resistance is not claimed."""

    def __init__(self, *, repo_root: Path, root: Path | None = None) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.root = (default_audit_root() if root is None else Path(root)).resolve()
        if _is_within(self.root, self.repo_root) or _is_within(self.repo_root, self.root):
            raise ValueError("audit log must be outside and disjoint from the repository")

    def append(self, entry: AuditEntry) -> Path:
        if not isinstance(entry, AuditEntry):
            raise ValueError("AuditEntry required")
        path = self._path_for(entry.case_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(entry.to_dict(), ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
        descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            written = os.write(descriptor, payload)
            if written != len(payload):
                raise OSError("incomplete audit append")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return path

    def read(self, case_id: str) -> tuple[dict[str, object], ...]:
        path = self._path_for(case_id)
        if not path.exists():
            return ()
        entries: list[dict[str, object]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    entries.append(json.loads(line))
        return tuple(entries)

    def _path_for(self, case_id: str) -> Path:
        validate_case_id(case_id)
        path = (self.root / case_id / "audit.jsonl").resolve()
        if not _is_within(path, self.root):
            raise ValueError("audit path escaped audit root")
        return path
