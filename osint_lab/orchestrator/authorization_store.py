"""Durable, append-only local history for scoped run authorizations."""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Mapping, Protocol
from uuid import uuid4

from osint_lab.case_manifest import validate_case_id
from osint_lab.policies import SourceClass

from .authorization import AuthorizationDecision, RunAuthorization


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class AuthorizationSignatureProvider(Protocol):
    """Interface only; key management and signatures are not implemented."""

    name: str

    def sign(self, payload: bytes) -> str: ...

    def verify(self, payload: bytes, signature: str) -> bool: ...


def default_authorization_root(environment: Mapping[str, str] | None = None) -> Path:
    values = os.environ if environment is None else environment
    local_app_data = values.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("LOCALAPPDATA is required for the default authorization store")
    return Path(local_app_data) / "LumirOSINTLab" / "authorizations"


def _is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _validate_authorization_id(value: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ValueError("authorization_id must be a safe non-empty identifier")
    return value


def _serialize(authorization: RunAuthorization) -> dict[str, object]:
    return {
        "authorization_id": authorization.authorization_id,
        "case_id": authorization.case_id,
        "requested_agent": authorization.requested_agent,
        "requested_source_class": authorization.requested_source_class.value,
        "requested_at": authorization.requested_at.isoformat(),
        "requested_by": authorization.requested_by,
        "purpose": authorization.purpose,
        "decision": authorization.decision.value,
        "decision_at": authorization.decision_at.isoformat(),
        "approved_by": authorization.approved_by,
        "expires_at": authorization.expires_at.isoformat(),
        "scope": authorization.scope,
        "notes": authorization.notes,
    }


def _deserialize(payload: object) -> RunAuthorization:
    if not isinstance(payload, dict):
        raise ValueError("authorization record must be a JSON object")
    expected = {
        "authorization_id", "case_id", "requested_agent", "requested_source_class",
        "requested_at", "requested_by", "purpose", "decision", "decision_at",
        "approved_by", "expires_at", "scope", "notes",
    }
    if set(payload) != expected:
        raise ValueError("authorization record has an unexpected schema")
    try:
        return RunAuthorization(
            authorization_id=payload["authorization_id"],
            case_id=payload["case_id"],
            requested_agent=payload["requested_agent"],
            requested_source_class=SourceClass(payload["requested_source_class"]),
            requested_at=datetime.fromisoformat(payload["requested_at"]),
            requested_by=payload["requested_by"],
            purpose=payload["purpose"],
            decision=AuthorizationDecision(payload["decision"]),
            decision_at=datetime.fromisoformat(payload["decision_at"]),
            approved_by=payload["approved_by"],
            expires_at=datetime.fromisoformat(payload["expires_at"]),
            scope=payload["scope"],
            notes=payload["notes"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid authorization record") from error


@dataclass(frozen=True)
class AuthorizationStoreRecord:
    path: Path
    authorization: RunAuthorization


class AuthorizationStore:
    """Persist immutable authorization decisions outside Git using atomic files."""

    def __init__(self, *, repo_root: Path, root: Path | None = None) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.root = (default_authorization_root() if root is None else Path(root)).resolve()
        if _is_within(self.root, self.repo_root) or _is_within(self.repo_root, self.root):
            raise ValueError("authorization store must be outside and disjoint from the repository")

    def save(self, authorization: RunAuthorization) -> AuthorizationStoreRecord:
        if not isinstance(authorization, RunAuthorization):
            raise ValueError("RunAuthorization required")
        history = self.history(authorization.case_id, authorization.authorization_id)
        if history:
            self._validate_binding(history[0], authorization)
        directory = self._directory(authorization.case_id, authorization.authorization_id)
        directory.mkdir(parents=True, exist_ok=True)
        filename = f"{authorization.decision_at.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}-{uuid4().hex}.json"
        destination = directory / filename
        payload = json.dumps(_serialize(authorization), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        self._atomic_create(destination, payload)
        return AuthorizationStoreRecord(destination, authorization)

    def load(self, case_id: str, authorization_id: str) -> RunAuthorization:
        history = self.history(case_id, authorization_id)
        if not history:
            raise FileNotFoundError("authorization was not found for this case")
        return history[-1]

    def history(self, case_id: str, authorization_id: str) -> tuple[RunAuthorization, ...]:
        directory = self._directory(case_id, authorization_id)
        if not directory.exists():
            return ()
        records: list[tuple[datetime, str, RunAuthorization]] = []
        for path in directory.glob("*.json"):
            try:
                authorization = _deserialize(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
                raise ValueError(f"invalid authorization history record: {path.name}") from error
            if authorization.case_id != case_id or authorization.authorization_id != authorization_id:
                raise ValueError("authorization history record does not match its storage path")
            records.append((authorization.decision_at, path.name, authorization))
        records.sort(key=lambda item: (item[0], item[1]))
        return tuple(item[2] for item in records)

    def _directory(self, case_id: str, authorization_id: str) -> Path:
        validate_case_id(case_id)
        _validate_authorization_id(authorization_id)
        path = (self.root / case_id / authorization_id).resolve()
        if not _is_within(path, self.root):
            raise ValueError("authorization path escaped authorization root")
        return path

    @staticmethod
    def _validate_binding(previous: RunAuthorization, current: RunAuthorization) -> None:
        fields = (
            "case_id", "requested_agent", "requested_source_class", "requested_at",
            "requested_by", "purpose", "scope",
        )
        if any(getattr(previous, field) != getattr(current, field) for field in fields):
            raise ValueError("authorization binding cannot change within an existing history")

    @staticmethod
    def _atomic_create(path: Path, payload: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=".auth-", suffix=".tmp")
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary_path, path)
            temporary_path.unlink()
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
