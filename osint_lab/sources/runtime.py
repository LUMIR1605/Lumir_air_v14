"""Local-only health, request budgeting and bounded private source cache."""

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
from threading import Lock
from typing import Mapping
from urllib.parse import urlsplit

from .models import SourceFailureStatus


def _outside_repo(repo_root: Path, target: Path) -> None:
    repo = repo_root.resolve()
    value = target.resolve()
    if value == repo or repo in value.parents:
        raise ValueError("private source state must be outside the repository")


@dataclass(frozen=True, kw_only=True)
class ProviderHealth:
    provider_id: str
    last_success: str | None
    last_failure: str | None
    last_status: SourceFailureStatus
    parser_version: str
    consecutive_failures: int
    challenge_detected: bool
    disabled_reason: str | None

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["last_status"] = self.last_status.value
        return value


class ProviderHealthStore:
    def __init__(self, *, repo_root: Path, case_root: Path) -> None:
        _outside_repo(Path(repo_root), Path(case_root))
        self.path = Path(case_root).resolve() / "source_state" / "provider_health.json"

    def load(self) -> dict[str, ProviderHealth]:
        if not self.path.exists():
            return {}
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        return {key: ProviderHealth(**{**value, "last_status": SourceFailureStatus(value["last_status"])})
                for key, value in payload.items()}

    def record(self, *, provider_id: str, status: SourceFailureStatus, timestamp: datetime,
               parser_version: str, challenge_detected: bool = False,
               disabled_reason: str | None = None) -> ProviderHealth:
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        values = self.load()
        previous = values.get(provider_id)
        success = status is SourceFailureStatus.SUCCESS
        value = ProviderHealth(
            provider_id=provider_id,
            last_success=timestamp.isoformat() if success else (previous.last_success if previous else None),
            last_failure=(previous.last_failure if success and previous else None) if success else timestamp.isoformat(),
            last_status=status, parser_version=parser_version,
            consecutive_failures=0 if success else (previous.consecutive_failures + 1 if previous else 1),
            challenge_detected=challenge_detected, disabled_reason=disabled_reason,
        )
        values[provider_id] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({key: item.to_dict() for key, item in values.items()},
                                        ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")
        os.replace(temporary, self.path)
        return value


@dataclass(frozen=True, kw_only=True)
class RequestBudget:
    max_case_requests: int = 24
    max_provider_requests: int = 24
    max_host_requests: int = 24

    def __post_init__(self) -> None:
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0
               for value in self.__dict__.values()):
            raise ValueError("request budget values must be positive integers")


class RateLimiter:
    """Deterministic serial budget gate; it never sleeps or retries aggressively."""

    def __init__(self, budget: RequestBudget | None = None) -> None:
        self.budget = budget or RequestBudget()
        self._case: dict[str, int] = {}
        self._provider: dict[tuple[str, str], int] = {}
        self._host: dict[tuple[str, str], int] = {}
        self._lock = Lock()

    def reserve(self, *, case_id: str, provider_id: str, url: str, count: int = 1) -> None:
        host = (urlsplit(url).hostname or "").casefold()
        if not case_id or not provider_id or not host or count <= 0:
            raise ValueError("valid case, provider, URL and count are required")
        with self._lock:
            case_value = self._case.get(case_id, 0)
            provider_key = (case_id, provider_id)
            host_key = (case_id, host)
            if case_value + count > self.budget.max_case_requests:
                raise RuntimeError("case request budget exhausted")
            if self._provider.get(provider_key, 0) + count > self.budget.max_provider_requests:
                raise RuntimeError("provider request budget exhausted")
            if self._host.get(host_key, 0) + count > self.budget.max_host_requests:
                raise RuntimeError("host request budget exhausted")
            self._case[case_id] = case_value + count
            self._provider[provider_key] = self._provider.get(provider_key, 0) + count
            self._host[host_key] = self._host.get(host_key, 0) + count

    def snapshot(self, case_id: str) -> dict[str, object]:
        return {
            "case_requests": self._case.get(case_id, 0),
            "provider_requests": {key[1]: value for key, value in self._provider.items() if key[0] == case_id},
            "host_requests": {key[1]: value for key, value in self._host.items() if key[0] == case_id},
        }


class PrivateSourceCache:
    def __init__(self, *, repo_root: Path, case_root: Path, max_entries: int = 128) -> None:
        _outside_repo(Path(repo_root), Path(case_root))
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.directory = Path(case_root).resolve() / "source_cache"
        self.max_entries = max_entries

    @staticmethod
    def fingerprint(*, provider_id: str, request_identity: str) -> str:
        return hashlib.sha256(f"{provider_id}|{request_identity}".encode("utf-8")).hexdigest()

    def put(self, *, provider_id: str, provider_version: str, request_identity: str,
            timestamp: datetime, payload: Mapping[str, object]) -> dict[str, object]:
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        self.directory.mkdir(parents=True, exist_ok=True)
        request_fingerprint = self.fingerprint(provider_id=provider_id, request_identity=request_identity)
        serialized = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, allow_nan=False)
        value = {"timestamp": timestamp.isoformat(), "provider_id": provider_id,
                 "provider_version": provider_version, "request_fingerprint": request_fingerprint,
                 "content_hash": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
                 "payload": json.loads(serialized)}
        path = self.directory / f"{request_fingerprint}.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        os.replace(temporary, path)
        files = sorted(self.directory.glob("*.json"), key=lambda item: item.stat().st_mtime)
        for old in files[:-self.max_entries]:
            old.unlink()
        return value

    def get(self, *, provider_id: str, request_identity: str) -> dict[str, object] | None:
        path = self.directory / f"{self.fingerprint(provider_id=provider_id, request_identity=request_identity)}.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
