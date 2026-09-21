"""Private atomic storage and append-only manual review history."""

from datetime import datetime
import json
import os
from pathlib import Path
import tempfile
from typing import Mapping

from osint_lab.case_manifest import validate_case_id

from .models import AccountReviewStatus


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


class AccountAuditStore:
    def __init__(self, *, repo_root: Path, case_root: Path) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.case_root = Path(case_root).resolve()
        if _within(self.case_root, self.repo_root) or _within(self.repo_root, self.case_root):
            raise ValueError("account-audit storage must be outside and disjoint from Git")

    def save_private_input(self, *, case_id: str, email: str, created_at: datetime) -> Path:
        path = self._directory(case_id) / "private_input.json"
        self._atomic_json(path, {"email": email, "created_at": created_at.isoformat(), "mode": "ACCOUNT_AUDIT"})
        return path

    def save_run(self, *, case_id: str, payload: Mapping[str, object]) -> Path:
        path = self._directory(case_id) / "account_audit_run.json"
        self._atomic_json(path, payload)
        return path

    def load_run(self, case_id: str) -> dict[str, object]:
        path = self._directory(case_id) / "account_audit_run.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("stored account-audit run must be an object")
        return payload

    def append_review(
        self,
        *,
        case_id: str,
        service_id: str,
        status: AccountReviewStatus,
        note: str,
        timestamp: datetime,
    ) -> Path:
        path = self._directory(case_id) / "review_history.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({
            "service_id": service_id,
            "review_status": status.value,
            "user_note": note,
            "timestamp": timestamp.isoformat(),
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            if os.write(descriptor, line) != len(line):
                raise OSError("incomplete review history append")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return path

    def review_history(self, case_id: str) -> tuple[dict[str, object], ...]:
        path = self._directory(case_id) / "review_history.jsonl"
        if not path.is_file():
            return ()
        return tuple(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())

    def _directory(self, case_id: str) -> Path:
        validate_case_id(case_id)
        path = (self.case_root / case_id / "account_audit").resolve()
        if not _within(path, self.case_root):
            raise ValueError("account-audit path escaped case root")
        return path

    @staticmethod
    def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
        content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
