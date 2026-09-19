"""Atomic private storage for case manifests, plans, and run summaries."""

from datetime import datetime
import json
import os
from pathlib import Path
import tempfile
from typing import Mapping

from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity, validate_case_id
from osint_lab.evidence.vault import default_vault_root
from osint_lab.policies import SourceClass


def default_case_root(environment: Mapping[str, str] | None = None) -> Path:
    return default_vault_root(environment)


def _is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _timestamp_slug(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.strftime("%Y%m%dT%H%M%S%fZ")


class CaseStore:
    """Keep private case application state outside and disjoint from Git."""

    def __init__(self, *, repo_root: Path, root: Path | None = None) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.root = (default_case_root() if root is None else Path(root)).resolve()
        if _is_within(self.root, self.repo_root) or _is_within(self.repo_root, self.root):
            raise ValueError("case store must be outside and disjoint from the repository")

    def create(self, manifest: CaseManifest) -> Path:
        if not isinstance(manifest, CaseManifest):
            raise ValueError("validated CaseManifest required")
        path = self._case_directory(manifest.case_id) / "case.json"
        if path.exists():
            raise FileExistsError("case manifest already exists")
        self._write_json(path, manifest.to_dict())
        return path

    def save(self, manifest: CaseManifest) -> Path:
        if not isinstance(manifest, CaseManifest):
            raise ValueError("validated CaseManifest required")
        path = self._case_directory(manifest.case_id) / "case.json"
        self._write_json(path, manifest.to_dict())
        return path

    def load(self, case_id: str) -> CaseManifest:
        path = self._case_directory(case_id) / "case.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise FileNotFoundError("case manifest was not found") from None
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("case manifest could not be loaded") from error
        if not isinstance(payload, dict):
            raise ValueError("case manifest must be a JSON object")
        try:
            return CaseManifest(
                case_id=payload["case_id"],
                case_name=payload["case_name"],
                created_at=datetime.fromisoformat(payload["created_at"]),
                authorized_by=payload["authorized_by"],
                purpose=payload["purpose"],
                legal_basis_or_consent_note=payload["legal_basis_or_consent_note"],
                seed_entities=tuple(
                    SeedEntity(entity_type=item["entity_type"], value=item["value"])
                    for item in payload["seed_entities"]
                ),
                allowed_source_classes=frozenset(
                    SourceClass(item) for item in payload["allowed_source_classes"]
                ),
                forbidden_source_classes=frozenset(
                    SourceClass(item) for item in payload["forbidden_source_classes"]
                ),
                allowed_agent_types=frozenset(payload["allowed_agent_types"]),
                third_party_api_allowed=payload.get("third_party_api_allowed", False),
                tor_allowed=payload.get("tor_allowed", False),
                direct_target_allowed=payload.get("direct_target_allowed", False),
                retention_days=payload["retention_days"],
                notes=payload.get("notes", ""),
                status=CaseStatus(payload["status"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("case manifest failed validation") from error

    def save_plan(self, *, case_id: str, created_at: datetime, payload: Mapping[str, object]) -> Path:
        path = self._case_directory(case_id) / "plans" / f"plan_{_timestamp_slug(created_at)}.json"
        self._write_json(path, payload)
        return path

    def save_run_summary(
        self,
        *,
        case_id: str,
        finished_at: datetime,
        payload: Mapping[str, object],
    ) -> Path:
        path = self._case_directory(case_id) / "runs" / f"run_{_timestamp_slug(finished_at)}.json"
        self._write_json(path, payload)
        return path

    def latest_run_summary(self, case_id: str) -> dict[str, object]:
        directory = self._case_directory(case_id) / "runs"
        paths = sorted(directory.glob("run_*.json")) if directory.is_dir() else []
        if not paths:
            raise FileNotFoundError("case has no stored run summary")
        try:
            payload = json.loads(paths[-1].read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("latest run summary could not be loaded") from error
        if not isinstance(payload, dict):
            raise ValueError("latest run summary must be a JSON object")
        return payload

    def _case_directory(self, case_id: str) -> Path:
        validate_case_id(case_id)
        path = (self.root / case_id).resolve()
        if not _is_within(path, self.root):
            raise ValueError("case path escaped case root")
        return path

    def _write_json(self, path: Path, payload: Mapping[str, object]) -> None:
        if not isinstance(payload, Mapping):
            raise ValueError("stored payload must be a mapping")
        content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        self._atomic_write(path, content)

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
