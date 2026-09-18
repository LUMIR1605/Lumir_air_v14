"""Local evidence vault with integrity metadata and no pretend encryption."""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Mapping, Protocol
from uuid import uuid4

from osint_lab.case_manifest import CaseManifest, validate_case_id
from osint_lab.policies import SourceClass


VAULT_SUBDIRECTORIES = (
    "findings",
    "artifacts",
    "screenshots",
    "raw",
    "logs",
    "reports",
    "graph",
)
ARTIFACT_SUBDIRECTORIES = frozenset({"artifacts", "screenshots", "raw"})


class VaultEncryption(Protocol):
    """Future encryption adapter; no implementation is bundled in v1."""

    name: str

    def encrypt(self, plaintext: bytes, *, case_id: str, evidence_id: str) -> bytes: ...

    def decrypt(self, ciphertext: bytes, *, case_id: str, evidence_id: str) -> bytes: ...


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


def _is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def default_vault_root(environment: Mapping[str, str] | None = None) -> Path:
    values = os.environ if environment is None else environment
    local_app_data = values.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("LOCALAPPDATA is required for the default Windows evidence vault")
    return Path(local_app_data) / "LumirOSINTLab" / "cases"


@dataclass(frozen=True, kw_only=True)
class EvidenceArtifact:
    evidence_id: str
    case_id: str
    filename: str
    original_source: str
    collected_at: datetime
    sha256: str
    media_type: str
    size: int
    collector_name: str
    source_class: SourceClass
    notes: str

    def __post_init__(self) -> None:
        _require_text("evidence_id", self.evidence_id)
        validate_case_id(self.case_id)
        _validate_filename(self.filename)
        for name in ("original_source", "media_type", "collector_name"):
            _require_text(name, getattr(self, name))
        _require_aware("collected_at", self.collected_at)
        if len(self.sha256) != 64 or any(character not in "0123456789abcdef" for character in self.sha256):
            raise ValueError("sha256 must be a lowercase SHA-256 digest")
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise ValueError("size must be a non-negative integer")
        if not isinstance(self.source_class, SourceClass):
            raise ValueError("source_class must be a SourceClass")
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "filename": self.filename,
            "original_source": self.original_source,
            "collected_at": self.collected_at.isoformat(),
            "sha256": self.sha256,
            "media_type": self.media_type,
            "size": self.size,
            "collector_name": self.collector_name,
            "source_class": self.source_class.value,
            "notes": self.notes,
        }


def _validate_filename(filename: str) -> str:
    _require_text("filename", filename)
    if filename in {".", ".."} or "/" in filename or "\\" in filename:
        raise ValueError("filename must not contain a path")
    return filename


class EvidenceVault:
    """Write case data only to a dedicated root outside the repository."""

    def __init__(self, *, repo_root: Path, root: Path | None = None) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.root = (default_vault_root() if root is None else Path(root)).resolve()
        if _is_within(self.root, self.repo_root) or _is_within(self.repo_root, self.root):
            raise ValueError("evidence vault must be outside and disjoint from the repository")

    def create_case(self, manifest: CaseManifest) -> Path:
        if not isinstance(manifest, CaseManifest):
            raise ValueError("validated CaseManifest required")
        case_directory = self._case_directory(manifest.case_id)
        case_directory.mkdir(parents=True, exist_ok=True)
        for name in VAULT_SUBDIRECTORIES:
            (case_directory / name).mkdir(exist_ok=True)
        payload = json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        self._atomic_write(case_directory / "case.json", payload)
        return case_directory

    def store_bytes(
        self,
        *,
        case_id: str,
        filename: str,
        content: bytes,
        original_source: str,
        collected_at: datetime,
        media_type: str,
        collector_name: str,
        source_class: SourceClass,
        notes: str = "",
        category: str = "artifacts",
    ) -> EvidenceArtifact:
        validate_case_id(case_id)
        _validate_filename(filename)
        if not isinstance(content, bytes):
            raise ValueError("content must be bytes")
        if category not in ARTIFACT_SUBDIRECTORIES:
            raise ValueError("unsupported artifact category")
        case_directory = self._case_directory(case_id)
        if not (case_directory / "case.json").is_file():
            raise FileNotFoundError("case must be created before storing evidence")
        evidence_id = f"ev-{uuid4().hex}"
        record = EvidenceArtifact(
            evidence_id=evidence_id,
            case_id=case_id,
            filename=filename,
            original_source=original_source,
            collected_at=collected_at,
            sha256=hashlib.sha256(content).hexdigest(),
            media_type=media_type,
            size=len(content),
            collector_name=collector_name,
            source_class=source_class,
            notes=notes,
        )
        category_directory = case_directory / category
        final_directory = category_directory / evidence_id
        staging_directory = category_directory / f".tmp-{evidence_id}"
        staging_directory.mkdir(exist_ok=False)
        try:
            self._atomic_write(staging_directory / filename, content)
            metadata = json.dumps(record.to_dict(), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            self._atomic_write(staging_directory / "metadata.json", metadata)
            os.replace(staging_directory, final_directory)
        except Exception:
            shutil.rmtree(staging_directory, ignore_errors=True)
            raise
        return record

    def evidence_directory(self, artifact: EvidenceArtifact, *, category: str = "artifacts") -> Path:
        if not isinstance(artifact, EvidenceArtifact):
            raise ValueError("EvidenceArtifact required")
        if category not in ARTIFACT_SUBDIRECTORIES:
            raise ValueError("unsupported artifact category")
        path = self._case_directory(artifact.case_id) / category / artifact.evidence_id
        if not _is_within(path.resolve(), self.root):
            raise ValueError("evidence path escaped vault root")
        return path

    def _case_directory(self, case_id: str) -> Path:
        validate_case_id(case_id)
        path = (self.root / case_id).resolve()
        if not _is_within(path, self.root):
            raise ValueError("case path escaped vault root")
        return path

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
