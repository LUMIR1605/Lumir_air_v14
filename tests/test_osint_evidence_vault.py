from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.evidence import EvidenceVault, default_vault_root
from osint_lab.evidence.vault import VAULT_SUBDIRECTORIES
from osint_lab.policies import SourceClass


def manifest():
    return CaseManifest(
        case_id="case-vault-001",
        case_name="Synthetic vault fixture",
        created_at=datetime.now(timezone.utc),
        authorized_by="fixture-owner",
        purpose="Verify local vault behavior",
        legal_basis_or_consent_note="Synthetic fixture only.",
        seed_entities=(SeedEntity(entity_type="DOMAIN", value="example.test"),),
        allowed_source_classes=frozenset({SourceClass.LOCAL}),
        allowed_agent_types=frozenset({"FixtureAgent"}),
        status=CaseStatus.ACTIVE,
    )


def test_default_vault_root_uses_local_app_data():
    root = default_vault_root({"LOCALAPPDATA": r"C:\Users\Fixture\AppData\Local"})
    assert root == Path(r"C:\Users\Fixture\AppData\Local") / "LumirOSINTLab" / "cases"
    with pytest.raises(RuntimeError):
        default_vault_root({})


def test_vault_rejects_repo_or_ancestor_paths(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ValueError):
        EvidenceVault(repo_root=repo, root=repo / "case_data")
    with pytest.raises(ValueError):
        EvidenceVault(repo_root=repo, root=tmp_path)


def test_create_case_writes_manifest_and_required_structure_outside_repo(tmp_path):
    repo = tmp_path / "repo"
    vault_root = tmp_path / "private-vault"
    repo.mkdir()
    vault = EvidenceVault(repo_root=repo, root=vault_root)
    case_directory = vault.create_case(manifest())

    assert repo not in case_directory.parents
    assert case_directory == vault_root.resolve() / "case-vault-001"
    assert {path.name for path in case_directory.iterdir() if path.is_dir()} == set(VAULT_SUBDIRECTORIES)
    payload = json.loads((case_directory / "case.json").read_text(encoding="utf-8"))
    assert payload["case_id"] == "case-vault-001"
    assert not list(case_directory.glob("*.tmp"))


def test_store_bytes_writes_hash_metadata_and_payload_atomically(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    vault = EvidenceVault(repo_root=repo, root=tmp_path / "private-vault")
    vault.create_case(manifest())
    content = b"synthetic evidence bytes\n"
    collected_at = datetime.now(timezone.utc)

    artifact = vault.store_bytes(
        case_id="case-vault-001",
        filename="fixture.txt",
        content=content,
        original_source="offline:test-fixture",
        collected_at=collected_at,
        media_type="text/plain",
        collector_name="FixtureAgent",
        collector_version="1.0",
        execution_id="run-vault-001",
        source_class=SourceClass.LOCAL,
        notes="Synthetic only.",
    )
    evidence_directory = vault.evidence_directory(artifact)
    metadata = json.loads((evidence_directory / "metadata.json").read_text(encoding="utf-8"))

    assert artifact.sha256 == hashlib.sha256(content).hexdigest()
    assert artifact.size == len(content)
    assert (evidence_directory / "fixture.txt").read_bytes() == content
    assert metadata["collected_at"] == collected_at.isoformat()
    assert metadata["source_class"] == "LOCAL"
    assert metadata["collector_version"] == "1.0"
    assert metadata["execution_id"] == "run-vault-001"
    assert not list(evidence_directory.parent.glob(".tmp-*"))


def test_vault_rejects_path_traversal_and_unknown_cases(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    vault = EvidenceVault(repo_root=repo, root=tmp_path / "private-vault")
    with pytest.raises(ValueError):
        vault.store_bytes(
            case_id="../escape",
            filename="fixture.txt",
            content=b"x",
            original_source="fixture",
            collected_at=datetime.now(timezone.utc),
            media_type="text/plain",
            collector_name="FixtureAgent",
            collector_version="1.0",
            execution_id="run-vault-001",
            source_class=SourceClass.LOCAL,
        )
    with pytest.raises(FileNotFoundError):
        vault.store_bytes(
            case_id="missing-case",
            filename="fixture.txt",
            content=b"x",
            original_source="fixture",
            collected_at=datetime.now(timezone.utc),
            media_type="text/plain",
            collector_name="FixtureAgent",
            collector_version="1.0",
            execution_id="run-vault-001",
            source_class=SourceClass.LOCAL,
        )


def test_case_data_patterns_are_ignored_and_no_repo_fallback_exists(tmp_path):
    repository = Path(__file__).resolve().parents[1]
    ignore_rules = (repository / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert {".env", ".env.*", "cases/", "case_data/", "evidence_vault/", "*.sqlite"} <= set(ignore_rules)

    simulated_repo = tmp_path / "repo"
    simulated_repo.mkdir()
    vault = EvidenceVault(repo_root=simulated_repo, root=tmp_path / "private-vault")
    assert simulated_repo not in vault.root.parents
    assert vault.root != simulated_repo
