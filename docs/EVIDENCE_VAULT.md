# OSINT LAB evidence vault

## IMPLEMENTED

`osint_lab.evidence.EvidenceVault` stores case material in a dedicated root that must be outside and disjoint from the Git repository. The Windows default is:

`%LOCALAPPDATA%\LumirOSINTLab\cases\<case_id>\`

Creating a case writes `case.json` atomically and creates:

`findings/`, `artifacts/`, `screenshots/`, `raw/`, `logs/`, `reports/`, and `graph/`.

`store_bytes()` accepts only an existing case, a safe filename, bytes, a timezone-aware timestamp, and a declared `SourceClass`. It publishes an evidence directory atomically after writing the payload and `metadata.json`. Metadata contains `evidence_id`, `case_id`, `filename`, `original_source`, `collected_at`, SHA-256, media type, byte size, collector name, source class, and notes.

Case identifiers and filenames reject traversal. Vault roots inside the repository, or broad roots containing the repository, are rejected. `.gitignore` retains defense-in-depth rules for case folders, evidence vaults, SQLite case files, logs, reports, and `.env` files.

`VaultEncryption` is only a future adapter protocol. The current vault writes plaintext bytes and makes no encryption claim.

## PLANNED

- A reviewed encryption provider with key lifecycle, authenticated encryption, recovery, and migration tests.
- Access-control hardening and Windows permission verification.
- Streaming import for large files and verified import from existing paths.
- Retention enforcement, deletion workflow, integrity re-checks, and an evidence index.
- Crash-consistency tests covering multi-file and power-loss scenarios.

## NOT IMPLEMENTED

- No encryption, key management, secure deletion, compression, deduplication, or remote backup.
- No automated collector writes, screenshots, findings, logs, graph persistence, or report generation.
- No guarantee that the host filesystem or user profile is access-controlled.
- No Git-history secret scan or proof that historical secrets were revoked.
