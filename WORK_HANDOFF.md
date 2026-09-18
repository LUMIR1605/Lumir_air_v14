# LUMIR OSINT LAB — work handoff

## Current Status
Foundation v2 is implemented on `feature/osint-lab-v1`: validated case manifests, fail-closed PolicyGate, local Evidence Vault, relation graph, and deterministic contradiction checks. SHIELD RC6 code was not changed.

## Last Verified Commit
Implementation and tests through `4456cce`; full suite and RC6 smoke verified before this documentation update. Branch baseline `main`: `d881757`. Use `git log -1` for the latest documentation commit.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Windows verification: baseline `15 passed`; after foundation v2, `python -m pytest -q` PASS (`40 passed`, 25 new cases). `python test_shield.py` reports `5/5` input-detection smoke checks and exits `0`. Tests cover manifest validation, policy decisions, risky-source defaults, real temporary vault writes, SHA-256, path isolation, Git ignore defenses, graph validation, no automatic identity merge, and simple contradictions.

## What Works
RC6 identifies itself as engine `0.6.0` with report schema `3.0`; its existing smoke flow remains on the original code path. No path under `shield/` differs from `main`. OSINT LAB now validates authorization scope, denies risky classes by default, writes integrity-tagged evidence outside Git, preserves distinct graph nodes, and reports deterministic contradiction severity with evidence references.

## Known Problems
The vault is plaintext and has no key management, permission hardening, retention enforcement, secure deletion, or case loader. Graph state is in-memory only. PolicyGate has no per-run approval executor or collector integration. Contradiction rules compare explicit facts but do not establish truth. See [audit](docs/OSINT_LAB_AUDIT.md) for existing SHIELD risks. Existing tests do not verify the Windows GUI or installer.

## Architecture Decisions
Package remains isolated from RC6. Manifest flags and class allowlists are separate from per-run approval: risky classes return `REQUIRE_EXPLICIT_APPROVAL`, never implicit allow. Vault roots must be disjoint from the repo. Encryption is an unimplemented protocol, not a claim. Matching identifiers remain separate nodes unless an evidence-backed relation is explicitly added. Contradiction checks are rules, not AI verdicts.

## Current Task
Foundation v2 is implemented and locally verified. Publish the logical commits to `feature/osint-lab-v1` without force push, then review remote CI and the branch diff before merge.

## Next Task
Design the auditable per-run approval record and orchestrator enforcement before integrating any collector. Separately review encryption/key management, Windows ACLs, retention, and graph persistence. A GUI/report walkthrough remains separate from automated RC6 checks.

## Files Changed
Foundation v2 adds `osint_lab/case_manifest.py`, `policies/gate.py`, `evidence/vault.py`, `correlation/graph.py`, `verification/contradictions.py`, three test modules, and four focused documents. Existing package export files and this handoff are updated. No file under `shield/` is modified.

## Safety Notes
Only synthetic test identifiers were added. Actual case data belongs under `%LOCALAPPDATA%/LumirOSINTLab/cases` or another reviewed disjoint root. Current storage is not encrypted. Any risky source class still requires a future explicit per-run approval record; no network collectors were added. Git history may retain an old revoked key: never reuse it and confirm rotation independently.
