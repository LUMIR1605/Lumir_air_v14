# LUMIR OSINT LAB — work handoff

## Current Status
Foundation v4 is implemented on `feature/osint-lab-v1`: durable scoped RunAuthorization history, mandatory CollectorRegistry and PolicyGate enforcement, tamper-evident audit hash chain, Evidence Vault execution publication, ExecutionReceipt, and fail-closed audit/vault behavior. Only synthetic test collectors exist. SHIELD RC6 code was not changed.

## Last Verified Commit
Implementation and tests through `cd22d7c`; branch baseline `main`: `d881757`. Use `git log -1` for the latest documentation commit.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Windows verification on the documentation HEAD: `python -m pytest -q` PASS (`73 passed`); `python test_shield.py` RC6 PASS (`5/5`, exit `0`); `git diff --check` PASS. Tests cover reload/expiry/revocation/cross-case authorization; valid and damaged audit chains; registry denial, duplicates, mismatches and substitution; vault artifacts and receipt correctness; audit head binding; audit/vault fail-closed behavior; PolicyGate paths; and public bypass attempts. Both the Etap 4 range and the full branch range against `main` contain no path under `shield/`.

## What Works
The Orchestrator validates exact registry metadata before it evaluates CaseManifest and PolicyGate. Risky classes require durable case-specific lookup of the latest matching unexpired approval. After a collector run it atomically stores execution metadata, raw observations and candidates in the vault, records completion in the audit chain, stores an ExecutionReceipt, and only then returns the result. Raw request values are represented in audit metadata by SHA-256 hashes. No path under `shield/` was intentionally changed.

## Known Problems
Authorization signatures, key management, trusted approver identity, multi-process locking, external audit-head witnessing, vault encryption, permission hardening, retention, graph persistence, production collectors, GUI and installer validation remain unimplemented. The audit chain is tamper-evident and does not claim immutability; tail truncation needs an external checkpoint. Python registry and contract controls are not a sandbox against hostile imported code.

## Architecture Decisions
Manifest permission and per-run approval remain separate controls: authorization cannot override PolicyGate. LOCAL and allowed PASSIVE_WEB need no per-run record; THIRD_PARTY_API, TOR and DIRECT_TARGET require an exact durable approval. Registry validation precedes context issuance. Audit failure propagates; a required vault failure returns `FAILED` without observations or receipt. Synthetic collectors remain test-only.

## Current Task
Foundation v4 implementation, focused tests, full pytest, RC6 smoke, shield diff, and whitespace checks are complete. Publish `feature/osint-lab-v1` without force push.

## Next Task
Review the trust and integrity foundation. The next step is acceptance of the authorization, audit, registry, vault, and receipt boundaries plus a separate design for real signatures/key management and concurrency. Do not start PhoneMetadataCollector until that review is accepted.

## Files Changed
Foundation v4 adds the authorization store, audit verifier, collector registry, execution receipt, vault metadata integration, fail-closed orchestrator behavior, focused tests, and four new documents. No production collector was added and no file under `shield/` is modified.

## Safety Notes
Only synthetic references and collectors were added. No test collector performs network access. Authorization, audit, and evidence roots must stay outside Git. Local history and hash chains are not immutable; vault data remains plaintext. Git history may retain an old revoked key: never reuse it and confirm rotation independently.
