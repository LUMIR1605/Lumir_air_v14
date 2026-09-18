# LUMIR OSINT LAB — work handoff

## Current Status
Foundation v1 is applied on `feature/osint-lab-v1` and verified on the user's Windows checkout. SHIELD RC6 code was not changed.

## Last Verified Commit
`f30ed64` (complete applied patch series; full suite verified before this Windows handoff update). Branch baseline `main`: `d881757`. Use `git log -1` for the latest handoff-only commit.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Windows verification after applying the patch: `python -m pytest -q` PASS (`15 passed in 13.36s`); `python test_shield.py` reports `5/5` input-detection smoke checks and exits `0`; `git diff --check main...HEAD` PASS. Tests use fixtures/mocks for OSINT LAB and regression paths; the existing smoke command retains the current SHIELD scanner behavior. No new failure class.

## What Works
RC6 identifies itself consistently as engine `0.6.0` with report schema `3.0`; consent-based self scan and existing reports remain on their original code paths. No path under `shield/` differs from `main`. Isolated `osint_lab` provides strict source classes, source policy with local-only default, a validated finding schema, raw observation contract and conservative `FOUND → POSSIBLE` normalization. Four new focused tests pass.

## Known Problems
See [audit](docs/OSINT_LAB_AUDIT.md). Key items: old Sherlock adapter treats URLs in stdout as found/risk without verification; DNS resolution exceptions can be presented as absent domain; fallback source can mislabel provenance; Holehe can make outbound provider queries; historic exposed API key noted in `docs/SECRET_ROTATION.md` requires independent confirmation of revocation. Current tracked-file pattern review revealed no obvious live secret or case dataset; it cannot establish absence across Git history or all formats. Existing tests do not verify Windows GUI or installer.

## Architecture Decisions
Package at repository root because `shield/` and `lumir/` are already top-level; no import into RC6. Planned pipeline and agent roles are described in [architecture](docs/OSINT_LAB_ARCHITECTURE.md). No network collector, Tor agent, vault implementation, automatic correlation, or verification engine exists. `DIRECT_TARGET` is disabled by default. Future verification should record independent evidence in a separate reviewed decision rather than promoting collector output.

## Current Task
Foundation complete and verified in the Windows checkout. Publish `feature/osint-lab-v1` without force push, then review remote CI and the branch diff before merge.

## Next Task
Review remote CI and merge readiness. A GUI/report walkthrough is still separate from the automated RC6 checks recorded here. Next implementation milestone: authorization manifest plus a private evidence vault outside Git, with retention, integrity and source-class enforcement before integrating any collector.

## Files Changed
Created: `WORK_HANDOFF.md`, `docs/OSINT_LAB_AUDIT.md`, `docs/OSINT_LAB_ARCHITECTURE.md`, `osint_lab/` package (12 files), `tests/test_osint_lab_foundation.py`. Modified: `.gitignore`. No files under `shield/` modified.

## Safety Notes
Only synthetic test identifiers were added. Store actual case data and evidence outside the repo, for example `%LOCALAPPDATA%/LumirOSINTLab/cases`, with access controls; `.gitignore` also blocks common accidental in-repo paths, SQLite case stores and `.env`. Git history may retain an old revoked key: never reuse it; confirm rotation before exposure. Any network class beyond local requires a separate explicit allow decision and authorization. No authentication bypass, credential misuse, exploitation, illegal datasets or evasion.
