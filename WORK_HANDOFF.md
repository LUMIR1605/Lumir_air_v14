# LUMIR OSINT LAB — work handoff

## Current Status
Foundation v1 complete on `feature/osint-lab-v1` in a clean Linux clone. SHIELD RC6 code was not changed. This checkout is not the user's Windows laptop; Windows runtime and packaging need a separate verification.

## Last Verified Commit
`e91b3e3` (foundation code and tests; full suite verified before this handoff documentation commit). Original `main`: `1bbbbea92a8bde72cef6863c7457c8d0c2831de7`. Use `git log -1` for latest handoff-only commit.

## Environment
Linux kernel `6.18.44` x86_64, Python `3.12.14`, venv pip `25.0.1`; initial system pip `26.2.1`. Windows version and laptop Python/pip versions: **not available in this environment**. Dependencies installed in ignored `.venv` from `requirements.txt` with minimum bounds, not a locked release environment.

## Tests
Before edits, system `python -m pytest -q` FAIL before collection: `No module named pytest`; root cause absent test dependency. After venv dependency install, baseline PASS: `19 passed in 0.43s`; `python test_shield.py`: `5/5`. After changes PASS: `23 passed in 0.61s`; smoke `5/5`; `pyflakes` for new files and `git diff --check` PASS. Tests use fixtures/mocks, no live OSINT collection. No new failure class.

## What Works
RC6 consent-based self scan and existing reports remain on their original code paths. Isolated `osint_lab` package provides strict source classes, source policy with local-only default, a validated finding schema, raw observation contract and conservative `FOUND → POSSIBLE` normalization. Four new focused tests pass.

## Known Problems
See [audit](docs/OSINT_LAB_AUDIT.md). Key items: old Sherlock adapter treats URLs in stdout as found/risk without verification; DNS resolution exceptions can be presented as absent domain; fallback source can mislabel provenance; Holehe can make outbound provider queries; historic exposed API key noted in `docs/SECRET_ROTATION.md` requires independent confirmation of revocation. Current tracked-file pattern review revealed no obvious live secret or case dataset; it cannot establish absence across Git history or all formats. Existing tests do not verify Windows GUI or installer.

## Architecture Decisions
Package at repository root because `shield/` and `lumir/` are already top-level; no import into RC6. Planned pipeline and agent roles are described in [architecture](docs/OSINT_LAB_ARCHITECTURE.md). No network collector, Tor agent, vault implementation, automatic correlation, or verification engine exists. `DIRECT_TARGET` is disabled by default. Future verification should record independent evidence in a separate reviewed decision rather than promoting collector output.

## Current Task
Foundation complete in this clone; verify remote branch availability and provide exact test/commit results. Actual laptop state cannot be inspected through this checkout.

## Next Task
On Windows, check working tree and `git status` before switching to this branch, install dependencies in a local venv, run `python -m pytest -q` and `python test_shield.py`, then inspect RC6 GUI/report smoke behavior. Next implementation milestone: authorization manifest plus a private evidence vault outside Git, with retention, integrity and source-class enforcement before integrating any collector.

## Files Changed
Created: `WORK_HANDOFF.md`, `docs/OSINT_LAB_AUDIT.md`, `docs/OSINT_LAB_ARCHITECTURE.md`, `osint_lab/` package (12 files), `tests/test_osint_lab_foundation.py`. Modified: `.gitignore`. No files under `shield/` modified.

## Safety Notes
Only synthetic test identifiers were added. Store actual case data and evidence outside the repo, for example `%LOCALAPPDATA%/LumirOSINTLab/cases`, with access controls; `.gitignore` also blocks common accidental in-repo paths, SQLite case stores and `.env`. Git history may retain an old revoked key: never reuse it; confirm rotation before exposure. Any network class beyond local requires a separate explicit allow decision and authorization. No authentication bypass, credential misuse, exploitation, illegal datasets or evasion.
