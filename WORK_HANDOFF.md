# LUMIR OSINT LAB — work handoff

## Current Status
Etap 10 Windows Desktop Launcher MVP is implemented on `feature/osint-lab-v1`: a thin Tkinter GUI accepts phone, email, username, and domain inputs, creates private cases, invokes the existing CaseRunner, displays progress and summary, and opens validated report/case paths. CLI and desktop share one composition root. No collector or Etap 4 enforcement path was replaced. SHIELD RC6 code was not changed.

## Last Verified Commit
Etap 9 baseline `825c9df`; branch baseline `main`: `d881757`. Use `git log -1` for the latest Etap 10 commit after publication.

## Environment
Microsoft Windows `10.0.26200.9457`; Python `3.14.6` (`C:\Python314\python.exe`), pip `26.1.2`, pytest `8.4.2`, phonenumbers `9.0.34`, dnspython `2.8.0`, requests `2.34.2`. The repository uses minimum dependency bounds rather than a locked release environment.

## Tests
Final Etap 10 Windows verification: focused desktop suite PASS (`13 passed`); `python -m pytest -q` PASS (`205 passed in 7.33s`); `python test_shield.py` RC6 PASS (`5/5`, exit `0`); CLI help and `git diff --check` PASS. Automated tests require no real monitor and the real desktop phone-path fixture performs no network access. Manual smoke PASS with a reserved `.test` email and PASSIVE_WEB off: analysis returned `PARTIAL`, HTML opened automatically and by button, the case folder opened in Explorer, relaunch worked, and the created Desktop shortcut launched the GUI.

## What Works
The full authorized workflow now runs `Desktop/CLI -> CaseManifest -> Plan -> PolicyGate/Registry -> Orchestrator -> Collectors -> Evidence/Receipts -> Aggregation/Contradictions -> JSON/HTML Report -> Audit verification`. CaseRunner never calls `_run()` and separately plans email local, exposure, and domain DNS steps. Reports are private case artifacts, SHA-256 hashed, and stored in Evidence Vault before direct publication. Audit stores seed hashes rather than raw seeds. PASSIVE_WEB is off by default in the desktop form.

## Known Problems
The runner is sequential and has no budgets, cancellation/resume, scheduler, or persistent background jobs. The GUI uses a process-local worker only for responsiveness. Reports are private and plaintext; encryption, redacted export, PDF, signatures, installer/updater, and external audit witnessing remain unimplemented. Contradictions are deterministic inclusions from explicit assertions, not automated resolution. Existing collector limitations remain: public signals and technical metadata do not establish owner or identity.

## Architecture Decisions
Plans are advisory and transparent, while Orchestrator enforcement remains authoritative at execution time. Policy-denied steps are submitted only to record the denial; their collectors do not run and source exposure remains zero. Email-derived DNS is a separate dependent step and is never invoked from an email collector. A report write or audit verification failure cannot return full `SUCCESS`. Desktop and CLI construction plus manifest policy live in one shared application module; GUI status callbacks are observational and do not control execution.

## Current Task
Implementation, automated regression, RC6, CLI regression, manual Windows GUI smoke, Desktop shortcut creation/launch, documentation, and shield checks are complete. Create logical Etap 10 commits, verify a clean tree, and publish `feature/osint-lab-v1` without force push.

## Next Task
After Etap 10 publication, prioritize review/redacted export, cancellation/budgets/rate limits, or signed installer packaging—not new identity inference or collector bypasses.

## Files Changed
Etap 10 adds the shared application composition module, desktop backend and Tk GUI, Windows launcher and shortcut script, offline desktop tests, and desktop documentation. It adds observational progress callbacks to CaseRunner and refactors the CLI to use shared construction. No file under `shield/` is modified.

## Safety Notes
End-to-end tests use only synthetic identifiers and reserved `.test` domains with mocked DNS/HTTP; no user case data or public request is used. Case manifests, plans, run summaries, reports, audit, authorization history, and evidence must remain outside Git under their configured `%LOCALAPPDATA%\LumirOSINTLab` roots. The private vault remains plaintext.
