# Report Engine MVP

## IMPLEMENTED

`ReportEngine` creates private JSON and HTML reports from one `CaseRunResult` model. Reports include case metadata, executive summary, private seed values, executions, raw observations with JSON-safe payloads, receipts, evidence references, finding candidates, deterministic contradiction results, privacy/source exposure counts, known collector limitations, and audit verification/head hash. Report schema `1.1` adds observations additively.

For `phone_metadata`, HTML renders the numbering-plan payload as explicit technical fields. Missing carrier or geographic values are shown as `Brak danych lokalnych`; JSON preserves the original `null`. The section states that numbering-plan data do not confirm the current operator, owner, or a person's location. Receipt and audit serialization remain unchanged and do not receive the raw phone number.

Report wording is intentionally conservative: technical metadata, public signal, possible profile candidate, not independently verified, and unable to determine. Collector candidates are never described as proven ownership or the same person.

Each format is SHA-256 hashed and first stored through Evidence Vault as a `case_report_engine` artifact. Only after both vault writes succeed are direct private files atomically published under:

`%LOCALAPPDATA%\LumirOSINTLab\cases\<case_id>\reports\report_<timestamp>.json|html`

The returned `ReportReference` contains both paths, hashes, and vault evidence IDs. A report failure degrades the case result to `PARTIAL` or `FAILED`; it cannot be reported as full success. HTML escapes all case and evidence text.

Contradictions use the existing `detect_contradictions()` foundation on explicit assertions. The report records `NONE`, `LOW`, `MEDIUM`, or `HIGH`, reasons, and evidence references. It does not resolve contradictions or identity automatically.

## PLANNED

- Schema migration/version compatibility and report redaction profiles.
- Optional reviewer annotations, verification decisions, and approved export bundles.
- Retention enforcement and encrypted-at-rest case storage.

## NOT IMPLEMENTED

- PDF, public sharing, email delivery, cloud upload, GUI, AI narrative generation, or identity verdicts.
- Encryption, external audit witnessing, or cryptographic report signatures.
