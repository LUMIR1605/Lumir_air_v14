# Lumir SHIELD Engine Truthfulness Audit

## Fixes

| File / function | Previous problem | New behavior | Regression test |
| --- | --- | --- | --- |
| `shield/risk_score.py` / report calculation | Unavailable modules were skipped and the remaining score could look complete. | `shield.truth.assessment` uses only completed modules and records excluded modules, normalized weights and coverage. | `test_coverage_excludes_partial_and_not_applicable` |
| `shield/breach_scan.py` / `scan` | Missing HIBP key exposed an empty breach list shaped like a negative result. | Missing key returns `unavailable`, `breaches: null`, `score: null` and an approved-source record. | `test_hibp_without_key_is_unavailable` |
| `shield/email_scan.py` / `scan` | Account exposure helper could query unapproved services. | Exposure is `not_checked`; profile reports the module as blocked without a approved source. | manual profile review |
| `shield/domain_scan.py` / `scan` | Direct website probing was performed without an approved source. | Domain module is DNS-only; web security remains explicitly blocked in profiles. | scan schema validation |
| `shield/report_builder.py` / `build` | JSON was a wrapper around an in-memory result. | Validated v3 report is written directly and HTML/PDF read that persisted JSON. | `test_invalid_non_completed_score_is_rejected` |

## Approved sources

- `hibp_v3`: approved official API, requires a lawful key.
- `local_dns`: approved local technical DNS analysis.

`public_web_probe` is pending and disabled. It is never invoked by V3.
