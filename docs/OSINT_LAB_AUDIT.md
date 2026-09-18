# OSINT LAB — repo audit before changes

Baseline commit: `1bbbbea92a8bde72cef6863c7457c8d0c2831de7` (`main`); clean checkout, no uncommitted files. Audit performed in a Linux clone, not on the user's Windows laptop. No Windows version or laptop Python/pip version was observable.

## Inventory

- Entrypoints: `lumir_shield_app.py` (Windows Tk GUI), `shield.py` (consent-based CLI), `lumir/__main__.py` (older AIR news/music workflow), `radar.py`. `shield/core.py` is an API wrapper; `shield/multi_scan.py` dispatches scanners.
- SHIELD active paths: email DNS, HIBP with configured key, consent-gated Holehe account exposure, local phone metadata, single GitHub username lookup, DNS domain analysis. URL and web probing are blocked in the RC6 dispatcher. `shield/input_validation.py` normalizes user input; `shield/truth.py` gates sources and scores coverage.
- Adapter/legacy surface: `shield/sherlock_scan.py`, `shield/social_scan.py`, `shield/url_scan.py`, `shield/phone_sources/*`, `radar_reference.py`, and older `modules/`, `sources/`, `intelligence/`, `output/`. Presence in the tree is not evidence that an adapter runs in RC6; Sherlock is not called by `shield/multi_scan.py`. `config.yaml` is empty; `data/history.json` and `data/music_queue.json` are tracked AIR state placeholders.
- Dependencies: `requirements.txt` contains requests, dnspython, phonenumbers, reportlab, GUI support via standard-library tkinter, and AIR/music dependencies. Sherlock and Holehe are subprocess adapters, not declared Python dependencies. No new third-party OSINT packages added.
- Reports: RC6 GUI/CLI build JSON, HTML, PDF via `shield/report_builder.py`, `shield/html_report.py`, `shield/pdf_report.py`, and local `shield/report_paths.py` (`%USERPROFILE%/Lumir SHIELD/Reports`). `shield/core.py` still writes `shield_report.json` in the working directory. Other AIR output paths live in `output/` and `core/config.py`.
- Network: explicit DNS resolver calls to 1.1.1.1 / 8.8.8.8 in email/domain modules; GitHub REST username lookup; HIBP REST with environment key; optional Holehe CLI may contact third-party providers despite the adapter name `holehe_local`. `shield/url_scan.py` can issue HTTP requests when called directly, although RC6 dispatcher blocks it. `core/network.py` is another general network wrapper for AIR.
- Storage: local report files and AIR JSON history/queue; no case vault in the baseline. Scan targets and evidence can appear in SHIELD JSON and filenames. Case storage needs its own path outside the repository and explicit retention/access policy.
- Tests: `tests/test_truthfulness.py`, `tests/test_self_scan_flow.py`, `tests/test_account_exposure_scan.py`, plus `test_shield.py`. Baseline after installing `requirements.txt` into ignored `.venv`: `19 passed in 0.43s`; smoke input checks `5/5`. Initial system Python attempt failed before collection with `No module named pytest`.

## Risks / follow-up findings

1. `shield/sherlock_scan.py` parses any stdout line with `https://` as a found service and emits `risk=medium`; it lacks exit-code and ownership verification. Isolated from RC6 dispatcher, but must not be reused without normalization and independent verification.
2. `shield/domain_scan.py` returns `exists=False` on any resolution exception, including transient network errors, with a high-risk narrative. Treat DNS transport failure as unknown in future integration.
3. `shield/multi_scan.py` uses `local_dns` as a fallback source for scanner output missing `sources`; this can misattribute provenance. SHIELD `confidence` may describe source/control confidence rather than identity linkage.
4. `shield/account_exposure_scan.py` correctly marks Holehe results probable and excludes them from security score, yet its source name suggests a local-only operation. Any future policy classification must reflect the actual outbound provider queries.
5. `shield/core.py` and the GUI/CLI have different report path strategies. There are duplicate reporting and network abstractions elsewhere in AIR; do not unify them during foundation work.
6. `.env` was not ignored, despite `.env.example` saying it must not be committed. Existing `docs/SECRET_ROTATION.md` states an API key appeared in Git history and requires revocation/rotation; the latest tracked config example uses a placeholder. An audit of visible current tracked text found no obvious live token or personal case data, but pattern scanning cannot prove their absence, and history remains a separate exposure. Never copy historical key material into reports.

## Baseline environment

Linux `6.18.44`; Python `3.12.14`; system pip `26.2.1`; clean venv installed from unconstrained minimum-version `requirements.txt`. Tests here do not validate Windows packaging, Windows GUI, or original pinned RC6 dependency versions.
