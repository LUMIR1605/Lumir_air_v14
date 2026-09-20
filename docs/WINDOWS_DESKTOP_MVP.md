# Windows desktop MVP

## Start

Run `LUMIR_OSINT_LAB.cmd` from the repository or use `CREATE_DESKTOP_SHORTCUT.ps1` once to create `LUMIR OSINT LAB.lnk` on the current user's Desktop. The launcher resolves the repository from its own location, checks Python plus Tkinter imports, and runs `python -m osint_lab.desktop_gui`.

## Workflow

The window accepts any non-empty subset of phone, email, username, and domain. Empty fields are ignored. `PASSIVE_WEB` is off by default; enabling it only adds that source class to the generated case manifest. Every analysis creates a private case under `%LOCALAPPDATA%\LumirOSINTLab\cases`, then uses the shared application services and existing `CaseRunner -> Registry/PolicyGate -> Orchestrator -> Collectors -> Vault/Receipts -> Report` path.

The worker thread keeps Tk responsive and communicates status through a queue. Tk widgets are only updated on the UI thread. On completion the window presents case status, finding counts, contradiction count, and validated actions for opening the HTML report and case folder. The HTML report is also opened automatically when available.

## Privacy and failures

Case seeds and report content stay in the private case/evidence directory outside Git. Audit entries retain the existing hash/reference policy and do not contain raw identifiers. The desktop failure log is `%LOCALAPPDATA%\LumirOSINTLab\logs\desktop.jsonl`; it stores timestamp, component, and exception class, but omits raw input and traceback text from the user-facing message.

Report and case-folder actions validate that the selected path is inside the expected case directory before passing it to Windows. A backend failure produces a short Polish message and does not bypass the policy, registry, audit, evidence, or receipt controls.

Etap 14 adds `OTWÓRZ GRAF`. It opens only the generated `graph/graph_viewer.html` below the selected private case directory. The viewer is dependency-free and offline; clicking a node or edge shows its type, confidence, status and evidence references.

## Delivery boundary

IMPLEMENTED: Tkinter form, optional inputs, default-off PASSIVE_WEB control, automatic private case creation, progress states, guarded execution, JSON/HTML report generation, summary, validated report/folder opening, repository-relative launcher, and Desktop shortcut script.

PLANNED: cancellation, resumable/background jobs, richer case history, redacted export, encryption, and signed distribution packaging.

NOT IMPLEMENTED: PDF, installer/updater, service mode, cloud synchronization, automatic identity merging, AI verdicts, or collector-specific execution outside the Orchestrator.
