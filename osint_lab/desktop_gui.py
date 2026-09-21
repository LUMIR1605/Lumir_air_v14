"""Tkinter Windows desktop UI for the OSINT LAB MVP."""

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from osint_lab.account_audit import (
    AccountAuditAuthorizationError,
    AccountAuditRun,
    AccountAuditStatus,
    AccountReviewStatus,
    DependencyStatus,
)
from osint_lab.application import build_application
from osint_lab.desktop import (
    DesktopAnalysisError,
    DesktopAnalysisSummary,
    DesktopBackend,
    DesktopInput,
    DesktopValidationError,
)


class DesktopWindow:
    def __init__(self, root: tk.Tk, backend: DesktopBackend) -> None:
        self.root = root
        self.backend = backend
        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._running = False
        self._last_summary: DesktopAnalysisSummary | None = None
        self._account_running = False
        self._account_cancel = threading.Event()
        self._account_run: AccountAuditRun | None = None
        self._account_counts: dict[str, int] = {}

        root.title("LUMIR OSINT LAB")
        root.geometry("1120x820")
        root.minsize(900, 720)
        root.configure(background="#0d1726")
        self._configure_style()

        self.phone_var = tk.StringVar()
        self.email_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.domain_var = tk.StringVar()
        self.passive_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Gotowy do analizy.")
        self.summary_var = tk.StringVar(value="Wynik pojawi się po zakończeniu analizy.")
        self.audit_email_var = tk.StringVar()
        self.audit_authorized_var = tk.BooleanVar(value=False)
        self.audit_privacy_var = tk.BooleanVar(value=False)
        self.audit_show_not_found_var = tk.BooleanVar(value=False)
        self.audit_status_var = tk.StringVar(value="Sprawdzanie lokalnego silnika Account Audit...")
        self.audit_progress_var = tk.StringVar(value="Sprawdzono 0 / 0")
        self.audit_review_var = tk.StringVar(value=AccountReviewStatus.UNREVIEWED.value)
        self.audit_note_var = tk.StringVar()

        self._build()
        self.root.after(100, self._poll_events)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("App.TFrame", background="#0d1726")
        style.configure("Card.TFrame", background="#15243a")
        style.configure("Title.TLabel", background="#0d1726", foreground="#f5f8ff", font=("Segoe UI", 24, "bold"))
        style.configure("Subtitle.TLabel", background="#0d1726", foreground="#9fb1ca", font=("Segoe UI", 10))
        style.configure("Field.TLabel", background="#15243a", foreground="#dbe7f7", font=("Segoe UI", 10, "bold"))
        style.configure("Status.TLabel", background="#15243a", foreground="#7dd3fc", font=("Segoe UI", 11, "bold"))
        style.configure("Summary.TLabel", background="#15243a", foreground="#dbe7f7", font=("Segoe UI", 10))
        style.configure("TEntry", fieldbackground="#eef4fb", foreground="#101827", padding=8)
        style.configure("TCheckbutton", background="#15243a", foreground="#dbe7f7")
        style.map("TCheckbutton", background=[("active", "#15243a")], foreground=[("active", "#ffffff")])
        style.configure("Primary.TButton", font=("Segoe UI", 11, "bold"), padding=(16, 10), background="#2563eb", foreground="#ffffff")
        style.map("Primary.TButton", background=[("active", "#1d4ed8"), ("disabled", "#53657d")])
        style.configure("Secondary.TButton", font=("Segoe UI", 10), padding=(12, 8), background="#263a56", foreground="#ffffff")
        style.map("Secondary.TButton", background=[("active", "#334c6d"), ("disabled", "#53657d")])
        style.configure("Treeview", rowheight=26, fieldbackground="#eef4fb", foreground="#101827")
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build(self) -> None:
        outer = ttk.Frame(self.root, style="App.TFrame", padding=28)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="LUMIR OSINT LAB", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="Prywatna analiza lokalna i kontrolowane źródła publiczne",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(2, 20))

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)
        public_tab = ttk.Frame(notebook, style="App.TFrame", padding=8)
        account_tab = ttk.Frame(notebook, style="App.TFrame", padding=8)
        notebook.add(public_tab, text="PUBLIC OSINT")
        notebook.add(account_tab, text="AUDYT KONT")

        card = ttk.Frame(public_tab, style="Card.TFrame", padding=22)
        card.pack(fill="both", expand=True)
        card.columnconfigure(0, weight=1)
        self._field(card, "Telefon", self.phone_var, 0)
        self._field(card, "E-mail", self.email_var, 2)
        self._field(card, "Username / nick", self.username_var, 4)
        self._field(card, "Domena", self.domain_var, 6)

        checkbox = ttk.Checkbutton(
            card,
            text="Zezwól na publiczne zapytania PASSIVE_WEB",
            variable=self.passive_var,
        )
        checkbox.grid(row=8, column=0, sticky="w", pady=(14, 16))

        self.analyze_button = ttk.Button(
            card,
            text="ANALIZUJ",
            command=self._start_analysis,
            style="Primary.TButton",
        )
        self.analyze_button.grid(row=9, column=0, sticky="ew")

        ttk.Separator(card).grid(row=10, column=0, sticky="ew", pady=18)
        ttk.Label(card, textvariable=self.status_var, style="Status.TLabel").grid(row=11, column=0, sticky="w")
        ttk.Label(
            card,
            textvariable=self.summary_var,
            style="Summary.TLabel",
            justify="left",
            wraplength=610,
        ).grid(row=12, column=0, sticky="ew", pady=(8, 16))

        actions = ttk.Frame(card, style="Card.TFrame")
        actions.grid(row=13, column=0, sticky="ew")
        actions.columnconfigure((0, 1, 2), weight=1)
        self.report_button = ttk.Button(
            actions,
            text="OTWÓRZ RAPORT HTML",
            command=self._open_report,
            style="Secondary.TButton",
            state="disabled",
        )
        self.report_button.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.folder_button = ttk.Button(
            actions,
            text="OTWÓRZ FOLDER SPRAWY",
            command=self._open_folder,
            style="Secondary.TButton",
            state="disabled",
        )
        self.folder_button.grid(row=0, column=1, sticky="ew", padx=(6, 0))
        self.graph_button = ttk.Button(
            actions,
            text="OTWÓRZ GRAF",
            command=self._open_graph,
            style="Secondary.TButton",
            state="disabled",
        )
        self.graph_button.grid(row=0, column=2, sticky="ew", padx=(6, 0))
        self._build_account_audit(account_tab)

    def _build_account_audit(self, parent: ttk.Frame) -> None:
        card = ttk.Frame(parent, style="Card.TFrame", padding=18)
        card.pack(fill="both", expand=True)
        card.columnconfigure(0, weight=1)
        ttk.Label(card, text="ACCOUNT AUDIT / SELF-AUDIT", style="Field.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            card,
            text="Oddzielny audyt własnego lub wyraźnie autoryzowanego adresu. Nie jest uruchamiany przez PUBLIC OSINT.",
            style="Summary.TLabel",
            wraplength=980,
        ).grid(row=1, column=0, sticky="w", pady=(4, 10))
        ttk.Label(card, text="Email", style="Field.TLabel").grid(row=2, column=0, sticky="w")
        ttk.Entry(card, textvariable=self.audit_email_var).grid(row=3, column=0, sticky="ew", pady=(4, 8))
        ttk.Checkbutton(
            card,
            text="Potwierdzam, że kontroluję ten adres e-mail lub mam wyraźną zgodę właściciela na audyt kont.",
            variable=self.audit_authorized_var,
        ).grid(row=4, column=0, sticky="w")
        ttk.Checkbutton(
            card,
            text="Rozumiem, że audyt może ujawnić wskazany adres e-mail sprawdzanym usługom.",
            variable=self.audit_privacy_var,
        ).grid(row=5, column=0, sticky="w", pady=(4, 8))
        buttons = ttk.Frame(card, style="Card.TFrame")
        buttons.grid(row=6, column=0, sticky="ew")
        buttons.columnconfigure((0, 1, 2), weight=1)
        self.audit_start_button = ttk.Button(
            buttons, text="SPRAWDŹ KONTA", command=self._start_account_audit, style="Primary.TButton"
        )
        self.audit_start_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.audit_cancel_button = ttk.Button(
            buttons, text="ANULUJ AUDYT", command=self._cancel_account_audit,
            style="Secondary.TButton", state="disabled",
        )
        self.audit_cancel_button.grid(row=0, column=1, sticky="ew", padx=5)
        self.audit_report_button = ttk.Button(
            buttons, text="OTWÓRZ CHECKLISTĘ", command=self._open_account_report,
            style="Secondary.TButton", state="disabled",
        )
        self.audit_report_button.grid(row=0, column=2, sticky="ew", padx=(5, 0))
        ttk.Label(card, textvariable=self.audit_status_var, style="Status.TLabel").grid(row=7, column=0, sticky="w", pady=(10, 2))
        ttk.Label(card, textvariable=self.audit_progress_var, style="Summary.TLabel").grid(row=8, column=0, sticky="w")
        ttk.Checkbutton(
            card,
            text="Pokaż także serwisy, gdzie nie znaleziono konta",
            variable=self.audit_show_not_found_var,
            command=self._render_account_results,
        ).grid(row=9, column=0, sticky="w", pady=(8, 4))
        columns = ("service", "status", "confidence", "method", "notes", "decision")
        self.audit_tree = ttk.Treeview(card, columns=columns, show="headings", height=12)
        headings = {"service": "SERWIS", "status": "STATUS", "confidence": "PEWNOŚĆ",
                    "method": "METODA", "notes": "UWAGI", "decision": "DECYZJA"}
        widths = {"service": 150, "status": 105, "confidence": 90, "method": 120,
                  "notes": 390, "decision": 150}
        for name in columns:
            self.audit_tree.heading(name, text=headings[name])
            self.audit_tree.column(name, width=widths[name], minwidth=70, stretch=name == "notes")
        self.audit_tree.grid(row=10, column=0, sticky="nsew")
        card.rowconfigure(10, weight=1)
        review = ttk.Frame(card, style="Card.TFrame")
        review.grid(row=11, column=0, sticky="ew", pady=(8, 0))
        review.columnconfigure(1, weight=1)
        ttk.Label(review, text="Decyzja", style="Field.TLabel").grid(row=0, column=0, padx=(0, 6))
        ttk.Combobox(
            review, textvariable=self.audit_review_var,
            values=[item.value for item in AccountReviewStatus], state="readonly", width=20,
        ).grid(row=0, column=1, sticky="w")
        ttk.Label(review, text="Moja notatka", style="Field.TLabel").grid(row=0, column=2, padx=(14, 6))
        ttk.Entry(review, textvariable=self.audit_note_var).grid(row=0, column=3, sticky="ew")
        review.columnconfigure(3, weight=1)
        ttk.Button(review, text="ZAPISZ DECYZJĘ", command=self._save_account_review,
                   style="Secondary.TButton").grid(row=0, column=4, padx=(8, 0))
        self.root.after(10, self._refresh_account_diagnostic)

    @staticmethod
    def _field(parent: ttk.Frame, label: str, variable: tk.StringVar, row: int) -> None:
        ttk.Label(parent, text=label, style="Field.TLabel").grid(row=row, column=0, sticky="w", pady=(0, 5))
        ttk.Entry(parent, textvariable=variable).grid(row=row + 1, column=0, sticky="ew", pady=(0, 10))

    def _start_analysis(self) -> None:
        if self._running:
            return
        values = DesktopInput(
            phone=self.phone_var.get(),
            email=self.email_var.get(),
            username=self.username_var.get(),
            domain=self.domain_var.get(),
            allow_passive_web=self.passive_var.get(),
        )
        if not any((values.phone.strip(), values.email.strip(), values.username.strip(), values.domain.strip())):
            messagebox.showwarning("LUMIR OSINT LAB", "Nie podano żadnych danych.", parent=self.root)
            return
        self._running = True
        self._last_summary = None
        self.analyze_button.configure(state="disabled")
        self.report_button.configure(state="disabled")
        self.folder_button.configure(state="disabled")
        self.graph_button.configure(state="disabled")
        self.status_var.set("Przygotowanie...")
        self.summary_var.set("Analiza jest wykonywana przez kontrolowany pipeline.")
        worker = threading.Thread(target=self._analyze_worker, args=(values,), daemon=True)
        worker.start()

    def _analyze_worker(self, values: DesktopInput) -> None:
        try:
            result = self.backend.analyze(
                values,
                status_callback=lambda message: self._events.put(("status", message)),
            )
            self._events.put(("result", result))
        except DesktopValidationError as error:
            self._events.put(("validation_error", str(error)))
        except DesktopAnalysisError as error:
            self._events.put(("analysis_error", str(error)))
        except Exception as error:
            self.backend.record_error(error)
            self._events.put(("analysis_error", "Nie udało się uruchomić analizy."))

    def _refresh_account_diagnostic(self) -> None:
        worker = threading.Thread(target=self._account_diagnostic_worker, daemon=True)
        worker.start()

    def _account_diagnostic_worker(self) -> None:
        try:
            diagnostic = self.backend.account_audit_diagnostic()
        except DesktopAnalysisError as error:
            self._events.put(("account_diagnostic_error", str(error)))
            return
        self._events.put(("account_diagnostic", diagnostic))

    def _apply_account_diagnostic(self, diagnostic: object) -> None:
        if diagnostic.status is DependencyStatus.INSTALLED:
            self.audit_status_var.set(
                f"Holehe {diagnostic.provider_version}: INSTALLED; moduły: "
                f"{diagnostic.provider_modules_detected}; Python {diagnostic.python_version}: "
                f"{diagnostic.python_interpreter}"
            )
            self.audit_start_button.configure(state="normal")
        else:
            self.audit_status_var.set(
                f"Account Audit engine not installed ({diagnostic.reason}). "
                "Uruchom INSTALL_ACCOUNT_AUDIT.cmd ręcznie, jeśli chcesz go zainstalować."
            )
            self.audit_start_button.configure(state="disabled")

    def _start_account_audit(self) -> None:
        if self._account_running:
            return
        if not self.audit_authorized_var.get():
            messagebox.showwarning("AUDYT KONT", "Wymagane jest potwierdzenie SELF-AUDIT.", parent=self.root)
            return
        if not self.audit_privacy_var.get():
            messagebox.showwarning(
                "AUDYT KONT",
                "Zaakceptuj informację, że adres może zostać ujawniony sprawdzanym usługom.",
                parent=self.root,
            )
            return
        self._account_running = True
        self._account_cancel = threading.Event()
        self._account_run = None
        self._account_counts = {}
        self.audit_start_button.configure(state="disabled")
        self.audit_cancel_button.configure(state="normal")
        self.audit_report_button.configure(state="disabled")
        self.audit_status_var.set("Uruchamianie kontrolowanego audytu kont...")
        self.audit_progress_var.set("Sprawdzono 0 / 0")
        email = self.audit_email_var.get()
        authorized = self.audit_authorized_var.get()
        privacy_accepted = self.audit_privacy_var.get()
        worker = threading.Thread(
            target=self._account_audit_worker,
            args=(email, authorized, privacy_accepted),
            daemon=True,
        )
        worker.start()

    def _account_audit_worker(self, email: str, authorized: bool, privacy_accepted: bool) -> None:
        try:
            result = self.backend.run_account_audit(
                email=email,
                authorization_confirmed=authorized,
                privacy_disclosure_accepted=privacy_accepted,
                progress_callback=lambda done, total, item: self._events.put(
                    ("account_progress", (done, total, item))
                ),
                cancel_event=self._account_cancel,
            )
            self._events.put(("account_result", result))
        except AccountAuditAuthorizationError as error:
            self._events.put(("account_error", str(error)))
        except (DesktopValidationError, DesktopAnalysisError) as error:
            self._events.put(("account_error", str(error)))
        except Exception as error:
            self.backend.record_error(error)
            self._events.put(("account_error", "Nie udało się uruchomić audytu kont."))

    def _cancel_account_audit(self) -> None:
        if self._account_running:
            self._account_cancel.set()
            self.audit_status_var.set("Anulowanie po bezpiecznym zatrzymaniu procesu...")

    def _account_progress(self, done: int, total: int, item: object) -> None:
        status = item.status.value
        self._account_counts[status] = self._account_counts.get(status, 0) + 1
        self.audit_status_var.set(f"Aktualnie: {item.service_name} ({status})")
        self.audit_progress_var.set(
            f"Sprawdzono {done} / {total}    FOUND: {self._account_counts.get('FOUND', 0)}    "
            f"UNKNOWN: {self._account_counts.get('UNKNOWN', 0)}    "
            f"RATE LIMITED: {self._account_counts.get('RATE_LIMITED', 0)}"
        )

    def _finish_account_audit(self, run: AccountAuditRun) -> None:
        self._account_running = False
        self._account_run = run
        self.audit_cancel_button.configure(state="disabled")
        self.audit_start_button.configure(state="normal")
        if run.report_paths.get("html"):
            self.audit_report_button.configure(state="normal")
        summary = run.summary()
        self.audit_status_var.set(f"Audyt kont: {run.status}")
        self.audit_progress_var.set(
            f"Sprawdzono {summary['SERVICES_CHECKED']} usług    FOUND: {summary['FOUND']}    "
            f"NOT_FOUND: {summary['NOT_FOUND']}    UNKNOWN: {summary['UNKNOWN']}    "
            f"RATE LIMITED: {summary['RATE_LIMITED']}    ERROR: {summary['ERROR']}"
        )
        self._render_account_results()

    def _render_account_results(self) -> None:
        if not hasattr(self, "audit_tree"):
            return
        self.audit_tree.delete(*self.audit_tree.get_children())
        if self._account_run is None:
            return
        show_not_found = self.audit_show_not_found_var.get()
        for item in self._account_run.results:
            if item.status is AccountAuditStatus.NOT_FOUND and not show_not_found:
                continue
            recovery = ""
            if item.recovery_email_masked:
                recovery += f" recovery e-mail: {item.recovery_email_masked}"
            if item.recovery_phone_masked:
                recovery += f" recovery phone: {item.recovery_phone_masked}"
            self.audit_tree.insert(
                "", "end", iid=item.service_id,
                values=(item.service_name, item.status.value, item.confidence.value,
                        item.detection_method.value, item.notes + recovery, item.review_status.value),
            )

    def _save_account_review(self) -> None:
        selection = self.audit_tree.selection()
        if not selection or self._account_run is None:
            messagebox.showwarning("AUDYT KONT", "Wybierz serwis z tabeli.", parent=self.root)
            return
        service_id = selection[0]
        try:
            status = AccountReviewStatus(self.audit_review_var.get())
            self.backend.record_account_review(
                case_id=self._account_run.case_id,
                service_id=service_id,
                status=status,
                note=self.audit_note_var.get(),
            )
        except (ValueError, OSError, DesktopAnalysisError) as error:
            messagebox.showerror("AUDYT KONT", str(error), parent=self.root)
            return
        self.audit_tree.set(service_id, "decision", status.value)
        self.audit_status_var.set("Zapisano lokalną decyzję i zachowano historię.")

    def _open_account_report(self) -> None:
        if self._account_run is None:
            return
        try:
            self.backend.open_account_audit_report(self._account_run)
        except (DesktopValidationError, OSError) as error:
            messagebox.showwarning("AUDYT KONT", str(error), parent=self.root)

    def _poll_events(self) -> None:
        try:
            while True:
                event, payload = self._events.get_nowait()
                if event == "status":
                    self.status_var.set(str(payload))
                elif event == "result":
                    self._finish_success(payload)
                elif event == "validation_error":
                    self._finish_error(str(payload), warning=True)
                elif event == "analysis_error":
                    self._finish_error(str(payload), warning=False)
                elif event == "account_progress":
                    done, total, item = payload
                    self._account_progress(done, total, item)
                elif event == "account_diagnostic":
                    self._apply_account_diagnostic(payload)
                elif event == "account_diagnostic_error":
                    self.audit_status_var.set(str(payload))
                    self.audit_start_button.configure(state="disabled")
                elif event == "account_result":
                    self._finish_account_audit(payload)
                elif event == "account_error":
                    self._account_running = False
                    self.audit_cancel_button.configure(state="disabled")
                    self.audit_start_button.configure(state="normal")
                    self.audit_status_var.set(str(payload))
                    messagebox.showerror("AUDYT KONT", str(payload), parent=self.root)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)

    def _finish_success(self, summary: DesktopAnalysisSummary) -> None:
        self._running = False
        self._last_summary = summary
        self.analyze_button.configure(state="normal")
        self.folder_button.configure(state="normal")
        if summary.report_html_path:
            self.report_button.configure(state="normal")
        if summary.graph_viewer_path:
            self.graph_button.configure(state="normal")
        self.status_var.set("Gotowe.")
        self.summary_var.set(
            f"Status sprawy: {summary.overall_status}\n"
            f"POSSIBLE: {summary.possible_count}    UNKNOWN: {summary.unknown_count}    "
            f"NOT_FOUND: {summary.not_found_count}\n"
            f"Contradictions: {summary.contradiction_count}\n"
            f"Public matches verified: {summary.public_matches_verified}    "
            f"Rejected false positives: {summary.rejected_false_positives}\n"
            f"Target pages checked: {summary.target_pages_checked}\n"
            f"Discovery providers: {summary.discovery_providers}    "
            f"Queries: {summary.discovery_queries}    Candidates: {summary.discovery_candidates}\n"
            f"Discovery requests: {summary.discovery_requests}    "
            f"Brave: {summary.brave_status}\n"
            f"Sources executed: {summary.sources_executed}/{summary.sources_enabled}\n"
            f"Initial collectors: {summary.initial_collectors}    "
            f"Automatic pivots executed: {summary.automatic_pivots_executed}\n"
            f"Hop 1: {summary.hop_1_count}    Hop 2: {summary.hop_2_count}\n"
            f"Independent evidence: {summary.independent_evidence}    "
            f"Entities discovered: {summary.entities_discovered}    New relations: {summary.new_relations}\n"
            f"Useful pivots: {summary.useful_pivots}    "
            f"Blocked/Unavailable sources: {summary.blocked_unavailable_sources}\n"
            f"Stop reason: {summary.stop_reason}\n"
            f"Case ID: {summary.case_id}"
        )
        if summary.report_html_path:
            try:
                self.backend.open_report(summary)
            except (DesktopValidationError, OSError):
                messagebox.showwarning(
                    "LUMIR OSINT LAB",
                    "Raport został wygenerowany, ale nie udało się go automatycznie otworzyć.",
                    parent=self.root,
                )
        elif summary.overall_status == "PARTIAL":
            messagebox.showwarning(
                "LUMIR OSINT LAB",
                "Raport został wygenerowany częściowo.",
                parent=self.root,
            )
        if summary.overall_status == "DENIED" and not self.passive_var.get():
            messagebox.showinfo(
                "LUMIR OSINT LAB",
                "PASSIVE_WEB jest wyłączone.",
                parent=self.root,
            )

    def _finish_error(self, message: str, *, warning: bool) -> None:
        self._running = False
        self.analyze_button.configure(state="normal")
        self.status_var.set("Błąd.")
        self.summary_var.set(message)
        if warning:
            messagebox.showwarning("LUMIR OSINT LAB", message, parent=self.root)
        else:
            messagebox.showerror("LUMIR OSINT LAB", message, parent=self.root)

    def _open_report(self) -> None:
        try:
            self.backend.open_report(self._last_summary)
        except (DesktopValidationError, OSError) as error:
            messagebox.showwarning("LUMIR OSINT LAB", str(error), parent=self.root)

    def _open_folder(self) -> None:
        try:
            self.backend.open_case_folder(self._last_summary)
        except (DesktopValidationError, OSError) as error:
            messagebox.showwarning("LUMIR OSINT LAB", str(error), parent=self.root)

    def _open_graph(self) -> None:
        try:
            self.backend.open_graph(self._last_summary)
        except (DesktopValidationError, OSError) as error:
            messagebox.showwarning("LUMIR OSINT LAB", str(error), parent=self.root)


def main() -> int:
    root = tk.Tk()
    backend = DesktopBackend(application=build_application())
    DesktopWindow(root, backend)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
