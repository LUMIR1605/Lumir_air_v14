"""Tkinter Windows desktop UI for the OSINT LAB MVP."""

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

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

        root.title("LUMIR OSINT LAB")
        root.geometry("760x760")
        root.minsize(680, 700)
        root.configure(background="#0d1726")
        self._configure_style()

        self.phone_var = tk.StringVar()
        self.email_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.domain_var = tk.StringVar()
        self.passive_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Gotowy do analizy.")
        self.summary_var = tk.StringVar(value="Wynik pojawi się po zakończeniu analizy.")

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

    def _build(self) -> None:
        outer = ttk.Frame(self.root, style="App.TFrame", padding=28)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="LUMIR OSINT LAB", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="Prywatna analiza lokalna i kontrolowane źródła publiczne",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(2, 20))

        card = ttk.Frame(outer, style="Card.TFrame", padding=22)
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
