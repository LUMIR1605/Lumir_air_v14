"""Windows desktop application for consent-based Lumir SHIELD self-scans."""

from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from shield.input_validation import InputValidationError, normalize
from shield.report_paths import ensure_reports_directory, report_paths, reports_directory


APP_DIR = Path(__file__).resolve().parent
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
TYPE_LABELS = {
    "Automatycznie": "auto",
    "Adres e-mail": "email",
    "Numer telefonu": "phone",
    "Nick / username": "username",
}


class LumirShieldApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Lumir SHIELD — własne dane")
        self.minsize(680, 530)
        self.configure(bg="#06111f")
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.target = tk.StringVar()
        self.selected_type = tk.StringVar(value="Automatycznie")
        self.consent = tk.BooleanVar()
        self.status = tk.StringVar(value="READY — wybierz dane do sprawdzenia")
        self._build()
        self.after(100, self._drain_events)

    def _build(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Panel.TFrame", background="#0a1a2d")
        style.configure("Title.TLabel", background="#0a1a2d", foreground="#f3f8ff", font=("Segoe UI", 25, "bold"))
        style.configure("Text.TLabel", background="#0a1a2d", foreground="#c3d5e8", font=("Segoe UI", 10))
        style.configure("Status.TLabel", background="#0a1a2d", foreground="#50d8ff", font=("Segoe UI", 10, "bold"))
        style.configure("Scan.TButton", font=("Segoe UI", 12, "bold"), padding=(20, 12))
        style.configure("Shield.Horizontal.TProgressbar", troughcolor="#0d2942", background="#00b8f5", lightcolor="#49e5ff", bordercolor="#0d2942")

        panel = ttk.Frame(self, style="Panel.TFrame", padding=32)
        panel.pack(fill="both", expand=True, padx=28, pady=28)
        ttk.Label(panel, text="LUMIR SHIELD", style="Title.TLabel").pack(anchor="w")
        ttk.Label(panel, text="Bezpieczna kontrola własnych danych  |  RC6", style="Text.TLabel").pack(anchor="w", pady=(4, 2))
        ttk.Label(panel, text="Publiczne źródła i lokalne moduły — bez dostępu do prywatnych kont.", style="Text.TLabel").pack(anchor="w", pady=(0, 22))

        ttk.Label(panel, text="Typ danych", style="Text.TLabel").pack(anchor="w")
        self.type_picker = ttk.Combobox(panel, textvariable=self.selected_type, values=list(TYPE_LABELS), state="readonly", font=("Segoe UI", 11))
        self.type_picker.pack(fill="x", pady=(6, 15), ipady=5)
        ttk.Label(panel, text="Adres e-mail, numer telefonu lub nick", style="Text.TLabel").pack(anchor="w")
        self.entry = ttk.Entry(panel, textvariable=self.target, font=("Segoe UI", 13))
        self.entry.pack(fill="x", pady=(7, 14), ipady=8)
        self.entry.focus_set()
        ttk.Checkbutton(panel, text="Potwierdzam, że skanuję wyłącznie własne dane lub dane, do których mam uprawnienie.", variable=self.consent).pack(anchor="w", pady=(0, 18))
        ttk.Label(panel, text=f"Raporty lokalnie: {reports_directory()}", style="Text.TLabel", wraplength=600).pack(anchor="w", pady=(0, 20))
        self.button = ttk.Button(panel, text="ROZPOCZNIJ SKAN", command=self._start, style="Scan.TButton")
        self.button.pack(anchor="w")
        self.progress = ttk.Progressbar(panel, style="Shield.Horizontal.TProgressbar", mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(28, 10))
        ttk.Label(panel, textvariable=self.status, style="Status.TLabel", wraplength=600).pack(anchor="w")

    def _start(self) -> None:
        if not self.consent.get():
            messagebox.showwarning("Wymagane potwierdzenie", "Potwierdź, że skanujesz własne dane lub dane, do których masz uprawnienie.")
            return
        try:
            normalized = normalize(self.target.get(), TYPE_LABELS[self.selected_type.get()])
        except InputValidationError as error:
            messagebox.showwarning("Sprawdź dane", str(error))
            return
        self.button.state(["disabled"])
        self.progress["value"] = 8
        self.status.set(f"Uruchamianie analizy: {normalized.scan_type}…")
        threading.Thread(target=self._run, args=(normalized.scan_type, normalized.value), daemon=True).start()

    def _run(self, scan_type: str, target: str) -> None:
        self.events.put(("progress", "Skanowanie publicznych i lokalnych źródeł…"))
        try:
            from shield.html_report import build as build_html
            from shield.multi_scan import run
            from shield.pdf_report import build as build_pdf
            from shield.report_builder import build

            ensure_reports_directory()
            result = run(scan_type, target, consent_declared=True)
            self.events.put(("generating", "Generowanie raportów…"))
            paths = report_paths(scan_type, target)
            build(result, str(paths["json"]))
            build_html(result, str(paths["html"]))
            build_pdf(result, str(paths["pdf"]))
        except OSError as error:
            self.events.put(("error", f"Nie udało się zapisać raportów lokalnie.\nFolder: {reports_directory()}\nPowód: {error}"))
            return
        except Exception as error:
            self.events.put(("error", f"Nie udało się zakończyć skanu: {type(error).__name__}. Spróbuj ponownie."))
            return
        self.events.put(("success", (paths, scan_type)))

    def _drain_events(self) -> None:
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "progress":
                    self.progress["value"] = 55
                    self.status.set(str(payload))
                elif event == "generating":
                    self.progress["value"] = 85
                    self.status.set(str(payload))
                elif event == "success":
                    paths, scan_type = payload
                    self.progress["value"] = 100
                    self.status.set(f"Gotowe. Raport {scan_type} zapisano lokalnie.")
                    self.button.state(["!disabled"])
                    self._open_reports(paths)
                elif event == "error":
                    self.progress["value"] = 0
                    self.status.set("Gotowe do ponowienia.")
                    self.button.state(["!disabled"])
                    messagebox.showerror("Lumir SHIELD", str(payload))
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    @staticmethod
    def _open_reports(paths: dict[str, Path]) -> None:
        try:
            os.startfile(paths["pdf"])  # type: ignore[attr-defined]
            os.startfile(paths["html"])  # type: ignore[attr-defined]
            os.startfile(reports_directory())  # type: ignore[attr-defined]
        except OSError:
            messagebox.showinfo("Raport gotowy", f"Raporty zapisano lokalnie w:\n{reports_directory()}")


if __name__ == "__main__":
    LumirShieldApp().mainloop()
