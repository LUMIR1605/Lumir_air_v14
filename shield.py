#!/usr/bin/env python3

import sys
import shutil
from pathlib import Path

from core.compat import configure_stdio
from shield.core import detect_type
from shield.multi_scan import run
from shield.report_builder import build
from shield.html_report import build as build_html
from shield.pdf_report import build as build_pdf

configure_stdio()

if len(sys.argv) != 2:
    print("Uzycie:")
    print("python shield.py <email|telefon|url|domena|nick>")
    raise SystemExit(1)

target = sys.argv[1].strip()
if not target:
    print("Błąd: podaj cel skanowania.")
    raise SystemExit(2)

scan_type = detect_type(target)
print(f"Lumír SHIELD: skanowanie typu {scan_type} dla: {target}")

result = run(scan_type, target)

json_report = build(result)
html_report = build_html(result)
pdf_report = build_pdf(result)

android_download = Path("/storage/emulated/0/Download/LumirShield")
android_reports = []
storage_error = None
android_storage = Path("/storage/emulated/0")
if not android_storage.exists():
    storage_error = "Nie wykryto /storage/emulated/0. Na Androidzie uruchom w Termux: termux-setup-storage"
else:
    try:
        android_download.mkdir(parents=True, exist_ok=True)
        for source in (html_report, json_report, pdf_report):
            source_path = Path(source)
            if source_path.is_file():
                destination = android_download / source_path.name
                shutil.copy2(source_path, destination)
                android_reports.append(str(destination))
    except PermissionError:
        storage_error = "Brak dostepu do pamieci urzadzenia. W Termux uruchom: termux-setup-storage, zaakceptuj uprawnienie i uruchom skan ponownie."
    except OSError as error:
        storage_error = f"Nie mozna zapisac raportu w /storage/emulated/0/Download/LumirShield: {error}"

failed = [module for module in result["modules"] if module.get("scan_status") in {"error", "timeout", "unavailable"}]
print(f"Zakończono moduły: {len(result['modules'])}. Wynik: {result['risk_score']['score']}/100 ({result['risk_score']['risk']}).")
if failed:
    print(f"Uwaga: {len(failed)} moduł(y) zakończyły się częściowo lub były niedostępne.")

print("\nRaport zapisano jako:")
print(f" - {json_report}")
print(f" - {html_report}")
print(f" - {pdf_report}")
if storage_error:
    print(f"\n{storage_error}")
else:
    print("\nRaport zapisano również do:")
    print("/storage/emulated/0/Download/LumirShield/")
    for path in android_reports:
        print(f" - {path}")
