#!/usr/bin/env python3

import sys
import re
import shutil
from datetime import datetime
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

safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("_") or "scan"
timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
android_download = Path("/storage/emulated/0/Download/LumirShield")
saved_reports = []
try:
    android_download.mkdir(parents=True, exist_ok=True)
    for source, suffix in ((html_report, "html"), (pdf_report, "pdf"), (json_report, "json")):
        destination = android_download / f"Lumir_SHIELD_{safe_target}_{timestamp}.{suffix}"
        shutil.copy2(source, destination)
        saved_reports.append(str(destination))
except OSError:
    saved_reports = [str(Path(path).resolve()) for path in (html_report, pdf_report, json_report)]

failed = [module for module in result["modules"] if module.get("scan_status") in {"error", "timeout", "unavailable"}]
print(f"Zakończono moduły: {len(result['modules'])}. Wynik: {result['risk_score']['score']}/100 ({result['risk_score']['risk']}).")
if failed:
    print(f"Uwaga: {len(failed)} moduł(y) zakończyły się częściowo lub były niedostępne.")

print("\nRaport zapisano jako:")
print(f" - {json_report}")
print(f" - {html_report}")
print(f" - {pdf_report}")
print("\nPliki do udostępnienia:")
for path in saved_reports:
    print(f" - {path}")
