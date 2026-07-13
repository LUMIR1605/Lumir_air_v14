#!/usr/bin/env python3

import sys

from core.compat import configure_stdio
from shield.core import detect_type
from shield.multi_scan import run
from shield.report_builder import build
from shield.html_report import build as build_html

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

failed = [module for module in result["modules"] if module.get("scan_status") in {"error", "timeout", "unavailable"}]
print(f"Zakończono moduły: {len(result['modules'])}. Wynik: {result['risk_score']['score']}/100 ({result['risk_score']['risk']}).")
if failed:
    print(f"Uwaga: {len(failed)} moduł(y) zakończyły się częściowo lub były niedostępne.")

print("\nRaport zapisano jako:")
print(f" - {json_report}")
print(f" - {html_report}")
