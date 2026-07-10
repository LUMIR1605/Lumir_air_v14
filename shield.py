#!/usr/bin/env python3

import sys
from pprint import pprint

from shield.core import detect_type
from shield.multi_scan import run
from shield.report_builder import build
from shield.html_report import build as build_html

if len(sys.argv) != 2:
    print("Użycie:")
    print("python shield.py <email|telefon|url|domena|nick>")
    raise SystemExit(1)

target = sys.argv[1]

scan_type = detect_type(target)

result = run(scan_type, target)

build(result)
build_html(result)

print("\n🛡 LUMIR SHIELD\n")
pprint(result)

print("\nRaport zapisano jako:")
print(" • shield_report.json")
print(" • shield_report.html")
