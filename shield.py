#!/usr/bin/env python3

import sys
from pprint import pprint

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

target = sys.argv[1]
scan_type = detect_type(target)

result = run(scan_type, target)

json_report = build(result)
html_report = build_html(result)

print("\nLUMIR SHIELD\n")
pprint(result)

print("\nRaport zapisano jako:")
print(f" - {json_report}")
print(f" - {html_report}")
