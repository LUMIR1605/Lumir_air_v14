#!/usr/bin/env python3
"""Command-line entry point for consent-based Lumir SHIELD self-scans."""

import json
import sys

from core.compat import configure_stdio
from shield.html_report import build as build_html
from shield.input_validation import InputValidationError, normalize
from shield.multi_scan import run
from shield.pdf_report import build as build_pdf
from shield.report_builder import build
from shield.report_paths import report_paths


configure_stdio()

if len(sys.argv) not in {2, 3} or (len(sys.argv) == 3 and sys.argv[2] != "--consent-owner"):
    print("Użycie: python shield.py <email|telefon|nick> --consent-owner")
    raise SystemExit(1)

try:
    normalized = normalize(sys.argv[1])
except InputValidationError as error:
    print(f"Błąd: {error}")
    raise SystemExit(2)

scan_type, target = normalized.scan_type, normalized.value
consent = "--consent-owner" in sys.argv
print(f"Lumir SHIELD: skanowanie typu {scan_type} dla: {target}")
result = run(scan_type, target, consent_declared=consent)
paths = report_paths(scan_type, target)
json_report = build(result, str(paths["json"]))
with open(json_report, encoding="utf-8") as report_file:
    presentation_report = json.load(report_file)
html_report = build_html(presentation_report, str(paths["html"]))
pdf_report = build_pdf(presentation_report, str(paths["pdf"]))

assessment, coverage = result["security_assessment"], result["coverage"]
print(f"Lumir SHIELD — zakończono skan {scan_type}")
print(f"Wynik techniczny: {assessment['score']}/100" if assessment["score"] is not None else "Wynik techniczny: niedostępny")
print(f"Pokrycie modułów: {coverage['module_weighted_percent']}%")
print(f"Pokrycie kontroli: {coverage['control_weighted_percent']}%")
print(f"Wiarygodność oceny: {result['assessment_reliability']}")
print(f"Werdykt: {assessment['public_verdict']}")
print("\nRaporty zapisano lokalnie:")
for path in (json_report, html_report, pdf_report):
    print(f" - {path}")
