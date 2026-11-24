"""Generate explicitly synthetic reports, using no scanners or network."""
import argparse
from pathlib import Path
from shield.truth import base_report, module_placeholder, assessment
from shield.html_report import build as html
from shield.pdf_report import build as pdf
from shield.report_builder import build as json_report

def generate(output):
    output.mkdir(parents=True, exist_ok=True)
    for kind in ("email", "phone", "username"):
        report = base_report(kind, "DEMO — dane syntetyczne", True)
        report["scan_mode"] = "mocked"
        module = module_placeholder("account_exposure_scan" if kind == "email" else kind+"_scan", "unavailable", "DEMO: źródła nie zostały uruchomione", 100)
        if kind == "email":
            module.update(scan_status="partial", services={"checked_count":1,"probable_count":2,"confirmed_count":0,"results":[{"service_name":"synthetic-a.example","status":"probable"},{"service_name":"synthetic-b.example","status":"probable"}]})
        report["modules"] = [module]
        report.update(assessment(report["modules"], kind))
        report["security_assessment"]["public_verdict"] = "DEMO — wyłącznie dane syntetyczne. Nie wykonano rzeczywistego skanu."
        html(report, str(output/(kind+".html")))
        pdf(report, str(output/(kind+".pdf")))
        json_report(report, str(output/(kind+".json")))

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    generate(parser.parse_args().output)
