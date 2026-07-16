from html import unescape
from pathlib import Path
from tempfile import TemporaryDirectory

from shield.html_report import build as build_html
from shield.pdf_report import build as build_pdf


TITLE = "Sprawd\u017a, co internet nadal pami\u0119ta o Tobie"
SUBTITLE = "Wykryte us\u0142ugi s\u0105 sygna\u0142em technicznym, a nie potwierdzeniem istnienia konta."


def _module(name, *, status="completed", score=100, risk="low", **values):
    module = {
        "module": name,
        "scan_status": status,
        "score": score,
        "risk": risk,
        "score_basis": [],
        "findings": [],
    }
    module.update(values)
    return module


def _report(services, account_status="partial"):
    account = _module("account_exposure_scan", status=account_status, score=None, risk="unknown")
    return {
        "target": "test@example.com",
        "risk": "low",
        "risk_score": {"score": 84, "risk": "LOW"},
        "modules": [
            _module("email_scan", valid_format=True, mx_records=["mx.example.com"], spf="v=spf1", dmarc="p=none", dkim=True),
            _module("breach_scan", breaches_found=0),
            account,
            _module("domain_scan", exists=True, https=True, dns={}),
        ],
        "services": services,
        "action_plan": {"now": [], "today": [], "later": []},
        "executive_summary": ["Wynik testowy."],
        "coverage": {"module_weighted_percent": 85, "control_weighted_percent": 80, "missing_modules": []},
        "assessment_reliability": "high",
    }


def _services(*names, checked=1):
    return {
        "planned_count": 1,
        "attempted_count": 1,
        "checked_count": checked,
        "confirmed_count": 0,
        "probable_count": len(names),
        "not_found_count": 1 if checked and not names else 0,
        "not_checked_count": 0 if checked else 1,
        "results": [{"service_name": name, "status": "probable"} for name in names],
    }


def _html(report):
    with TemporaryDirectory() as directory:
        path = Path(directory) / "report.html"
        build_html(report, str(path))
        return unescape(path.read_text(encoding="utf-8"))


def test_html_renders_probable_service_cards_in_polish():
    html = _html(_report(_services("Spotify", "Office365")))

    assert TITLE in html
    assert SUBTITLE in html
    assert "Spotify" in html and "Office365" in html
    assert "Prawdopodobne powi\u0105zanie" in html
    assert "probable" not in html.lower()
    assert "To nie jest potwierdzenie istnienia konta." in html


def test_html_renders_empty_completed_result_without_claiming_no_accounts():
    html = _html(_report(_services()))

    assert "W tym sprawdzeniu nie wykryto prawdopodobnych us\u0142ug." in html
    assert "Nie oznacza to, \u017ce \u017cadne konta nie istniej\u0105." in html


def test_html_renders_unavailable_account_discovery_honestly():
    html = _html(_report(_services(checked=0), account_status="unavailable"))

    assert "Nie uda\u0142o si\u0119 sprawdzi\u0107 powi\u0105zanych us\u0142ug w tym skanie." in html


def test_pdf_renders_four_pages_with_polish_account_discovery_section():
    report = _report(_services("Spotify", "Office365", "Adobe"))
    with TemporaryDirectory() as directory:
        path = Path(directory) / "report.pdf"
        build_pdf(report, str(path))

        content = path.read_bytes()
        assert content.startswith(b"%PDF")
        assert b"/Count 4" in content
        assert len(content) > 10_000
