"""Professional, type-aware PDF report without changing the Truth Engine."""

from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path

import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


TYPE_NAMES = {"email": "adres e-mail", "phone": "numer telefonu", "username": "nick / username"}
STATUS_NAMES = {"completed": "potwierdzone w zakresie źródła", "partial": "częściowo sprawdzone", "unavailable": "niedostępne", "blocked": "zablokowane", "timeout": "przekroczony czas", "error": "błąd źródła", "not_applicable": "nie dotyczy"}
NAVY, PANEL, CYAN, TEXT, MUTED, AMBER = (colors.HexColor(value) for value in ("#06111F", "#0A1A2D", "#50D8FF", "#F3F8FF", "#B9CADB", "#FFD36A"))


def _register_fonts():
    bundled = Path(reportlab.__file__).resolve().parent / "fonts"
    options = [
        (Path("C:/Windows/Fonts/segoeui.ttf"), Path("C:/Windows/Fonts/segoeuib.ttf")),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")),
        (bundled / "Vera.ttf", bundled / "VeraBd.ttf"),
    ]
    regular, bold = next((pair for pair in options if pair[0].is_file() and pair[1].is_file()), options[-1])
    pdfmetrics.registerFont(TTFont("LumirRegular", str(regular)))
    pdfmetrics.registerFont(TTFont("LumirBold", str(bold)))


def _safe(value):
    if value in (None, "", [], {}):
        return "Brak danych"
    if isinstance(value, bool):
        return "Tak" if value else "Nie"
    if isinstance(value, (list, tuple)):
        return ", ".join(_safe(item) for item in value)
    return str(value)


def _details(report):
    modules = {item.get("module"): item for item in report.get("modules", []) if isinstance(item, dict)}
    if report.get("scan_type") == "email":
        email, breach, accounts = modules.get("email_scan", {}), modules.get("breach_scan", {}), modules.get("account_exposure_scan", {})
        return [("Format adresu", "Potwierdzony" if email.get("valid_format") else "Niepotwierdzony"), ("Domena", _safe(email.get("domain"))), ("MX", _safe(email.get("mx_records"))), ("SPF", _safe(email.get("spf"))), ("DKIM", _safe(email.get("dkim"))), ("DMARC", _safe(email.get("dmarc"))), ("Wpisy w wyciekach", _safe(breach.get("breaches_found"))), ("Usługi powiązane", f"{_safe((accounts.get('services') or {}).get('probable_count'))} prawdopodobnych; własność niepotwierdzona")]
    if report.get("scan_type") == "phone":
        phone = modules.get("phone_scan", {})
        return [("Format numeru", "Potwierdzony" if phone.get("valid") else "Niepotwierdzony"), ("Format międzynarodowy", _safe(phone.get("international"))), ("Kraj / obszar", _safe(phone.get("country"))), ("Operator", _safe(phone.get("operator"))), ("Własność numeru", "Niepotwierdzona — aplikacja nie identyfikuje osoby.")]
    username = modules.get("username_scan", {})
    profile = username.get("profile") or {}
    return [("Format nicku", "Potwierdzony"), ("Platforma", _safe(profile.get("platform"))), ("Publiczny profil", _safe(profile.get("url"))), ("Typ konta", _safe(profile.get("account_type"))), ("Publiczne repozytoria", _safe(profile.get("public_repos"))), ("Własność profilu", "Niepotwierdzona — zgodność nicku nie dowodzi tożsamości.")]


def _paragraph(text, style):
    return Paragraph(escape(_safe(text)).replace("\n", "<br/>"), style)


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
    canvas.setFillColor(MUTED)
    canvas.setFont("LumirRegular", 8)
    canvas.drawString(18 * mm, 11 * mm, "Lumir SHIELD · raport własnych danych · bez dostępu do prywatnych kont")
    canvas.drawRightString(A4[0] - 18 * mm, 11 * mm, f"Strona {doc.page}")
    canvas.restoreState()


def build(report, outfile="shield_report.pdf"):
    _register_fonts()
    styles = getSampleStyleSheet()
    title = ParagraphStyle("title", parent=styles["Title"], fontName="LumirBold", fontSize=24, leading=28, textColor=CYAN, spaceAfter=8)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontName="LumirBold", fontSize=14, leading=18, textColor=CYAN, spaceBefore=14, spaceAfter=8)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontName="LumirRegular", fontSize=9.5, leading=13, textColor=TEXT)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, leading=11, textColor=MUTED)
    doc = SimpleDocTemplate(outfile, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=22 * mm)
    assessment, coverage = report.get("security_assessment") or {}, report.get("coverage") or {}
    flow = [Paragraph("LUMIR SHIELD", title), Paragraph("RAPORT BEZPIECZNEJ KONTROLI WŁASNYCH DANYCH", small), Spacer(1, 7 * mm)]
    summary_rows = [
        ["Typ danych", TYPE_NAMES.get(report.get("scan_type"), _safe(report.get("scan_type")))],
        ["Cel", _safe(report.get("target"))], ["Data", datetime.now().strftime("%d.%m.%Y, %H:%M")],
        ["Zgoda", "Potwierdzona" if (report.get("consent") or {}).get("declared") else "Brak — analiza zablokowana"],
        ["Wynik techniczny", f"{_safe(assessment.get('score'))} / 100"],
        ["Pokrycie modułów", f"{_safe(coverage.get('module_weighted_percent'))}%"],
        ["Wiarygodność", _safe(report.get("assessment_reliability"))],
    ]
    summary = Table([[ _paragraph(label, small), _paragraph(value, body)] for label, value in summary_rows], colWidths=[48 * mm, 124 * mm])
    summary.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PANEL), ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#1B466B")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    flow.extend([summary, Spacer(1, 5 * mm), Paragraph(_safe(assessment.get("public_verdict")), ParagraphStyle("notice", parent=body, textColor=AMBER))])
    flow.append(Paragraph("Wyniki dla wybranego typu danych", h2))
    details = Table([[ _paragraph(label, small), _paragraph(value, body)] for label, value in _details(report)], colWidths=[55 * mm, 117 * mm])
    details.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PANEL), ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#1B466B")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    flow.append(details)
    flow.append(Paragraph("Moduły, źródła i pewność", h2))
    for module in report.get("modules", []):
        if not isinstance(module, dict):
            continue
        source_text = "; ".join(f"{source.get('source_name', source.get('source_id'))}: {STATUS_NAMES.get(source.get('status'), source.get('status'))}; pewność {source.get('confidence', 'brak')}" for source in module.get("sources", [])) or "Brak wykonanego źródła."
        findings = "; ".join(_safe(item) for item in (module.get("findings") or [module.get("error_reason") or "Brak dodatkowych ustaleń."]))
        section = [Paragraph(escape(str(module.get("module"))), ParagraphStyle("module", parent=body, fontName="LumirBold", textColor=CYAN)), _paragraph(f"Status: {STATUS_NAMES.get(module.get('scan_status'), module.get('scan_status'))}. {findings}", body), _paragraph(f"Źródła: {source_text}", small), Spacer(1, 4 * mm)]
        flow.append(KeepTogether(section))
    flow.extend([Paragraph("Zakres i ograniczenia", h2), _paragraph("Raport korzysta wyłącznie z lokalnych modułów oraz zatwierdzonych źródeł publicznych. Nie loguje się do kont, nie omija zabezpieczeń i nie potwierdza tożsamości osoby na podstawie samego nicku lub numeru. Status „niepotwierdzone” oznacza brak twardego dowodu, a nie negatywny wynik.", body)])
    doc.build(flow, onFirstPage=_footer, onLaterPages=_footer)
    return str(Path(outfile))
