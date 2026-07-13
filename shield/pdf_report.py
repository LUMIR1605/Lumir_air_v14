from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
import reportlab


MODULE_NAMES = {
    "email_scan": "E-mail",
    "domain_scan": "Domena",
    "breach_scan": "Wycieki danych",
    "username_scan": "Nazwa u\u017cytkownika",
    "phone_scan": "Telefon",
}
RISK_NAMES = {
    "low": "Bardzo dobrze",
    "medium": "Uwaga",
    "high": "Wysokie ryzyko",
    "critical": "Wysokie ryzyko",
    "unknown": "Brak danych",
}
RISK_COLORS = {
    "low": colors.HexColor("#31e778"),
    "medium": colors.HexColor("#ffc52b"),
    "high": colors.HexColor("#ff5d6c"),
    "critical": colors.HexColor("#ff5d6c"),
    "unknown": colors.HexColor("#9eb3ca"),
}


def _register_fonts():
    """Prefer system fonts with Polish glyphs, while retaining Termux portability."""
    bundled = Path(reportlab.__file__).resolve().parent / "fonts"
    options = [
        (Path("/system/fonts/Roboto-Regular.ttf"), Path("/system/fonts/Roboto-Bold.ttf")),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")),
        (Path("C:/Windows/Fonts/segoeui.ttf"), Path("C:/Windows/Fonts/segoeuib.ttf")),
        (bundled / "Vera.ttf", bundled / "VeraBd.ttf"),
    ]
    regular, bold = next((pair for pair in options if pair[0].is_file() and pair[1].is_file()), options[-1])
    pdfmetrics.registerFont(TTFont("LumirRegular", str(regular)))
    pdfmetrics.registerFont(TTFont("LumirBold", str(bold)))


def _page(canvas, document):
    canvas.saveState()
    canvas.setFillColor(colors.HexColor("#020b17"))
    canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
    canvas.setStrokeColor(colors.HexColor("#0e4f83"))
    canvas.setLineWidth(0.4)
    canvas.line(16 * mm, 16 * mm, A4[0] - 16 * mm, 16 * mm)
    canvas.setFillColor(colors.HexColor("#8da8c3"))
    canvas.setFont("LumirRegular", 7)
    canvas.drawString(16 * mm, 10 * mm, "Lumir SHIELD | Raport bezpieczenstwa")
    canvas.drawRightString(A4[0] - 16 * mm, 10 * mm, f"Strona {document.page}")
    canvas.restoreState()


def _module_card(module, styles):
    risk = str(module.get("risk", "unknown")).lower()
    name = MODULE_NAMES.get(str(module.get("module", "")), str(module.get("module", "Modul")))
    findings = module.get("findings", [])
    detail = "; ".join(str(item) for item in findings) if findings else "Nie wykryto dodatkowych informacji wymagajacych dzialania."
    title = Paragraph(escape(name), styles["card_title"])
    status = Paragraph(escape(RISK_NAMES.get(risk, "Brak danych")), styles[f"risk_{risk}" if risk in RISK_COLORS else "risk_unknown"])
    text = Paragraph(escape(detail), styles["card_body"])
    card = Table([[title, status], [text, ""]], colWidths=[118 * mm, 48 * mm])
    card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#071a2d")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#145781")),
        ("LINEBELOW", (0, 0), (-1, 0), 0.3, colors.HexColor("#145781")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return KeepTogether([card, Spacer(1, 4 * mm)])


def build(report, outfile="shield_report.pdf"):
    """Create a print-ready A4 presentation of the same scan object as HTML and JSON."""
    _register_fonts()
    document = SimpleDocTemplate(
        outfile,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("report_title", parent=styles["Title"], fontName="LumirBold", fontSize=23, leading=28, textColor=colors.HexColor("#f4fbff"), spaceAfter=3 * mm))
    styles.add(ParagraphStyle("eyebrow", parent=styles["BodyText"], fontName="LumirBold", fontSize=8, leading=10, textColor=colors.HexColor("#45d9ff"), spaceAfter=2 * mm))
    styles.add(ParagraphStyle("body", parent=styles["BodyText"], fontName="LumirRegular", fontSize=10, leading=14, textColor=colors.HexColor("#c7d9eb")))
    styles.add(ParagraphStyle("score", parent=styles["Title"], fontName="LumirBold", fontSize=40, leading=43, textColor=colors.HexColor("#f8fcff"), alignment=1))
    styles.add(ParagraphStyle("score_caption", parent=styles["BodyText"], fontName="LumirBold", fontSize=11, leading=14, textColor=colors.HexColor("#45d9ff"), alignment=1))
    styles.add(ParagraphStyle("card_title", parent=styles["Heading2"], fontName="LumirBold", fontSize=11, leading=14, textColor=colors.HexColor("#f4fbff")))
    styles.add(ParagraphStyle("card_body", parent=styles["BodyText"], fontName="LumirRegular", fontSize=9, leading=13, textColor=colors.HexColor("#c7d9eb")))
    for key, color in RISK_COLORS.items():
        styles.add(ParagraphStyle(f"risk_{key}", parent=styles["BodyText"], fontName="LumirBold", fontSize=9, leading=12, textColor=color, alignment=2))

    score = report.get("risk_score", {})
    value = score.get("score", 0)
    risk = str(score.get("risk", "unknown")).lower()
    story = [
        Paragraph("SECURITY INTELLIGENCE", styles["eyebrow"]),
        Paragraph("Lumir SHIELD - Raport bezpieczenstwa", styles["report_title"]),
        Paragraph(f"Cel skanowania: {escape(str(report.get('target', 'Brak danych')))}", styles["body"]),
        Spacer(1, 6 * mm),
    ]
    score_card = Table([
        [Paragraph(f"{value}/100", styles["score"])],
        [Paragraph(f"Wskaznik bezpieczenstwa: {RISK_NAMES.get(risk, 'Brak danych')}", styles["score_caption"])],
    ], colWidths=[166 * mm])
    score_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#062b49")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#35dfff")),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story += [score_card, Spacer(1, 7 * mm), Paragraph("Najwazniejsze wyniki", styles["card_title"]), Spacer(1, 2 * mm)]
    for module in report.get("modules", []):
        story.append(_module_card(module, styles))
    story += [Spacer(1, 2 * mm), Paragraph("Wynik zalezy od dostepnosci publicznych zrodel w chwili skanowania.", styles["body"])]
    document.build(story, onFirstPage=_page, onLaterPages=_page)
    return str(Path(outfile))
