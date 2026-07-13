from datetime import datetime
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph
import reportlab


PAGE_W, PAGE_H = A4
MARGIN = 16 * mm
NAVY = colors.HexColor("#020b17")
PANEL = colors.HexColor("#071a2d")
CYAN = colors.HexColor("#35dfff")
BLUE = colors.HexColor("#147cff")
TEXT = colors.HexColor("#f2f8ff")
MUTED = colors.HexColor("#a9c0d6")
GREEN = colors.HexColor("#35e879")
AMBER = colors.HexColor("#ffc52b")
RED = colors.HexColor("#ff5d6c")
MODULE_NAMES = {"email_scan": "E-mail", "domain_scan": "Domena", "breach_scan": "Wycieki danych", "username_scan": "Nazwa u\u017cytkownika", "phone_scan": "Telefon", "url_scan": "Adres URL"}
RISK_NAMES = {"low": "Bardzo dobrze", "medium": "Uwaga", "high": "Wysokie ryzyko", "critical": "Wysokie ryzyko", "unknown": "Brak danych"}
RISK_COLORS = {"low": GREEN, "medium": AMBER, "high": RED, "critical": RED, "unknown": MUTED}


def _register_fonts():
    bundled = Path(reportlab.__file__).resolve().parent / "fonts"
    options = [(Path("/system/fonts/Roboto-Regular.ttf"), Path("/system/fonts/Roboto-Bold.ttf")), (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")), (Path("C:/Windows/Fonts/segoeui.ttf"), Path("C:/Windows/Fonts/segoeuib.ttf")), (bundled / "Vera.ttf", bundled / "VeraBd.ttf")]
    regular, bold = next((pair for pair in options if pair[0].is_file() and pair[1].is_file()), options[-1])
    pdfmetrics.registerFont(TTFont("LumirRegular", str(regular)))
    pdfmetrics.registerFont(TTFont("LumirBold", str(bold)))


def _mix(start, end, amount):
    return colors.Color(start.red + (end.red - start.red) * amount, start.green + (end.green - start.green) * amount, start.blue + (end.blue - start.blue) * amount)


def _gradient(c, x, y, width, height, start, end, steps=42):
    step = height / steps
    for index in range(steps):
        c.setFillColor(_mix(start, end, index / max(steps - 1, 1)))
        c.rect(x, y + index * step, width, step + .5, fill=1, stroke=0)


def _paragraph(c, value, x, y, width, style):
    paragraph = Paragraph(escape(str(value)).replace("\n", "<br/>"), style)
    _, height = paragraph.wrap(width, PAGE_H)
    paragraph.drawOn(c, x, y - height)
    return height


def _styles():
    return {
        "eyebrow": ParagraphStyle("eyebrow", fontName="LumirBold", fontSize=7.5, leading=10, textColor=CYAN),
        "title": ParagraphStyle("title", fontName="LumirBold", fontSize=24, leading=28, textColor=TEXT),
        "subtitle": ParagraphStyle("subtitle", fontName="LumirRegular", fontSize=10, leading=14, textColor=MUTED),
        "card_title": ParagraphStyle("card_title", fontName="LumirBold", fontSize=11, leading=14, textColor=TEXT),
        "card_text": ParagraphStyle("card_text", fontName="LumirRegular", fontSize=8.7, leading=12, textColor=MUTED),
        "body": ParagraphStyle("body", fontName="LumirRegular", fontSize=10, leading=15, textColor=TEXT),
        "body_muted": ParagraphStyle("body_muted", fontName="LumirRegular", fontSize=9, leading=13, textColor=MUTED),
    }


def _background(c, page_number, section):
    _gradient(c, 0, 0, PAGE_W, PAGE_H, NAVY, colors.HexColor("#03182c"))
    c.setFillColor(colors.HexColor("#06345a")); c.circle(PAGE_W - 18 * mm, PAGE_H - 22 * mm, 29 * mm, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#082653")); c.circle(11 * mm, 20 * mm, 22 * mm, fill=1, stroke=0)
    c.setStrokeColor(colors.HexColor("#12527c")); c.setLineWidth(.45); c.line(MARGIN, 15 * mm, PAGE_W - MARGIN, 15 * mm)
    c.setFillColor(MUTED); c.setFont("LumirRegular", 7)
    c.drawString(MARGIN, 9 * mm, "Lumir SHIELD  v1.0  |  SECURITY INTELLIGENCE")
    c.drawRightString(PAGE_W - MARGIN, 9 * mm, f"{section.upper()}  |  {page_number}/6")


def _logo(c, x, y, size):
    c.saveState(); c.setLineWidth(1.4); c.setStrokeColor(CYAN); c.setFillColor(colors.HexColor("#0c3f75"))
    path = c.beginPath(); path.moveTo(x, y + size); path.lineTo(x + size * .78, y + size * .72); path.lineTo(x + size * .68, y + size * .2); path.lineTo(x, y); path.lineTo(x - size * .68, y + size * .2); path.lineTo(x - size * .78, y + size * .72); path.close()
    c.drawPath(path, fill=1, stroke=1); c.setFont("LumirBold", size * .65); c.setFillColor(TEXT); c.drawCentredString(x, y + size * .28, "L"); c.restoreState()


def _card(c, x, y, width, height, accent=CYAN):
    c.saveState(); c.setFillColor(PANEL); c.setStrokeColor(accent); c.setLineWidth(.65); c.roundRect(x, y, width, height, 4 * mm, fill=1, stroke=1)
    c.setFillColor(colors.HexColor("#0a2b49")); c.roundRect(x, y + height - 7 * mm, width, 7 * mm, 4 * mm, fill=1, stroke=0); c.restoreState()


def _icon(c, name, x, y, size, color=CYAN):
    c.saveState(); c.setStrokeColor(color); c.setFillColor(color); c.setLineWidth(1.5)
    if name == "check":
        c.circle(x, y, size / 2, fill=0, stroke=1); c.line(x - size * .23, y, x - size * .05, y - size * .2); c.line(x - size * .05, y - size * .2, x + size * .27, y + size * .23)
    elif name == "mail":
        c.roundRect(x - size / 2, y - size * .34, size, size * .68, 2, fill=0, stroke=1); c.line(x - size / 2, y + size * .28, x, y - size * .03); c.line(x, y - size * .03, x + size / 2, y + size * .28)
    elif name == "globe":
        c.circle(x, y, size / 2, fill=0, stroke=1); c.line(x - size / 2, y, x + size / 2, y); c.ellipse(x - size * .2, y - size / 2, x + size * .2, y + size / 2, fill=0, stroke=1)
    elif name == "lock":
        c.roundRect(x - size * .3, y - size * .32, size * .6, size * .55, 2, fill=0, stroke=1); c.arc(x - size * .22, y, x + size * .22, y + size * .45, 0, 180)
    elif name == "shield":
        _logo(c, x, y - size * .48, size * .6)
    elif name == "family":
        c.circle(x, y + size * .18, size * .16, fill=0, stroke=1); c.circle(x - size * .27, y, size * .12, fill=0, stroke=1); c.circle(x + size * .27, y, size * .12, fill=0, stroke=1); c.line(x - size * .42, y - size * .34, x + size * .42, y - size * .34)
    else:
        c.circle(x, y, size / 2, fill=0, stroke=1)
    c.restoreState()


def _module(report, name):
    return next((item for item in report.get("modules", []) if item.get("module") == name), {})


def _page_title(c, styles, number, title, subtitle):
    _background(c, number, title); _paragraph(c, "LUMIR SHIELD", MARGIN, PAGE_H - 25 * mm, 100 * mm, styles["eyebrow"]); _paragraph(c, title, MARGIN, PAGE_H - 31 * mm, 150 * mm, styles["title"]); _paragraph(c, subtitle, MARGIN, PAGE_H - 45 * mm, 160 * mm, styles["subtitle"])


def _page_one(c, report, styles):
    _background(c, 1, "Wynik"); _logo(c, PAGE_W / 2, PAGE_H - 52 * mm, 20 * mm)
    c.setFillColor(CYAN); c.setFont("LumirBold", 9); c.drawCentredString(PAGE_W / 2, PAGE_H - 82 * mm, "LUMIR SHIELD")
    c.setFillColor(TEXT); c.setFont("LumirBold", 21); c.drawCentredString(PAGE_W / 2, PAGE_H - 92 * mm, "RAPORT BEZPIECZE\u0143STWA")
    c.setFillColor(MUTED); c.setFont("LumirRegular", 10); c.drawCentredString(PAGE_W / 2, PAGE_H - 105 * mm, f"Cel skanowania: {report.get('target', 'Brak danych')}")
    score = report.get("risk_score", {}); value = score.get("score", 0); risk = str(score.get("risk", "unknown")).lower(); accent = RISK_COLORS.get(risk, MUTED); center_x, center_y = PAGE_W / 2, PAGE_H - 158 * mm
    c.saveState(); c.setFillColor(colors.HexColor("#0a3151")); c.circle(center_x, center_y, 42 * mm, fill=1, stroke=0); c.setStrokeColor(accent); c.setLineWidth(3); c.circle(center_x, center_y, 35 * mm, fill=0, stroke=1); c.setStrokeColor(CYAN); c.setLineWidth(.7); c.circle(center_x, center_y, 30 * mm, fill=0, stroke=1); c.setFillColor(TEXT); c.setFont("LumirBold", 41); c.drawCentredString(center_x, center_y + 3 * mm, str(value)); c.setFont("LumirRegular", 12); c.setFillColor(MUTED); c.drawCentredString(center_x, center_y - 6 * mm, "/ 100"); c.restoreState()
    label = "BARDZO DOBRY POZIOM BEZPIECZE\u0143STWA" if value >= 90 else ("DOBRY POZIOM BEZPIECZE\u0143STWA" if value >= 70 else ("UWAGA - WYMAGANE DZIA\u0141ANIE" if value >= 40 else "WYSOKIE RYZYKO"))
    _paragraph(c, label, MARGIN, PAGE_H - 204 * mm, PAGE_W - 2 * MARGIN, ParagraphStyle("score_label", parent=styles["card_title"], alignment=1, textColor=accent, fontSize=12))
    _card(c, MARGIN, 37 * mm, PAGE_W - 2 * MARGIN, 35 * mm, accent); c.setFillColor(CYAN); c.setFont("LumirBold", 8); c.drawString(MARGIN + 8 * mm, 65 * mm, "ANALIZA LUMIR AI")
    analysis = report.get("executive_summary", []); _paragraph(c, analysis[0] if analysis else "Wynik jest oparty na dostepnych danych z wykonanych modulow bezpieczenstwa.", MARGIN + 8 * mm, 59 * mm, PAGE_W - 32 * mm, styles["body"])
    c.setFillColor(MUTED); c.setFont("LumirRegular", 8); c.drawString(MARGIN + 8 * mm, 43 * mm, datetime.now().strftime("Wygenerowano: %d.%m.%Y, %H:%M")); c.showPage()


def _page_two(c, report, styles):
    _page_title(c, styles, 2, "Co znale\u017ali\u015bmy", "Najwa\u017cniejsze informacje z dost\u0119pnych modu\u0142\u00f3w skanu.")
    email, domain, username = _module(report, "email_scan"), _module(report, "domain_scan"), _module(report, "username_scan"); exposure = email.get("exposure", {}) if isinstance(email.get("exposure"), dict) else {}; accounts = username.get("accounts", []) or exposure.get("services", []) or []
    items = [("check", "Znalezione konta", f"{len(accounts)} znalezionych kont lub powiazanych uslug." if accounts else "Nie znaleziono kont w uruchomionych zrodlach.", GREEN if not accounts else AMBER), ("globe", "Domena", "Domena odpowiada poprawnie." if domain.get("exists") else "Brak potwierdzenia dostepnosci domeny.", GREEN if domain.get("exists") else MUTED), ("mail", "Bezpieczenstwo poczty", "Adres e-mail ma poprawny format." if email.get("valid_format") else "Brak pelnego potwierdzenia ustawien poczty.", GREEN if email.get("valid_format") else AMBER), ("lock", "HTTPS", "Polaczenie HTTPS jest aktywne." if domain.get("https") else "HTTPS nie zostal potwierdzony w tym skanie.", GREEN if domain.get("https") else AMBER)]
    card_w, card_h = 78 * mm, 53 * mm; positions = [(MARGIN, PAGE_H - 108 * mm), (PAGE_W - MARGIN - card_w, PAGE_H - 108 * mm), (MARGIN, PAGE_H - 168 * mm), (PAGE_W - MARGIN - card_w, PAGE_H - 168 * mm)]
    for (icon, title, detail, accent), (x, y) in zip(items, positions):
        _card(c, x, y, card_w, card_h, accent); _icon(c, icon, x + 12 * mm, y + card_h - 15 * mm, 10 * mm, accent); _paragraph(c, title, x + 20 * mm, y + card_h - 10 * mm, card_w - 26 * mm, styles["card_title"]); _paragraph(c, detail, x + 8 * mm, y + 20 * mm, card_w - 16 * mm, styles["card_text"])
    c.showPage()


def _page_three(c, report, styles):
    _page_title(c, styles, 3, "Plan dzia\u0142ania", "Trzy najwa\u017cniejsze kroki na podstawie wyniku skanu.")
    plan = report.get("action_plan", {}); actions = list(plan.get("now", [])) + list(plan.get("today", [])) + list(plan.get("later", [])); actions = actions or ["Utrzymuj aktualne hasla i wlacz uwierzytelnianie dwuskladnikowe, gdy jest dostepne."]
    for index in range(3):
        y = PAGE_H - (88 + index * 49) * mm; accent = [RED, AMBER, GREEN][index]; _card(c, MARGIN, y, PAGE_W - 2 * MARGIN, 39 * mm, accent); c.setFillColor(accent); c.circle(MARGIN + 15 * mm, y + 20 * mm, 8 * mm, fill=1, stroke=0); c.setFont("LumirBold", 14); c.setFillColor(NAVY); c.drawCentredString(MARGIN + 15 * mm, y + 16.5 * mm, str(index + 1)); _paragraph(c, ["Zrob teraz", "Zrob dzis", "Dobra praktyka"][index], MARGIN + 29 * mm, y + 31 * mm, 90 * mm, styles["card_title"]); _paragraph(c, actions[index] if index < len(actions) else "Brak dodatkowych dzialan wskazanych przez ten skan.", MARGIN + 29 * mm, y + 24 * mm, PAGE_W - MARGIN - (MARGIN + 29 * mm) - 8 * mm, styles["body_muted"])
    c.showPage()


def _page_four(c, report, styles):
    _page_title(c, styles, 4, "Cyfrowy \u015blad", "Konta i us\u0142ugi potwierdzone przez wykonane sprawdzenia.")
    username, email = _module(report, "username_scan"), _module(report, "email_scan"); found = []
    for item in username.get("accounts", []) or []:
        found.append((item.get("site", "Konto"), item.get("url", "Potwierdzone konto")) if isinstance(item, dict) else (str(item), "Potwierdzone konto"))
    exposure = email.get("exposure", {}) if isinstance(email.get("exposure"), dict) else {}
    found.extend((str(service), "Powiazana usluga") for service in exposure.get("services", []) or [])
    if not found:
        _card(c, MARGIN, PAGE_H - 128 * mm, PAGE_W - 2 * MARGIN, 62 * mm, MUTED); _icon(c, "shield", PAGE_W / 2, PAGE_H - 96 * mm, 22 * mm, MUTED); _paragraph(c, "Brak znalezionych kont", MARGIN, PAGE_H - 118 * mm, PAGE_W - 2 * MARGIN, ParagraphStyle("none_title", parent=styles["card_title"], alignment=1)); _paragraph(c, "W tym skanie nie potwierdzono publicznych kont ani powiazanych uslug.", MARGIN + 12 * mm, PAGE_H - 130 * mm, PAGE_W - 24 * mm, ParagraphStyle("none_text", parent=styles["card_text"], alignment=1))
    else:
        for index, (name, detail) in enumerate(found[:8]):
            col, row = index % 2, index // 2; card_w, card_h = 78 * mm, 27 * mm; x = MARGIN if col == 0 else PAGE_W - MARGIN - card_w; y = PAGE_H - (84 + row * 33) * mm; _card(c, x, y, card_w, card_h, CYAN); _icon(c, "check", x + 11 * mm, y + 14 * mm, 8 * mm, GREEN); _paragraph(c, name, x + 20 * mm, y + 20 * mm, card_w - 27 * mm, styles["card_title"]); _paragraph(c, detail, x + 20 * mm, y + 12 * mm, card_w - 27 * mm, styles["card_text"])
    c.showPage()


def _page_five(c, styles):
    _page_title(c, styles, 5, "Plan rodzinnego bezpiecze\u0144stwa", "Dobra praktyka bezpiecze\u0144stwa w erze AI.")
    guidance = [("Haslo bezpieczenstwa", "Ustal rodzinne haslo. Nie zapisuj go w telefonie ani w internecie."), ("Deepfake", "Nie ufaj tylko obrazowi lub nagraniu. Zawsze potwierdz pilna prosbe innym kanalem."), ("AI Voice", "Gdy rozmowca podaje sie za bliska osobe i nie zna hasla, przerwij rozmowe."), ("Phishing", "Nie klikaj linkow z pilnych wiadomosci. Weryfikuj nadawce i adres strony.")]
    for index, (title, detail) in enumerate(guidance):
        y = PAGE_H - (84 + index * 36) * mm; accent = [CYAN, BLUE, AMBER, RED][index]; _card(c, MARGIN, y, PAGE_W - 2 * MARGIN, 28 * mm, accent); _icon(c, "family" if index == 0 else "shield", MARGIN + 15 * mm, y + 14 * mm, 13 * mm, accent); _paragraph(c, title, MARGIN + 29 * mm, y + 21 * mm, 120 * mm, styles["card_title"]); _paragraph(c, detail, MARGIN + 29 * mm, y + 13 * mm, PAGE_W - MARGIN - (MARGIN + 29 * mm) - 8 * mm, styles["card_text"])
    c.showPage()


def _page_six(c, report, styles):
    _page_title(c, styles, 6, "Szczeg\u00f3\u0142y techniczne", "Dane diagnostyczne zebrane przez uruchomione modu\u0142y.")
    email, domain = _module(report, "email_scan"), _module(report, "domain_scan"); details = [("DNS", domain.get("dns", "Brak danych DNS")), ("SPF", email.get("spf", "Brak danych")), ("DKIM", email.get("dkim", "Brak danych")), ("DMARC", email.get("dmarc", "Brak danych")), ("Naglowki", domain.get("security_headers", "Brak danych"))]
    for index, (label, value) in enumerate(details):
        y = PAGE_H - (78 + index * 31) * mm; _card(c, MARGIN, y, PAGE_W - 2 * MARGIN, 24 * mm, BLUE); _paragraph(c, label, MARGIN + 8 * mm, y + 17 * mm, 32 * mm, styles["card_title"]); _paragraph(c, str(value).replace("{", "").replace("}", ""), MARGIN + 43 * mm, y + 17 * mm, PAGE_W - MARGIN - (MARGIN + 43 * mm) - 8 * mm, styles["card_text"])
    c.showPage()


def build(report, outfile="shield_report.pdf"):
    """Create a six-page Lumir SHIELD presentation from existing scan results."""
    _register_fonts(); c = canvas.Canvas(outfile, pagesize=A4, pageCompression=1); c.setTitle("Lumir SHIELD - Raport bezpieczenstwa"); styles = _styles()
    _page_one(c, report, styles); _page_two(c, report, styles); _page_three(c, report, styles); _page_four(c, report, styles); _page_five(c, styles); _page_six(c, report, styles); c.save()
    return str(Path(outfile))
