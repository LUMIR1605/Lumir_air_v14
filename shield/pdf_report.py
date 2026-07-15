"""Client-facing Lumir SHIELD PDF report rendered from existing scan data."""

from datetime import datetime
from html import escape
from pathlib import Path

import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle


PAGE_W, PAGE_H = A4
MARGIN = 14 * mm
NAVY = colors.HexColor("#020B17")
PANEL = colors.HexColor("#071A2D")
PANEL_ALT = colors.HexColor("#0A2540")
CYAN = colors.HexColor("#35DFFF")
BLUE = colors.HexColor("#147CFF")
TEXT = colors.HexColor("#F2F8FF")
MUTED = colors.HexColor("#A9C0D6")
GREEN = colors.HexColor("#35E879")
AMBER = colors.HexColor("#FFC52B")
RED = colors.HexColor("#FF5D6C")
GRAY = colors.HexColor("#8EA2B8")

MODULE_NAMES = {
    "email_scan": "Bezpieczeństwo poczty",
    "domain_scan": "Domena i DNS",
    "breach_scan": "Wycieki danych",
    "account_exposure_scan": "Konta i usługi",
    "username_scan": "Nazwa użytkownika",
    "phone_scan": "Telefon",
    "url_scan": "Adres URL",
    "dns_scan": "DNS",
    "mail_security_scan": "Zabezpieczenia poczty",
    "web_security_scan": "Bezpieczeństwo strony",
}
STATUS_NAMES = {
    "completed": "Zakończono",
    "partial": "Częściowo sprawdzono",
    "unavailable": "Niedostępny",
    "blocked": "Zablokowany",
    "not_applicable": "Nie dotyczy",
    "timeout": "Nie ukończono",
    "error": "Nie ukończono",
}


def _register_fonts():
    """Embed a Unicode font available on Windows, Termux, Linux or ReportLab."""
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


def _mix(start, end, amount):
    return colors.Color(
        start.red + (end.red - start.red) * amount,
        start.green + (end.green - start.green) * amount,
        start.blue + (end.blue - start.blue) * amount,
    )


def _gradient(c, x, y, width, height, start, end, steps=36):
    step = height / steps
    for index in range(steps):
        c.setFillColor(_mix(start, end, index / max(steps - 1, 1)))
        c.rect(x, y + index * step, width, step + 0.5, fill=1, stroke=0)


def _styles():
    return {
        "eyebrow": ParagraphStyle("eyebrow", fontName="LumirBold", fontSize=7.4, leading=9, textColor=CYAN),
        "title": ParagraphStyle("title", fontName="LumirBold", fontSize=20, leading=24, textColor=TEXT),
        "subtitle": ParagraphStyle("subtitle", fontName="LumirRegular", fontSize=9, leading=12, textColor=MUTED),
        "card_title": ParagraphStyle("card_title", fontName="LumirBold", fontSize=9.5, leading=12, textColor=TEXT),
        "body": ParagraphStyle("body", fontName="LumirRegular", fontSize=8.7, leading=12, textColor=TEXT),
        "muted": ParagraphStyle("muted", fontName="LumirRegular", fontSize=8.2, leading=11, textColor=MUTED),
        "small": ParagraphStyle("small", fontName="LumirRegular", fontSize=7.4, leading=9.3, textColor=MUTED),
        "table": ParagraphStyle("table", fontName="LumirRegular", fontSize=7.5, leading=9.5, textColor=TEXT),
    }


def _paragraph(c, value, x, top, width, style):
    text = escape(str(value or "Brak danych")).replace("\n", "<br/>")
    paragraph = Paragraph(text, style)
    _, height = paragraph.wrap(width, PAGE_H)
    paragraph.drawOn(c, x, top - height)
    return height


def _background(c, number, section):
    _gradient(c, 0, 0, PAGE_W, PAGE_H, NAVY, colors.HexColor("#031D34"))
    c.setFillColor(colors.HexColor("#073A61"))
    c.circle(PAGE_W - 16 * mm, PAGE_H - 18 * mm, 27 * mm, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#082A4C"))
    c.circle(8 * mm, 16 * mm, 19 * mm, fill=1, stroke=0)
    c.setStrokeColor(colors.HexColor("#15577E"))
    c.setLineWidth(0.45)
    c.line(MARGIN, 14 * mm, PAGE_W - MARGIN, 14 * mm)
    c.setFillColor(MUTED)
    c.setFont("LumirRegular", 7)
    c.drawString(MARGIN, 8.5 * mm, "Lumír SHIELD v2.0  |  SECURITY INTELLIGENCE")
    c.drawRightString(PAGE_W - MARGIN, 8.5 * mm, f"{section.upper()}  |  STRONA {number}")


def _card(c, x, y, width, height, accent=CYAN):
    c.saveState()
    c.setFillColor(PANEL)
    c.setStrokeColor(accent)
    c.setLineWidth(0.55)
    c.roundRect(x, y, width, height, 3.5 * mm, fill=1, stroke=1)
    c.setFillColor(PANEL_ALT)
    c.roundRect(x, y + height - 5 * mm, width, 5 * mm, 3.5 * mm, fill=1, stroke=0)
    c.restoreState()


def _draw_logo(c, x, y, size):
    """Draw the shield, lock and circuit mark without external assets."""
    c.saveState()
    c.setLineJoin(1)
    c.setFillColor(colors.HexColor("#061B36"))
    c.setStrokeColor(colors.HexColor("#D5F9FF"))
    c.setLineWidth(1.25)
    shield = c.beginPath()
    shield.moveTo(x, y + size)
    shield.lineTo(x + size * 0.72, y + size * 0.75)
    shield.lineTo(x + size * 0.62, y + size * 0.25)
    shield.lineTo(x, y)
    shield.lineTo(x - size * 0.62, y + size * 0.25)
    shield.lineTo(x - size * 0.72, y + size * 0.75)
    shield.close()
    c.drawPath(shield, fill=1, stroke=1)
    c.setStrokeColor(CYAN)
    c.setLineWidth(2.1)
    c.drawPath(shield, fill=0, stroke=1)
    c.setStrokeColor(CYAN)
    c.setLineWidth(0.85)
    for direction in (-1, 1):
        c.line(x + direction * size * 0.54, y + size * 0.55, x + direction * size * 0.29, y + size * 0.55)
        c.line(x + direction * size * 0.29, y + size * 0.55, x + direction * size * 0.2, y + size * 0.47)
        c.circle(x + direction * size * 0.54, y + size * 0.55, 1.3, fill=1, stroke=0)
    c.setStrokeColor(colors.HexColor("#75F0FF"))
    c.setLineWidth(2)
    c.arc(x - size * 0.2, y + size * 0.38, x + size * 0.2, y + size * 0.75, 0, 180)
    c.setFillColor(colors.HexColor("#0A2E59"))
    c.setStrokeColor(colors.HexColor("#D9FAFF"))
    c.roundRect(x - size * 0.29, y + size * 0.27, size * 0.58, size * 0.35, 3, fill=1, stroke=1)
    c.setFillColor(colors.HexColor("#BDF8FF"))
    c.circle(x, y + size * 0.46, size * 0.045, fill=1, stroke=0)
    c.rect(x - size * 0.025, y + size * 0.34, size * 0.05, size * 0.1, fill=1, stroke=0)
    c.restoreState()


def _module(report, name):
    return next((item for item in report.get("modules", []) if isinstance(item, dict) and item.get("module") == name), {})


def _safe_list(value):
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if item not in (None, "", "none", "None")]
    return []


def _technical_value(value, unavailable="Brak danych"):
    if value is None:
        return unavailable
    if isinstance(value, str) and value.strip().lower() in {"", "none", "not_checked"}:
        return unavailable
    if isinstance(value, bool):
        return "Tak" if value else "Nie"
    if isinstance(value, (list, tuple)):
        values = _safe_list(value)
        return ", ".join(values) if values else unavailable
    if isinstance(value, dict):
        status = value.get("status")
        if status in {"not_checked", "not_applicable"}:
            return "Nie sprawdzono"
        pairs = []
        for key, item in value.items():
            if key == "status":
                continue
            rendered = _technical_value(item, "Brak danych")
            pairs.append(f"{key}: {rendered}")
        return "; ".join(pairs) if pairs else unavailable
    return str(value)


def _status(module):
    status = str(module.get("scan_status", "not_started")).lower()
    if status == "completed":
        if module.get("module") == "breach_scan" and isinstance(module.get("breaches_found"), int) and module.get("breaches_found", 0) > 0:
            return STATUS_NAMES[status], RED
        risk = str(module.get("risk", "unknown")).lower()
        if risk == "medium":
            return STATUS_NAMES[status], AMBER
        if risk in {"high", "critical"}:
            return STATUS_NAMES[status], AMBER
        return STATUS_NAMES[status], GREEN
    if status == "partial":
        return STATUS_NAMES[status], AMBER
    if status in {"unavailable", "blocked", "not_applicable", "timeout", "error"}:
        return STATUS_NAMES.get(status, "Nie uruchomiono"), GRAY
    return "Nie uruchomiono", GRAY


def _coverage(report, key):
    coverage = report.get("coverage")
    value = coverage.get(key) if isinstance(coverage, dict) else None
    return f"{value:.0f}%" if isinstance(value, (int, float)) else "Brak danych"


def _date(report):
    value = report.get("generated_at")
    if not isinstance(value, str):
        return datetime.now().strftime("%d.%m.%Y, %H:%M")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().strftime("%d.%m.%Y, %H:%M")
    except ValueError:
        return value.replace("T", " ")[:16]


def _reliability(report):
    value = str(report.get("assessment_reliability", "insufficient")).lower()
    return {
        "high": "Wysoka",
        "medium": "Ograniczona",
        "insufficient": "Niewystarczająca",
    }.get(value, "Brak danych")


def _check(module, check_id):
    for item in module.get("score_basis", []):
        if isinstance(item, dict) and item.get("check_id") == check_id:
            return item
    return {}


def _summary_text(report):
    coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
    missing = coverage.get("missing_modules", []) if isinstance(coverage.get("missing_modules"), list) else []
    if missing:
        labels = ", ".join(MODULE_NAMES.get(name, str(name)) for name in missing)
        return f"Wynik pokazuje stan w sprawdzonym zakresie. Pełna ocena nie była możliwa, ponieważ nie wykonano: {labels}."
    return "Wynik pokazuje stan w sprawdzonym zakresie wykonanych modułów. Nie zastępuje pełnego audytu bezpieczeństwa."


def _page_header(c, styles, number, title, subtitle):
    _background(c, number, title)
    _paragraph(c, "LUMÍR SHIELD v2.0", MARGIN, PAGE_H - 20 * mm, 80 * mm, styles["eyebrow"])
    _paragraph(c, title, MARGIN, PAGE_H - 26 * mm, 150 * mm, styles["title"])
    _paragraph(c, subtitle, MARGIN, PAGE_H - 39 * mm, PAGE_W - 2 * MARGIN, styles["subtitle"])


def _page_one(c, report, styles):
    _background(c, 1, "Podsumowanie")
    _draw_logo(c, MARGIN + 12 * mm, PAGE_H - 39 * mm, 17 * mm)
    _paragraph(c, "LUMÍR SHIELD v2.0", MARGIN + 27 * mm, PAGE_H - 20 * mm, 100 * mm, styles["eyebrow"])
    _paragraph(c, "Raport bezpieczeństwa", MARGIN + 27 * mm, PAGE_H - 26 * mm, 120 * mm, styles["title"])
    target = _technical_value(report.get("target"), "Brak celu skanowania")
    _paragraph(c, f"Cel skanowania: {target}", MARGIN + 27 * mm, PAGE_H - 42 * mm, 125 * mm, styles["subtitle"])
    _paragraph(c, f"Data: {_date(report)}", MARGIN + 27 * mm, PAGE_H - 48 * mm, 125 * mm, styles["subtitle"])

    score_data = report.get("risk_score") if isinstance(report.get("risk_score"), dict) else {}
    score = score_data.get("score")
    score_text = str(round(score)) if isinstance(score, (int, float)) else "-"
    center_x, center_y = 65 * mm, PAGE_H - 111 * mm
    c.saveState()
    c.setFillColor(colors.HexColor("#0A3151"))
    c.circle(center_x, center_y, 38 * mm, fill=1, stroke=0)
    c.setStrokeColor(CYAN)
    c.setLineWidth(2.7)
    c.circle(center_x, center_y, 32 * mm, fill=0, stroke=1)
    c.setStrokeColor(colors.HexColor("#8FF5FF"))
    c.setLineWidth(0.6)
    c.circle(center_x, center_y, 27 * mm, fill=0, stroke=1)
    c.setFillColor(TEXT)
    c.setFont("LumirBold", 36)
    c.drawCentredString(center_x, center_y + 3 * mm, score_text)
    c.setFillColor(MUTED)
    c.setFont("LumirRegular", 10)
    c.drawCentredString(center_x, center_y - 5 * mm, "/ 100")
    c.restoreState()
    _paragraph(c, "Wynik techniczny w sprawdzonym zakresie", MARGIN, center_y - 43 * mm, 102 * mm, ParagraphStyle("score", parent=styles["card_title"], alignment=1, textColor=CYAN))

    metrics = [
        ("Pokrycie modułów", _coverage(report, "module_weighted_percent")),
        ("Pokrycie kontroli", _coverage(report, "control_weighted_percent")),
        ("Wiarygodność oceny", _reliability(report)),
    ]
    metric_x, metric_y = 111 * mm, PAGE_H - 68 * mm
    for index, (label, value) in enumerate(metrics):
        y = metric_y - index * 30 * mm
        _card(c, metric_x, y, 82 * mm, 23 * mm, CYAN if index < 2 else AMBER)
        _paragraph(c, label, metric_x + 7 * mm, y + 17 * mm, 68 * mm, styles["small"])
        _paragraph(c, value, metric_x + 7 * mm, y + 11 * mm, 68 * mm, styles["card_title"])

    _card(c, MARGIN, 66 * mm, PAGE_W - 2 * MARGIN, 30 * mm, AMBER)
    _paragraph(c, "Ważne ograniczenie", MARGIN + 7 * mm, 89 * mm, 50 * mm, ParagraphStyle("warning", parent=styles["card_title"], textColor=AMBER))
    _paragraph(c, "Wynik nie oznacza pełnego audytu, ponieważ część modułów była niedostępna lub zablokowana.", MARGIN + 7 * mm, 82 * mm, PAGE_W - 2 * MARGIN - 14 * mm, styles["body"])
    _card(c, MARGIN, 27 * mm, PAGE_W - 2 * MARGIN, 31 * mm, CYAN)
    _paragraph(c, "Podsumowanie dla Ciebie", MARGIN + 7 * mm, 51 * mm, 70 * mm, styles["card_title"])
    _paragraph(c, _summary_text(report), MARGIN + 7 * mm, 44 * mm, PAGE_W - 2 * MARGIN - 14 * mm, styles["muted"])
    c.showPage()


def _module_detail(module):
    name = module.get("module")
    if name == "email_scan":
        if module.get("valid_format") is False:
            return "Adres e-mail ma niepoprawny format."
        score = module.get("score")
        return f"Sprawdzono ustawienia poczty{f'; wynik techniczny: {round(score)}/100' if isinstance(score, (int, float)) else ''}."
    if name == "domain_scan":
        return "Potwierdzono dostępność domeny i podstawowe rekordy DNS." if module.get("exists") else "Nie potwierdzono dostępności domeny."
    if name == "breach_scan":
        count = module.get("breaches_found")
        if isinstance(count, int):
            return "Nie potwierdzono wycieku w dostępnym źródle." if count == 0 else f"Potwierdzono wpisy w wyciekach: {count}."
        return "Nie sprawdzono pełnej bazy wycieków: źródło było niedostępne."
    if name in {"account_exposure_scan", "username_scan"}:
        return "Nie potwierdzono kont w dostępnych źródłach. Nie oznacza to, że konta nie istnieją."
    reason = module.get("error_reason")
    return _technical_value(reason, "Moduł nie przekazał dodatkowych danych.")


def _page_two(c, report, styles):
    _page_header(c, styles, 2, "Co sprawdziliśmy", "Statusy pokazują rzeczywisty zakres wykonanej analizy.")
    modules = [item for item in report.get("modules", []) if isinstance(item, dict)]
    top = PAGE_H - 54 * mm
    card_h = min(29 * mm, max(20 * mm, 110 * mm / max(len(modules), 1)))
    for index, module in enumerate(modules):
        y = top - (index + 1) * card_h
        label, accent = _status(module)
        _card(c, MARGIN, y, PAGE_W - 2 * MARGIN, card_h - 3 * mm, accent)
        _paragraph(c, MODULE_NAMES.get(module.get("module"), str(module.get("module", "Moduł"))), MARGIN + 7 * mm, y + card_h - 8 * mm, 68 * mm, styles["card_title"])
        _paragraph(c, label, PAGE_W - MARGIN - 45 * mm, y + card_h - 8 * mm, 38 * mm, ParagraphStyle(f"module_status_{index}", parent=styles["small"], alignment=2, textColor=accent))
        _paragraph(c, _module_detail(module), MARGIN + 7 * mm, y + card_h - 15 * mm, PAGE_W - 2 * MARGIN - 14 * mm, styles["muted"])

    email, domain = _module(report, "email_scan"), _module(report, "domain_scan")
    card_w = (PAGE_W - 2 * MARGIN - 7 * mm) / 2
    email_text = "Format adresu został potwierdzony." if email.get("valid_format") else "Nie potwierdzono poprawnego formatu adresu."
    if _check(email, "spf_record").get("status") == "passed":
        email_text += " Rekord SPF został wykryty."
    if _check(email, "dmarc_record").get("status") == "failed":
        email_text += " DMARC wymaga poprawy."
    domain_text = "Domena odpowiada poprawnie." if domain.get("exists") else "Domena nie została potwierdzona."
    if domain.get("https") is None:
        domain_text += " HTTPS nie był sprawdzany w tym zakresie."
    for x, title, detail, accent in ((MARGIN, "Poczta", email_text, AMBER if email.get("risk") == "medium" else GREEN), (MARGIN + card_w + 7 * mm, "Domena", domain_text, GREEN if domain.get("exists") else GRAY)):
        _card(c, x, 80 * mm, card_w, 45 * mm, accent)
        _paragraph(c, title, x + 7 * mm, 118 * mm, card_w - 14 * mm, styles["card_title"])
        _paragraph(c, detail, x + 7 * mm, 109 * mm, card_w - 14 * mm, styles["muted"])
    c.showPage()


def _actions(report):
    email, breach = _module(report, "email_scan"), _module(report, "breach_scan")
    actions = []
    if breach.get("scan_status") == "completed" and isinstance(breach.get("breaches_found"), int) and breach.get("breaches_found", 0) > 0:
        actions.append("Zmień hasła do kont wskazanych przez potwierdzony wyciek i włącz 2FA.")
    if _check(email, "dmarc_record").get("status") == "failed":
        actions.append("Skonfiguruj rekord DMARC dla domeny, aby ograniczyć podszywanie się pod adres e-mail.")
    if _check(email, "spf_record").get("status") == "failed":
        actions.append("Dodaj lub popraw rekord SPF dla domeny pocztowej.")
    if email.get("scan_status") == "partial":
        actions.append("Uzupełnij weryfikację ustawień SPF, DKIM i DMARC dla adresu pocztowego.")
    actions.append("Włącz uwierzytelnianie dwuskładnikowe (2FA) wszędzie, gdzie jest dostępne.")
    if breach.get("scan_status") != "completed":
        actions.append("Po skonfigurowaniu uprawnionego źródła ponów sprawdzenie wycieków danych.")
    unique = []
    for action in actions:
        if action not in unique:
            unique.append(action)
    return unique[:3]


def _unavailable(report):
    entries = []
    for module in report.get("modules", []):
        if not isinstance(module, dict) or module.get("scan_status") == "completed":
            continue
        name = MODULE_NAMES.get(module.get("module"), str(module.get("module", "Moduł")))
        status, _ = _status(module)
        entries.append(f"{name}: {status.lower()}.")
    return entries or ["Wszystkie zaplanowane moduły zakończyły się w dostępnym zakresie."]


def _technical_rows(report):
    email, domain = _module(report, "email_scan"), _module(report, "domain_scan")
    dns = domain.get("dns") if isinstance(domain.get("dns"), dict) else {}
    dmarc = email.get("dmarc")
    if isinstance(dmarc, str) and dmarc.strip().lower() == "none":
        dmarc = "Rekord wykryty: polityka monitorująca"
    return [
        ("DNS", _technical_value(dns, "Brak danych DNS")),
        ("MX", _technical_value(email.get("mx_records") or dns.get("MX"), "Nie wykryto rekordu")),
        ("SPF", _technical_value(email.get("spf"), "Nie wykryto rekordu")),
        ("DKIM", _technical_value(email.get("dkim"), "Nie potwierdzono rekordu")),
        ("DMARC", _technical_value(dmarc, "Nie wykryto rekordu")),
        ("HTTPS", _technical_value(domain.get("https"), "Nie sprawdzono")),
        ("Nagłówki", _technical_value(domain.get("security_headers"), "Nie sprawdzono")),
    ]


def _page_three(c, report, styles):
    _page_header(c, styles, 3, "Plan działania i dane techniczne", "Kroki wynikają wyłącznie z danych dostępnych w tym raporcie.")
    actions = _actions(report)
    action_top = PAGE_H - 54 * mm
    for index, action in enumerate(actions):
        y = action_top - (index + 1) * 20 * mm
        _card(c, MARGIN, y, PAGE_W - 2 * MARGIN, 16 * mm, CYAN if index == 0 else AMBER)
        c.setFillColor(CYAN if index == 0 else AMBER)
        c.circle(MARGIN + 8 * mm, y + 8 * mm, 3.7 * mm, fill=1, stroke=0)
        c.setFillColor(NAVY)
        c.setFont("LumirBold", 8)
        c.drawCentredString(MARGIN + 8 * mm, y + 6.2 * mm, str(index + 1))
        _paragraph(c, action, MARGIN + 16 * mm, y + 12 * mm, PAGE_W - 2 * MARGIN - 22 * mm, styles["muted"])

    unavailable = " ".join(_unavailable(report))
    _card(c, MARGIN, 138 * mm, PAGE_W - 2 * MARGIN, 28 * mm, GRAY)
    _paragraph(c, "Czego nie udało się sprawdzić", MARGIN + 7 * mm, 159 * mm, 100 * mm, styles["card_title"])
    _paragraph(c, unavailable, MARGIN + 7 * mm, 151 * mm, PAGE_W - 2 * MARGIN - 14 * mm, styles["muted"])

    rows = [[Paragraph("<b>Obszar</b>", styles["table"]), Paragraph("<b>Wartość</b>", styles["table"])]]
    for label, value in _technical_rows(report):
        rows.append([Paragraph(escape(label), styles["table"]), Paragraph(escape(value), styles["table"])])
    table = Table(rows, colWidths=[35 * mm, PAGE_W - 2 * MARGIN - 35 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0A3151")),
        ("BACKGROUND", (0, 1), (-1, -1), PANEL),
        ("TEXTCOLOR", (0, 0), (-1, -1), TEXT),
        ("FONTNAME", (0, 0), (-1, -1), "LumirRegular"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#1A5479")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    _, height = table.wrap(PAGE_W - 2 * MARGIN, 100 * mm)
    table.drawOn(c, MARGIN, 55 * mm)
    c.showPage()


def build(report, outfile="shield_report.pdf"):
    """Create a compact three-page Lumir SHIELD client report from scan results."""
    _register_fonts()
    document = canvas.Canvas(outfile, pagesize=A4, pageCompression=1)
    document.setTitle("Lumír SHIELD v2.0 - Raport bezpieczeństwa")
    styles = _styles()
    _page_one(document, report, styles)
    _page_two(document, report, styles)
    _page_three(document, report, styles)
    document.save()
    return str(Path(outfile))
