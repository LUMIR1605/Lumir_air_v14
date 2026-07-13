from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Spacer, Paragraph, Table, TableStyle


def build(report, outfile="shield_report.pdf"):
    """Create an A4 PDF from the same scan object used for JSON and HTML."""
    document = SimpleDocTemplate(outfile, pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm)
    styles = getSampleStyleSheet()
    story = [Paragraph("Lumír SHIELD - Raport bezpieczeństwa", styles["Title"])]
    score = report.get("risk_score", {})
    story += [
        Paragraph(f"Cel: {report.get('target', 'Brak danych')}", styles["BodyText"]),
        Paragraph(f"Wynik: {score.get('score', 0)}/100 - {score.get('risk', 'UNKNOWN')}", styles["Heading2"]),
        Spacer(1, 6 * mm),
    ]
    rows = [["Moduł", "Status", "Ryzyko", "Źródło", "Ustalenia"]]
    for module in report.get("modules", []):
        rows.append([
            str(module.get("module", "Brak")),
            str(module.get("scan_status", "completed")),
            str(module.get("risk", "unknown")),
            str(module.get("source", "Lumír SHIELD")),
            "; ".join(str(item) for item in module.get("findings", [])) or "Brak",
        ])
    table = Table(rows, colWidths=[30 * mm, 25 * mm, 22 * mm, 43 * mm, 48 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#075bb9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9fb8d4")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEADING", (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f8fc")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)
    story += [Spacer(1, 6 * mm), Paragraph("Wynik zależy od dostępności publicznych źródeł w chwili skanowania.", styles["BodyText"])]
    document.build(story)
    return str(Path(outfile))
