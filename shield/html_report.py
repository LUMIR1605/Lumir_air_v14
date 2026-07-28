"""Self-contained, type-aware HTML report for Lumir SHIELD."""

from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path


TYPE_NAMES = {"email": "adres e-mail", "phone": "numer telefonu", "username": "nick / username"}
STATUS_NAMES = {
    "completed": "potwierdzone w zakresie źródła", "partial": "częściowo sprawdzone",
    "unavailable": "niedostępne", "blocked": "zablokowane", "timeout": "przekroczony czas",
    "error": "błąd źródła", "not_applicable": "nie dotyczy",
}


def _safe(value) -> str:
    if value in (None, "", [], {}):
        return "Brak danych"
    if isinstance(value, bool):
        return "Tak" if value else "Nie"
    if isinstance(value, (list, tuple)):
        return ", ".join(_safe(item) for item in value) or "Brak danych"
    return str(value)


def _details(report: dict) -> list[tuple[str, str]]:
    modules = {item.get("module"): item for item in report.get("modules", []) if isinstance(item, dict)}
    if report.get("scan_type") == "email":
        email, breach, accounts = modules.get("email_scan", {}), modules.get("breach_scan", {}), modules.get("account_exposure_scan", {})
        return [
            ("Format adresu", "Potwierdzony" if email.get("valid_format") else "Niepotwierdzony"),
            ("Domena", _safe(email.get("domain"))), ("Rekordy MX", _safe(email.get("mx_records"))),
            ("SPF", _safe(email.get("spf"))), ("DKIM", _safe(email.get("dkim"))),
            ("DMARC", _safe(email.get("dmarc"))),
            ("Wpisy w wyciekach", _safe(breach.get("breaches_found"))),
            ("Usługi powiązane", f"{_safe((accounts.get('services') or {}).get('probable_count'))} prawdopodobnych; własność niepotwierdzona"),
        ]
    if report.get("scan_type") == "phone":
        phone = modules.get("phone_scan", {})
        return [
            ("Format numeru", "Potwierdzony" if phone.get("valid") else "Niepotwierdzony"),
            ("Format międzynarodowy", _safe(phone.get("international"))),
            ("Kraj / obszar", _safe(phone.get("country"))), ("Operator", _safe(phone.get("operator"))),
            ("Własność numeru", "Niepotwierdzona — aplikacja nie wykonuje identyfikacji osoby."),
        ]
    username = modules.get("username_scan", {})
    profile = username.get("profile") or {}
    return [
        ("Format nicku", "Potwierdzony"), ("Platforma", _safe(profile.get("platform"))),
        ("Publiczny profil", _safe(profile.get("url"))), ("Typ konta", _safe(profile.get("account_type"))),
        ("Publiczne repozytoria", _safe(profile.get("public_repos"))),
        ("Własność profilu", "Niepotwierdzona — zgodność nicku nie dowodzi tożsamości."),
    ]


def _module_cards(report: dict) -> str:
    cards = []
    for module in report.get("modules", []):
        if not isinstance(module, dict):
            continue
        findings = module.get("findings") or [module.get("error_reason") or "Brak dodatkowych ustaleń."]
        cards.append(
            "<article class='card'><h3>{}</h3><p><b>Status:</b> {}</p><p><b>Pewność:</b> {}</p><p>{}</p></article>".format(
                escape(str(module.get("module", "moduł"))),
                escape(STATUS_NAMES.get(str(module.get("scan_status")), str(module.get("scan_status")))),
                escape(_safe(module.get("confidence"))),
                escape(_safe(findings)),
            )
        )
    return "".join(cards)


def _sources(report: dict) -> str:
    rows = []
    for module in report.get("modules", []):
        for source in module.get("sources", []) if isinstance(module, dict) else []:
            rows.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                escape(_safe(source.get("source_name") or source.get("source_id"))),
                escape(STATUS_NAMES.get(str(source.get("status")), _safe(source.get("status")))),
                escape(_safe(source.get("confidence"))),
                escape(_safe(source.get("terms_status"))),
            ))
    return "".join(rows) or "<tr><td colspan='4'>Brak źródeł wykonanych dla tego skanu.</td></tr>"


def build(report, outfile="shield_report_v2.html"):
    assessment = report.get("security_assessment") or {}
    coverage = report.get("coverage") or {}
    details = "".join(f"<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>" for label, value in _details(report))
    content = f"""<!doctype html><html lang='pl'><head><meta charset='utf-8'><title>Lumir SHIELD — raport</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#06111f;color:#eef7ff;margin:0}}main{{max-width:1040px;margin:auto;padding:42px}}header,.card,section{{background:#0a1a2d;border:1px solid #1b466b;border-radius:16px;padding:22px;margin:18px 0}}h1{{margin:0;color:#5be4ff}}h2{{color:#5be4ff}}h3{{margin:0 0 12px}}.muted{{color:#b9cadb}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}}.card{{margin:0}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px;border-bottom:1px solid #1b466b;vertical-align:top}}th{{color:#8cecff}}.warn{{color:#ffd36a}}code{{color:#a5efff}}</style></head><body><main>
<header><h1>LUMIR SHIELD</h1><p class='muted'>Raport własnych danych · {escape(TYPE_NAMES.get(report.get('scan_type'), str(report.get('scan_type'))))}</p><p><b>Cel:</b> {escape(_safe(report.get('target')))}<br><b>Data:</b> {escape(datetime.now().strftime('%d.%m.%Y, %H:%M'))}<br><b>Zgoda:</b> {'potwierdzona' if (report.get('consent') or {}).get('declared') else 'brak — analiza zablokowana'}</p></header>
<section><h2>Uczciwa ocena zakresu</h2><div class='grid'><article class='card'><b>Wynik techniczny</b><p>{escape(_safe(assessment.get('score')))} / 100</p></article><article class='card'><b>Pokrycie modułów</b><p>{escape(_safe(coverage.get('module_weighted_percent')))}%</p></article><article class='card'><b>Wiarygodność</b><p>{escape(_safe(report.get('assessment_reliability')))}</p></article></div><p class='warn'>{escape(_safe(assessment.get('public_verdict')))}</p></section>
<section><h2>Wyniki dla wybranego typu danych</h2><table>{details}</table></section>
<section><h2>Moduły i statusy</h2><div class='grid'>{_module_cards(report)}</div></section>
<section><h2>Źródła i poziom pewności</h2><table><tr><th>Źródło</th><th>Status</th><th>Pewność</th><th>Status zasad</th></tr>{_sources(report)}</table><p class='muted'>„Niepotwierdzone” oznacza brak twardego dowodu. Raport nie wyciąga z tego negatywnego wniosku.</p></section>
<section><h2>Zakres i prywatność</h2><p>Raport korzysta wyłącznie z lokalnych modułów i zatwierdzonych źródeł publicznych. Nie loguje się do kont, nie omija zabezpieczeń i nie potwierdza tożsamości osoby na podstawie samego nicku lub numeru.</p></section>
</main></body></html>"""
    Path(outfile).write_text(content, encoding="utf-8")
    return str(Path(outfile))
