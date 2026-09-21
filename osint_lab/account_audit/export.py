"""Human-first private JSON, CSV and HTML exports for ACCOUNT_AUDIT."""

import csv
from html import escape
import io
import json
import os
from pathlib import Path
import tempfile

from .cleanup import AccountCleanupCatalog
from .models import AccountAuditRun, AccountAuditStatus


class AccountAuditExporter:
    def __init__(self, *, case_root: Path, catalog: AccountCleanupCatalog) -> None:
        self.case_root = Path(case_root).resolve()
        self.catalog = catalog

    def export(self, run: AccountAuditRun) -> dict[str, str]:
        target = (self.case_root / run.case_id / "account_audit" / "reports").resolve()
        if self.case_root not in target.parents:
            raise ValueError("account-audit export path escaped case root")
        target.mkdir(parents=True, exist_ok=True)
        json_path = target / "account_audit.json"
        csv_path = target / "account_audit.csv"
        html_path = target / "account_cleanup.html"
        self._atomic(json_path, json.dumps(run.to_dict(), ensure_ascii=False, indent=2,
                                          sort_keys=True).encode("utf-8") + b"\n")
        self._atomic(csv_path, self._csv(run).encode("utf-8-sig"))
        self._atomic(html_path, self._html(run).encode("utf-8"))
        return {"json": str(json_path), "csv": str(csv_path), "html": str(html_path)}

    def _csv(self, run: AccountAuditRun) -> str:
        output = io.StringIO(newline="")
        fields = ["Service", "Domain", "Detection status", "Confidence", "Method",
                  "User decision", "Official deletion/account URL", "Notes"]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for item in run.results:
            cleanup = self.catalog.get(item.service_id)
            writer.writerow({
                "Service": item.service_name,
                "Domain": item.domain,
                "Detection status": item.status.value,
                "Confidence": item.confidence.value,
                "Method": item.detection_method.value,
                "User decision": item.review_status.value,
                "Official deletion/account URL": cleanup.deletion_url or cleanup.account_settings_url or "",
                "Notes": self._private_notes(item),
            })
        return output.getvalue()

    def _html(self, run: AccountAuditRun) -> str:
        summary = run.summary()
        found = [item for item in run.results if item.status is AccountAuditStatus.FOUND]
        review = [item for item in run.results if item.status in {
            AccountAuditStatus.UNKNOWN, AccountAuditStatus.RATE_LIMITED,
            AccountAuditStatus.BLOCKED, AccountAuditStatus.ERROR,
        }]
        not_found = [item for item in run.results if item.status is AccountAuditStatus.NOT_FOUND]

        def row(item: object, checkbox: bool = False) -> str:
            cleanup = self.catalog.get(item.service_id)
            url = cleanup.deletion_url or cleanup.account_settings_url
            service = escape(item.service_name)
            service_html = f'<a href="{escape(url, quote=True)}">{service}</a>' if url else service
            mark = '<input type="checkbox" aria-label="manual cleanup"> ' if checkbox else ""
            return (f"<tr><td>{mark}{service_html}</td><td>{escape(item.domain)}</td>"
                    f"<td>{item.status.value}</td><td>{item.confidence.value}</td>"
                    f"<td>{item.detection_method.value}</td><td>{item.review_status.value}</td>"
                    f"<td>{escape(self._private_notes(item))}</td></tr>")

        return f'''<!doctype html><html lang="pl"><head><meta charset="utf-8">
<title>Audyt kont - podsumowanie</title><style>body{{font:16px Segoe UI,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#182235}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd5e3;padding:.55rem;text-align:left}}th{{background:#eef3f9}}details{{margin:1rem 0}}.notice{{background:#fff7d6;padding:1rem;border-left:4px solid #d69e00}}</style></head><body>
<h1>AUDYT KONT - PODSUMOWANIE</h1>
<p>Sprawdzono {summary['SERVICES_CHECKED']} usług. W {summary['FOUND']} usługach znaleziono sygnał, że adres może być używany przez konto. {summary['NEEDS_MANUAL_REVIEW']} wyników wymaga ręcznej weryfikacji. {summary['RATE_LIMITED']} usług ograniczyło zapytania.</p>
<p class="notice">ACCOUNT AUDIT jest odrębnym self-audytem, nie publicznym OSINT. Wyniki nie potwierdzają właściciela konta. Usuwanie i logowanie pozostają wyłącznie ręczne.</p>
<h2>PRAWDOPODOBNIE MASZ KONTO</h2><table><tr><th>Serwis</th><th>Domena</th><th>Status</th><th>Pewność</th><th>Metoda</th><th>Decyzja</th><th>Notatki</th></tr>{''.join(row(item, True) for item in found)}</table>
<h2>DO SPRAWDZENIA</h2><table><tr><th>Serwis</th><th>Domena</th><th>Status</th><th>Pewność</th><th>Metoda</th><th>Decyzja</th><th>Notatki</th></tr>{''.join(row(item) for item in review)}</table>
<details><summary>NIE ZNALEZIONO ({len(not_found)})</summary><table><tr><th>Serwis</th><th>Domena</th><th>Status</th><th>Pewność</th><th>Metoda</th><th>Decyzja</th><th>Notatki</th></tr>{''.join(row(item) for item in not_found)}</table></details>
</body></html>'''

    @staticmethod
    def _private_notes(item: object) -> str:
        values = [item.user_note or item.notes]
        if item.recovery_email_masked:
            values.append(f"Masked recovery email: {item.recovery_email_masked}")
        if item.recovery_phone_masked:
            values.append(f"Masked recovery phone: {item.recovery_phone_masked}")
        return " | ".join(values)

    @staticmethod
    def _atomic(path: Path, content: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
