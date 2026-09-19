"""Private JSON and HTML report generation for completed case runs."""

from dataclasses import dataclass
from datetime import datetime
from html import escape
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Iterable, Mapping

from osint_lab.case_manifest import CaseManifest
from osint_lab.evidence import EvidenceVault
from osint_lab.orchestrator.audit import AuditVerification
from osint_lab.policies import SourceClass
from osint_lab.verification.contradictions import ContradictionResult


REPORT_ENGINE_VERSION = "1.0.0"


@dataclass(frozen=True, kw_only=True)
class ReportReference:
    json_path: str
    json_sha256: str
    json_evidence_id: str
    html_path: str
    html_sha256: str
    html_evidence_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "json_path": self.json_path,
            "json_sha256": self.json_sha256,
            "json_evidence_id": self.json_evidence_id,
            "html_path": self.html_path,
            "html_sha256": self.html_sha256,
            "html_evidence_id": self.html_evidence_id,
        }


class ReportEngine:
    """Render factual private reports and publish copies through Evidence Vault."""

    def __init__(
        self,
        *,
        evidence_vault: EvidenceVault,
        case_root: Path,
        clock,
    ) -> None:
        if not isinstance(evidence_vault, EvidenceVault):
            raise ValueError("EvidenceVault required")
        if not callable(clock):
            raise ValueError("clock must be callable")
        self._vault = evidence_vault
        self._case_root = Path(case_root).resolve()
        if self._case_root != self._vault.root:
            raise ValueError("report case root must match Evidence Vault root")
        self._clock = clock

    def build_model(
        self,
        *,
        manifest: CaseManifest,
        run_id: str,
        started_at: datetime,
        finished_at: datetime,
        overall_status: str,
        executions: Iterable[object],
        findings_summary: Mapping[str, int],
        contradiction: ContradictionResult,
        warnings: Iterable[str],
        audit_verification: AuditVerification,
    ) -> dict[str, object]:
        execution_records = tuple(executions)
        execution_payloads: list[dict[str, object]] = []
        findings: list[dict[str, object]] = []
        source_counts = {source.value: 0 for source in SourceClass}
        successful = partial = failed = denied = 0
        collectors: set[str] = set()
        receipt_refs: list[str] = []

        for record in execution_records:
            step = record.step
            result = record.result
            result_status = record.result_status
            collectors.add(step.collector_name)
            if result is not None and result_status != "DENIED":
                source_counts[step.source_class.value] += 1
            if result_status == "SUCCESS":
                successful += 1
            elif result_status == "PARTIAL":
                partial += 1
            elif result_status == "DENIED":
                denied += 1
            else:
                failed += 1
            receipt = result.receipt.to_dict() if result is not None and result.receipt is not None else None
            evidence_refs = list(result.receipt.evidence_refs) if receipt is not None else []
            receipt_reference = f"receipt:{result.receipt.execution_id}" if receipt is not None else None
            if receipt_reference is not None:
                receipt_refs.append(receipt_reference)
            execution_payloads.append({
                "step_id": step.step_id,
                "seed_type": step.seed_type,
                "collector": step.collector_name,
                "collector_version": record.collector_version,
                "source_class": step.source_class.value,
                "started_at": result.started_at.isoformat() if result is not None else None,
                "finished_at": result.finished_at.isoformat() if result is not None else None,
                "result": result_status,
                "errors": list(result.errors) if result is not None else list(record.errors),
                "receipt": receipt,
                "receipt_reference": receipt_reference,
                "evidence_refs": evidence_refs,
            })
            if result is None:
                continue
            for candidate in result.finding_candidates:
                findings.append({
                    "candidate_type": candidate.raw_status,
                    "normalized_status": candidate.normalized_status.value,
                    "confidence": None,
                    "source": step.collector_name,
                    "source_class": step.source_class.value,
                    "value_reference": candidate.value_reference,
                    "evidence_refs": [candidate.evidence_ref] if candidate.evidence_ref else evidence_refs,
                    "notes": candidate.notes,
                })

        generated_at = self._now()
        return {
            "schema_version": "1.0",
            "generated_at": generated_at.isoformat(),
            "case": {
                "case_id": manifest.case_id,
                "case_name": manifest.case_name,
                "purpose": manifest.purpose,
                "created_at": manifest.created_at.isoformat(),
                "status": manifest.status.value,
            },
            "executive_summary": {
                "run_id": run_id,
                "overall_status": overall_status,
                "started_at": started_at.isoformat(),
                "finished_at": finished_at.isoformat(),
                "seed_count": len(manifest.seed_entities),
                "collector_count": len(collectors),
                "successful_executions": successful,
                "partial_executions": partial,
                "failed_executions": failed,
                "denied_executions": denied,
                "finding_counts": dict(findings_summary),
                "contradiction_count": len(contradiction.reasons),
                "warnings": list(warnings),
            },
            "seeds": [seed.to_dict() for seed in manifest.seed_entities],
            "executions": execution_payloads,
            "findings": findings,
            "contradictions": {
                "severity": contradiction.severity.value,
                "reasons": list(contradiction.reasons),
                "evidence_refs": list(contradiction.evidence_refs),
            },
            "privacy_source_exposure": source_counts,
            "limitations": self._limitations(collectors),
            "audit": {
                "verified": audit_verification.valid,
                "verification_reason": audit_verification.reason,
                "entry_count": audit_verification.entry_count,
                "audit_head_hash": audit_verification.head_hash,
                "execution_receipt_refs": sorted(set(receipt_refs)),
            },
            "interpretation_notice": (
                "Results are technical metadata or public signals and are not independently "
                "verified identity or ownership conclusions. Unable to determine is a valid outcome."
            ),
        }

    def write(
        self,
        *,
        manifest: CaseManifest,
        run_id: str,
        model: Mapping[str, object],
    ) -> ReportReference:
        if not isinstance(manifest, CaseManifest):
            raise ValueError("validated CaseManifest required")
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be non-empty")
        if not isinstance(model, Mapping):
            raise ValueError("report model must be a mapping")
        generated_at = datetime.fromisoformat(str(model["generated_at"]))
        slug = generated_at.strftime("%Y%m%dT%H%M%S%fZ")
        json_name = f"report_{slug}.json"
        html_name = f"report_{slug}.html"
        json_bytes = json.dumps(model, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        html_bytes = self._render_html(model).encode("utf-8")
        reports_directory = (self._case_root / manifest.case_id / "reports").resolve()
        if self._case_root not in reports_directory.parents:
            raise ValueError("report path escaped case root")
        json_path = reports_directory / json_name
        html_path = reports_directory / html_name
        self._vault.create_case(manifest)
        json_artifact = self._vault.store_bytes(
            case_id=manifest.case_id,
            filename=json_name,
            content=json_bytes,
            original_source="report-engine:json",
            collected_at=generated_at,
            media_type="application/json",
            collector_name="case_report_engine",
            collector_version=REPORT_ENGINE_VERSION,
            execution_id=run_id,
            source_class=SourceClass.LOCAL,
            notes="Private aggregate case report.",
            category="reports",
        )
        html_artifact = self._vault.store_bytes(
            case_id=manifest.case_id,
            filename=html_name,
            content=html_bytes,
            original_source="report-engine:html",
            collected_at=generated_at,
            media_type="text/html",
            collector_name="case_report_engine",
            collector_version=REPORT_ENGINE_VERSION,
            execution_id=run_id,
            source_class=SourceClass.LOCAL,
            notes="Private aggregate case report.",
            category="reports",
        )
        self._atomic_write(json_path, json_bytes)
        self._atomic_write(html_path, html_bytes)
        return ReportReference(
            json_path=str(json_path),
            json_sha256=hashlib.sha256(json_bytes).hexdigest(),
            json_evidence_id=json_artifact.evidence_id,
            html_path=str(html_path),
            html_sha256=hashlib.sha256(html_bytes).hexdigest(),
            html_evidence_id=html_artifact.evidence_id,
        )

    def regenerate(
        self,
        *,
        manifest: CaseManifest,
        run_id: str,
        existing_json_path: str,
    ) -> ReportReference:
        path = Path(existing_json_path).resolve()
        case_directory = (self._case_root / manifest.case_id).resolve()
        reports_directory = (case_directory / "reports").resolve()
        if reports_directory not in path.parents or path.suffix.casefold() != ".json":
            raise ValueError("existing report is outside the case reports directory")
        try:
            model = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("existing JSON report could not be loaded") from error
        if not isinstance(model, dict):
            raise ValueError("existing report must be a JSON object")
        case_payload = model.get("case")
        if not isinstance(case_payload, dict) or case_payload.get("case_id") != manifest.case_id:
            raise ValueError("existing report belongs to another or invalid case")
        model["generated_at"] = self._now().isoformat()
        return self.write(manifest=manifest, run_id=run_id, model=model)

    @staticmethod
    def _limitations(collectors: set[str]) -> list[str]:
        values = [
            "Collector candidates do not confirm identity, ownership, or that two identifiers belong to one person.",
            "NOT_FOUND applies only to the queried source and rule; UNKNOWN remains unresolved.",
        ]
        if "phone_metadata" in collectors:
            values.append("Phone metadata is numbering-plan data, not subscriber identification.")
        if "domain_dns" in collectors:
            values.append("DNS is a point-in-time resolver observation and does not establish ownership.")
        if "username_lookup" in collectors:
            values.append("Matching public usernames are possible profile candidates only.")
        if "email_local_metadata" in collectors:
            values.append("Local email provider lists are explicit, versioned, and intentionally incomplete.")
        if "email_exposure" in collectors:
            values.append("Email exposure uses reviewed public signals and cannot establish account control.")
        return values

    @staticmethod
    def _render_html(model: Mapping[str, object]) -> str:
        case = model["case"]
        summary = model["executive_summary"]
        rows = []
        for execution in model["executions"]:
            rows.append(
                "<tr>"
                f"<td>{escape(str(execution['collector']))}</td>"
                f"<td>{escape(str(execution['source_class']))}</td>"
                f"<td>{escape(str(execution['result']))}</td>"
                f"<td>{escape(', '.join(execution['evidence_refs']))}</td>"
                "</tr>"
            )
        finding_rows = []
        for finding in model["findings"]:
            finding_rows.append(
                "<tr>"
                f"<td>{escape(str(finding['candidate_type']))}</td>"
                f"<td>{escape(str(finding['normalized_status']))}</td>"
                f"<td>{escape(str(finding['source']))}</td>"
                f"<td>{escape(str(finding['notes']))}</td>"
                "</tr>"
            )
        seeds = "".join(
            f"<li>{escape(str(seed['entity_type']))}: {escape(str(seed['value']))}</li>"
            for seed in model["seeds"]
        )
        limitations = "".join(f"<li>{escape(item)}</li>" for item in model["limitations"])
        warnings = "".join(f"<li>{escape(item)}</li>" for item in summary["warnings"]) or "<li>None</li>"
        contradiction = model["contradictions"]
        reasons = "".join(f"<li>{escape(item)}</li>" for item in contradiction["reasons"]) or "<li>None</li>"
        exposure = "".join(
            f"<li>{escape(name)}: {count}</li>"
            for name, count in model["privacy_source_exposure"].items()
        )
        audit = model["audit"]
        return (
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>LUMIR OSINT LAB private case report</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;line-height:1.45}"
            "table{border-collapse:collapse;width:100%}th,td{border:1px solid #bbb;padding:.45rem;text-align:left}"
            "code{overflow-wrap:anywhere}</style></head><body>"
            f"<h1>Private case report: {escape(str(case['case_id']))}</h1>"
            "<h2>Case</h2>"
            f"<p><strong>Name:</strong> {escape(str(case['case_name']))}<br>"
            f"<strong>Purpose:</strong> {escape(str(case['purpose']))}<br>"
            f"<strong>Status:</strong> {escape(str(case['status']))}</p>"
            "<h2>Executive summary</h2>"
            f"<p>Run status: <strong>{escape(str(summary['overall_status']))}</strong>; "
            f"seeds: {summary['seed_count']}; collectors: {summary['collector_count']}; "
            f"successful: {summary['successful_executions']}; partial: {summary['partial_executions']}; "
            f"failed: {summary['failed_executions']}; denied: {summary['denied_executions']}.</p>"
            f"<h3>Warnings</h3><ul>{warnings}</ul>"
            f"<h2>Seeds</h2><ul>{seeds}</ul>"
            "<h2>Executions</h2><table><thead><tr><th>Collector</th><th>Source class</th>"
            f"<th>Result</th><th>Evidence refs</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
            "<h2>Findings</h2><table><thead><tr><th>Candidate</th><th>Status</th>"
            f"<th>Source</th><th>Notes</th></tr></thead><tbody>{''.join(finding_rows)}</tbody></table>"
            f"<h2>Contradictions</h2><p>Severity: {escape(str(contradiction['severity']))}</p><ul>{reasons}</ul>"
            f"<h2>Privacy / source exposure</h2><ul>{exposure}</ul>"
            f"<h2>Limitations</h2><ul>{limitations}</ul>"
            "<h2>Audit</h2>"
            f"<p>Verified: {audit['verified']}; entries: {audit['entry_count']}; "
            f"head: <code>{escape(str(audit['audit_head_hash']))}</code></p>"
            f"<p>{escape(str(model['interpretation_notice']))}</p>"
            "</body></html>"
        )

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("report clock must return a timezone-aware datetime")
        return value
