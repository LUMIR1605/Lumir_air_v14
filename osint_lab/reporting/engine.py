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
from osint_lab.intelligence import IntelligenceSummary
from osint_lab.orchestrator.audit import AuditVerification
from osint_lab.policies import SourceClass
from osint_lab.verification.contradictions import ContradictionResult


REPORT_ENGINE_VERSION = "1.5.0"

_PHONE_DETAIL_FIELDS = (
    ("normalized_e164", "Numer znormalizowany E.164"),
    ("international_format", "Format międzynarodowy"),
    ("national_format", "Format krajowy"),
    ("country_code", "Kod kraju"),
    ("region_code", "Region"),
    ("possible", "Czy numer możliwy"),
    ("valid", "Czy numer poprawny"),
    ("number_type", "Typ numeru"),
    ("carrier_name", "Operator / carrier metadata"),
    ("geographic_description", "Opis geograficzny"),
    ("timezones", "Strefy czasowe"),
)
_NO_LOCAL_DATA = "Brak danych lokalnych"
_PHONE_METADATA_NOTICE = (
    "Dane planu numeracyjnego — nie potwierdzają aktualnego operatora, "
    "właściciela ani lokalizacji osoby."
)


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
        intelligence_summary: IntelligenceSummary | None = None,
        graph_bundle: Mapping[str, object] | None = None,
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
                "observations": [
                    {
                        "raw_status": observation.raw_status,
                        "value_reference": observation.value_reference,
                        "evidence_ref": observation.evidence_ref,
                        "notes": observation.notes,
                        "payload": dict(observation.payload),
                    }
                    for observation in (result.observations if result is not None else ())
                ],
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
        analytical_assessment = (
            intelligence_summary.to_dict() if intelligence_summary is not None
            else IntelligenceSummary().to_dict()
        )
        phone_public_intelligence = self._phone_public_summary(
            execution_payloads,
            analytical_assessment,
        )
        return {
            "schema_version": "1.5",
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
            "analytical_assessment": analytical_assessment,
            "phone_public_intelligence": phone_public_intelligence,
            "graph_intelligence": dict(graph_bundle or {}),
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
        if "phone_public_web" in collectors:
            values.append(
                "Phone public-web matches are public occurrences and possible associations, not subscriber identity."
            )
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
        phone_details = ReportEngine._render_phone_details(model["executions"])
        phone_public = ReportEngine._render_phone_public_intelligence(
            model.get("phone_public_intelligence", {})
        )
        analytical_assessment = ReportEngine._render_analytical_assessment(
            model.get("analytical_assessment", {})
        )
        graph_intelligence = ReportEngine._render_graph_intelligence(model.get("graph_intelligence", {}))
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
            f"{phone_details}"
            f"{phone_public}"
            f"{analytical_assessment}"
            f"{graph_intelligence}"
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
    def _render_graph_intelligence(value: object) -> str:
        data = value if isinstance(value, Mapping) else {}
        dossier = data.get("dossier") if isinstance(data.get("dossier"), Mapping) else {}
        if not dossier:
            return ""

        def rows(values: object, fields: tuple[str, ...]) -> str:
            if not isinstance(values, list) or not values:
                return "<li>None</li>"
            rendered = []
            for item in values:
                if isinstance(item, Mapping):
                    rendered.append("<li>" + escape(" | ".join(
                        f"{field}: {item.get(field)}" for field in fields if item.get(field) is not None
                    )) + "</li>")
                else:
                    rendered.append(f"<li>{escape(str(item))}</li>")
            return "".join(rendered)

        entities = rows(dossier.get("key_entities"), ("entity_type", "display_value", "confidence", "status"))
        relations = rows(dossier.get("key_relations"), ("relation_type", "confidence", "status", "evidence_refs"))
        paths = rows(dossier.get("important_paths"), ("explanation", "confidence", "evidence_refs"))
        hypotheses = rows(dossier.get("hypotheses"), ("statement", "status", "confidence"))
        contradictions = rows(dossier.get("contradictions"), ())
        pivots = rows(dossier.get("recommended_pivots"),
                      ("proposed_enricher", "graph_value", "status", "reason"))
        timeline = rows(dossier.get("timeline"), ("event_type", "timestamp", "description", "evidence_refs"))
        return (
            "<section><h2>ANALYST VIEW</h2>"
            f"<h3>KEY ENTITIES</h3><ul>{entities}</ul>"
            f"<h3>KEY RELATIONS</h3><ul>{relations}</ul>"
            f"<h3>IMPORTANT PATHS</h3><ul>{paths}</ul>"
            f"<h3>OPEN HYPOTHESES</h3><ul>{hypotheses}</ul>"
            f"<h3>CONTRADICTIONS</h3><ul>{contradictions}</ul>"
            f"<h3>TIMELINE</h3><ul>{timeline}</ul>"
            f"<h3>NEXT BEST PIVOTS</h3><ul>{pivots}</ul></section>"
        )

    @staticmethod
    def _render_phone_details(executions: Iterable[object]) -> str:
        sections: list[str] = []
        for execution in executions:
            if not isinstance(execution, Mapping) or execution.get("collector") != "phone_metadata":
                continue
            payload: Mapping[str, object] = {}
            observations = execution.get("observations")
            if isinstance(observations, list) and observations and isinstance(observations[0], Mapping):
                candidate = observations[0].get("payload")
                if isinstance(candidate, Mapping):
                    payload = candidate
            detail_rows = "".join(
                "<tr>"
                f"<th>{escape(label)}</th>"
                f"<td>{escape(ReportEngine._display_phone_value(payload.get(key)))}</td>"
                "</tr>"
                for key, label in _PHONE_DETAIL_FIELDS
            )
            sections.append(
                "<section><h2>Szczegóły techniczne numeru</h2>"
                f"<p><strong>{escape(_PHONE_METADATA_NOTICE)}</strong></p>"
                f"<table><tbody>{detail_rows}</tbody></table></section>"
            )
        return "".join(sections)

    @staticmethod
    def _phone_public_summary(
        executions: list[dict[str, object]],
        assessment: Mapping[str, object],
    ) -> dict[str, object]:
        observations: list[Mapping[str, object]] = []
        applicable = False
        for execution in executions:
            if execution.get("collector") != "phone_public_web":
                continue
            applicable = True
            values = execution.get("observations")
            if isinstance(values, list):
                observations.extend(item for item in values if isinstance(item, Mapping))
        providers: set[str] = set()
        status_counts = {name: 0 for name in ("MATCH", "NO_MATCH", "UNKNOWN", "ERROR")}
        match_level_counts = {
            name: 0 for name in (
                "SEARCH_DISCOVERY_ONLY", "NUMERIC_MATCH", "NUMERIC_MATCH_ONLY",
                "PHONE_CONTEXT_MATCH", "STRUCTURED_PHONE_MATCH", "REJECTED_NUMERIC_ID", "UNKNOWN",
            )
        }
        urls: set[str] = set()
        domains: set[str] = set()
        variants: set[str] = set()
        entities: list[object] = []
        evidence_refs: set[str] = set()
        false_positives: list[dict[str, object]] = []
        discovery_rows: list[dict[str, object]] = []
        verified_targets: list[dict[str, object]] = []
        rejected_targets: list[dict[str, object]] = []
        phone_signals: list[dict[str, object]] = []
        for observation in observations:
            payload = observation.get("payload")
            if not isinstance(payload, Mapping):
                continue
            provider_id = payload.get("provider_id")
            if isinstance(provider_id, str):
                providers.add(provider_id)
            channels = payload.get("discovery_channels")
            if isinstance(channels, list):
                for channel in channels:
                    if isinstance(channel, Mapping):
                        discovery_rows.append(dict(channel))
                        channel_provider = channel.get("provider_id")
                        if isinstance(channel_provider, str):
                            providers.add(channel_provider)
            elif payload.get("stage") == "SEARCH_DISCOVERY":
                discovery_rows.append({
                    "provider_id": provider_id,
                    "query_variant": payload.get("query_variant"),
                    "request_url": payload.get("request_url"),
                    "status": payload.get("status"),
                    "error_code": payload.get("error_code"),
                })
            status = payload.get("status")
            if isinstance(status, str) and status in status_counts:
                status_counts[status] += 1
            match_level = payload.get("match_level")
            if isinstance(match_level, str) and match_level in match_level_counts:
                match_level_counts[match_level] += 1
            accepted_semantic_match = (
                status == "MATCH"
                and match_level in {"PHONE_CONTEXT_MATCH", "STRUCTURED_PHONE_MATCH"}
            )
            if accepted_semantic_match:
                for key, target in (
                    ("result_url", urls), ("source_domain", domains), ("matched_variant", variants),
                ):
                    value = payload.get(key)
                    if isinstance(value, str) and value:
                        target.add(value)
                discovered = payload.get("discovered_entities")
                if isinstance(discovered, list):
                    entities.extend(item for item in discovered if isinstance(item, Mapping))
            evidence_ref = observation.get("evidence_ref")
            if isinstance(evidence_ref, str) and evidence_ref:
                evidence_refs.add(evidence_ref)
            if match_level == "REJECTED_NUMERIC_ID":
                false_positives.append({
                    "result_url": payload.get("result_url"),
                    "source_domain": payload.get("source_domain"),
                    "matched_variant": payload.get("matched_variant"),
                    "match_location": payload.get("match_location"),
                    "reason": payload.get("semantic_reason") or payload.get("error_reason"),
                    "evidence_ref": evidence_ref,
                })
            if payload.get("stage") == "TARGET_PAGE_VALIDATION":
                target_fetch = payload.get("target_fetch") if isinstance(payload.get("target_fetch"), Mapping) else {}
                target_row = {
                    "url": payload.get("target_canonical_url") or payload.get("result_url"),
                    "domain": payload.get("target_domain") or payload.get("source_domain"),
                    "page_role": payload.get("page_role"),
                    "phone_match_type": payload.get("target_match_type") or match_level,
                    "signal_type": payload.get("target_signal_type"),
                    "context": payload.get("context_snippet"),
                    "source_date": payload.get("source_date"),
                    "source_date_warning": payload.get("source_date_warning"),
                    "evidence_ref": evidence_ref,
                    "fetch_status": target_fetch.get("fetch_status"),
                    "error_code": payload.get("error_code") or target_fetch.get("error_code"),
                    "reason": payload.get("semantic_reason") or payload.get("error_reason"),
                }
                if accepted_semantic_match:
                    verified_targets.append(target_row)
                    phone_signals.append({
                        "target_url": target_row["url"],
                        "match_type": target_row["phone_match_type"],
                        "signal_type": target_row["signal_type"],
                        "signal_path": payload.get("signal_path"),
                        "normalized_phone": payload.get("normalized_phone"),
                        "raw_visible_value": payload.get("raw_visible_value"),
                        "context_before": payload.get("context_before"),
                        "matched_text": payload.get("matched_text"),
                        "context_after": payload.get("context_after"),
                        "evidence_ref": evidence_ref,
                    })
                else:
                    rejected_targets.append(target_row)

        quality_values = assessment.get("evidence_quality")
        quality = [
            item for item in quality_values
            if isinstance(item, Mapping) and item.get("source_name") == "phone_public_web"
        ] if isinstance(quality_values, list) else []
        quality_by_ref = {
            item.get("evidence_id"): item.get("quality_score") for item in quality
            if isinstance(item.get("evidence_id"), str)
        }
        for item in (*verified_targets, *rejected_targets):
            item["evidence_quality"] = quality_by_ref.get(item.get("evidence_ref"))
        correlations_values = assessment.get("probable_correlations")
        correlations = [
            item for item in correlations_values
            if isinstance(item, Mapping)
            and bool(set(item.get("evidence_refs", [])) & evidence_refs)
        ] if isinstance(correlations_values, list) else []
        correlation_refs = {
            ref for item in correlations for ref in item.get("evidence_refs", []) if isinstance(ref, str)
        }
        hypotheses_values = assessment.get("open_hypotheses")
        hypotheses = [
            item for item in hypotheses_values
            if isinstance(item, Mapping)
            and bool(set(item.get("evidence_for", [])) & correlation_refs)
        ] if isinstance(hypotheses_values, list) else []
        hypothesis_ids = {item.get("hypothesis_id") for item in hypotheses}
        review_values = assessment.get("adversarial_reviews")
        reviews = [
            item for item in review_values
            if isinstance(item, Mapping) and item.get("hypothesis_id") in hypothesis_ids
        ] if isinstance(review_values, list) else []
        alternatives = sorted({
            str(value)
            for item in hypotheses
            for value in item.get("alternative_explanations", [])
        } | {
            str(value)
            for item in reviews
            for value in item.get("alternative_explanations", [])
        })
        pivot_values = assessment.get("recommended_next_pivots")
        pivots = [
            item for item in pivot_values
            if isinstance(item, Mapping)
            and item.get("proposed_collector") in {
                "phone_public_web", "email_local_metadata", "email_exposure", "domain_dns", "username_lookup",
                "company_web_research",
            }
        ] if isinstance(pivot_values, list) else []
        unique_entities = {
            (str(item.get("entity_type")), str(item.get("value")), str(item.get("source_url"))): item
            for item in entities
        }
        return {
            "applicable": applicable,
            "provider_count": len(providers),
            "providers": sorted(providers),
            "status_counts": status_counts,
            "match_level_counts": match_level_counts,
            "public_urls": sorted(urls),
            "source_domains": sorted(domains),
            "matched_variants": sorted(variants),
            "discovered_entities": list(unique_entities.values()),
            "evidence_refs": sorted(evidence_refs),
            "source_independence_groups": sorted({
                str(item.get("independence_group")) for item in quality if item.get("independence_group")
            }),
            "evidence_quality": quality,
            "correlations": correlations,
            "hypotheses": hypotheses,
            "alternative_explanations": alternatives,
            "recommended_pivots": pivots,
            "false_positives_rejected": false_positives,
            "search_discovery": list({
                json.dumps(item, ensure_ascii=False, sort_keys=True, default=str): item
                for item in discovery_rows
            }.values()),
            "target_pages_checked": len(verified_targets) + len(rejected_targets),
            "target_pages_verified": verified_targets,
            "target_pages_rejected": rejected_targets,
            "phone_signals": phone_signals,
            "exposure_notice": (
                "PASSIVE_WEB providers received searched phone variants. Public occurrence. Possible association. "
                "Not independently verified subscriber identity or ownership."
            ),
        }

    @staticmethod
    def _render_phone_public_intelligence(value: object) -> str:
        data = value if isinstance(value, Mapping) else {}
        if data.get("applicable") is not True:
            return ""

        def items(values: object, formatter=str) -> str:
            if not isinstance(values, list) or not values:
                return "<li>None</li>"
            return "".join(f"<li>{escape(formatter(item))}</li>" for item in values)

        counts = data.get("status_counts") if isinstance(data.get("status_counts"), Mapping) else {}
        status_text = ", ".join(
            f"{name}: {escape(str(counts.get(name, 0)))}" for name in ("MATCH", "NO_MATCH", "UNKNOWN", "ERROR")
        )
        entities = items(
            data.get("discovered_entities"),
            lambda item: (
                f"{item.get('entity_type', 'OTHER')}: {item.get('value', '')} "
                f"(confidence {item.get('confidence', '')})"
            ) if isinstance(item, Mapping) else str(item),
        )
        quality = items(
            data.get("evidence_quality"),
            lambda item: (
                f"{item.get('evidence_id', '')}: score {item.get('quality_score', '')}, "
                f"group {item.get('independence_group', '')}"
            ) if isinstance(item, Mapping) else str(item),
        )
        correlations = items(
            data.get("correlations"),
            lambda item: (
                f"{item.get('status', 'UNKNOWN')} {item.get('relation_type', '')} "
                f"(confidence {item.get('confidence', '')})"
            ) if isinstance(item, Mapping) else str(item),
        )
        hypotheses = items(
            data.get("hypotheses"),
            lambda item: f"{item.get('status', 'OPEN')}: {item.get('statement', '')}"
            if isinstance(item, Mapping) else str(item),
        )
        pivots = items(
            data.get("recommended_pivots"),
            lambda item: f"{item.get('status', '')}: {item.get('proposed_collector', '')}"
            if isinstance(item, Mapping) else str(item),
        )
        false_positives = items(
            data.get("false_positives_rejected"),
            lambda item: (
                f"{item.get('result_url') or item.get('source_domain') or 'Public result'} — "
                f"{item.get('reason', 'Numeric identifier rejected.')}"
            ) if isinstance(item, Mapping) else str(item),
        )
        discovery = items(
            data.get("search_discovery"),
            lambda item: (
                f"{item.get('provider_id', '')}: {item.get('result_url') or item.get('request_url') or ''} "
                f"[{item.get('query_variant') or item.get('status') or ''}]"
            ) if isinstance(item, Mapping) else str(item),
        )
        verified_targets = items(
            data.get("target_pages_verified"),
            lambda item: (
                f"{item.get('url', '')} — {item.get('page_role', 'UNKNOWN')}; "
                f"{item.get('phone_match_type', '')}/{item.get('signal_type', '')}; "
                f"quality {item.get('evidence_quality', '')}; source date {item.get('source_date', 'UNKNOWN')}; "
                f"context: {item.get('context') or 'None'}; evidence: {item.get('evidence_ref', '')}"
            ) if isinstance(item, Mapping) else str(item),
        )
        rejected_targets = items(
            data.get("target_pages_rejected"),
            lambda item: (
                f"{item.get('url', '')} — {item.get('phone_match_type', 'UNKNOWN')}; "
                f"{item.get('reason') or item.get('error_code') or 'Not verified'}"
            ) if isinstance(item, Mapping) else str(item),
        )
        signals = items(
            data.get("phone_signals"),
            lambda item: (
                f"{item.get('match_type', '')}/{item.get('signal_type', '')}: "
                f"{item.get('context_before') or ''} {item.get('matched_text') or item.get('raw_visible_value') or ''} "
                f"{item.get('context_after') or ''}"
            ) if isinstance(item, Mapping) else str(item),
        )
        return (
            "<section><h2>PHONE PUBLIC INTELLIGENCE</h2>"
            f"<p>{escape(str(data.get('exposure_notice', '')))}</p>"
            f"<p>Providers: {escape(str(data.get('provider_count', 0)))}; {status_text}</p>"
            f"<h3>SEARCH DISCOVERY</h3><ul>{discovery}</ul>"
            f"<h3>TARGET PAGES VERIFIED</h3><ul>{verified_targets}</ul>"
            f"<h3>TARGET PAGES REJECTED</h3><ul>{rejected_targets}</ul>"
            f"<h3>PHONE SIGNALS</h3><ul>{signals}</ul>"
            f"<h3>DISCOVERED ENTITIES</h3><ul>{entities}</ul>"
            f"<h3>SOURCE INDEPENDENCE</h3><ul>{items(data.get('source_independence_groups'))}</ul>"
            f"<h3>EVIDENCE QUALITY</h3><ul>{quality}</ul>"
            f"<h3>CORRELATIONS</h3><ul>{correlations}</ul>"
            f"<h3>HYPOTHESES</h3><ul>{hypotheses}</ul>"
            f"<h3>ALTERNATIVE EXPLANATIONS</h3><ul>{items(data.get('alternative_explanations'))}</ul>"
            f"<h3>RECOMMENDED PIVOTS</h3><ul>{pivots}</ul>"
            f"<h3>FALSE POSITIVES REJECTED</h3><ul>{false_positives}</ul></section>"
        )

    @staticmethod
    def _render_analytical_assessment(assessment: object) -> str:
        value = assessment if isinstance(assessment, Mapping) else {}

        def text_list(items: object, formatter) -> str:
            if not isinstance(items, list) or not items:
                return "<li>None</li>"
            return "".join(f"<li>{escape(formatter(item))}</li>" for item in items)

        facts = text_list(
            value.get("known_technical_facts"),
            lambda item: "FACT — " + str(item.get("statement", "")) if isinstance(item, Mapping) else str(item),
        )
        correlations = text_list(
            value.get("probable_correlations"),
            lambda item: (
                "CORRELATION — " + str(item.get("status", "UNKNOWN")) + ": "
                + str(item.get("relation_type", "")) + " (confidence " + str(item.get("confidence", "")) + ")"
            ) if isinstance(item, Mapping) else str(item),
        )
        hypotheses = text_list(
            value.get("open_hypotheses"),
            lambda item: (
                "HYPOTHESIS — " + str(item.get("status", "OPEN")) + ": " + str(item.get("statement", ""))
            ) if isinstance(item, Mapping) else str(item),
        )
        contradictions = text_list(value.get("contradictory_evidence"), str)
        alternatives = text_list(value.get("alternative_explanations"), str)
        pivots = text_list(
            value.get("recommended_next_pivots"),
            lambda item: (
                str(item.get("status", "")) + " — " + str(item.get("proposed_collector", ""))
                + " (information gain " + str(item.get("expected_information_gain", "")) + ")"
            ) if isinstance(item, Mapping) else str(item),
        )
        questions = text_list(value.get("unresolved_questions"), str)
        reviews = text_list(
            value.get("adversarial_reviews"),
            lambda item: (
                "VERIFICATION — " + str(item.get("result", "UNTESTED")) + ": "
                + "; ".join(str(part) for part in item.get("challenges", []))
            ) if isinstance(item, Mapping) else str(item),
        )
        quality = value.get("evidence_quality_summary")
        if isinstance(quality, Mapping):
            quality_text = (
                f"Evidence: {escape(str(quality.get('evidence_count', 0)))}; independent groups: "
                f"{escape(str(quality.get('independent_group_count', 0)))}; average score: "
                f"{escape(str(quality.get('average_quality_score', 0)))}."
            )
        else:
            quality_text = "No assessed evidence."
        return (
            "<section><h2>ANALYTICAL ASSESSMENT</h2>"
            f"<h3>Known technical facts</h3><ul>{facts}</ul>"
            f"<h3>Probable correlations</h3><ul>{correlations}</ul>"
            f"<h3>Open hypotheses</h3><ul>{hypotheses}</ul>"
            f"<h3>Contradictory evidence</h3><ul>{contradictions}</ul>"
            f"<h3>Evidence quality</h3><p>{quality_text}</p>"
            f"<h3>Alternative explanations</h3><ul>{alternatives}</ul>"
            f"<h3>Adversarial verification</h3><ul>{reviews}</ul>"
            f"<h3>Recommended next pivots</h3><ul>{pivots}</ul>"
            f"<h3>Unresolved questions</h3><ul>{questions}</ul></section>"
        )

    @staticmethod
    def _display_phone_value(value: object) -> str:
        if value is None or value == "" or value == []:
            return _NO_LOCAL_DATA
        if isinstance(value, bool):
            return "Tak" if value else "Nie"
        if isinstance(value, list):
            return ", ".join(str(item) for item in value) or _NO_LOCAL_DATA
        return str(value)

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
