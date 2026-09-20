"""Application-level case planning and execution through the guarded Orchestrator."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Callable, Iterable, Mapping
from uuid import uuid4

from osint_lab.agents import (
    Collector,
    CollectorRegistry,
    DomainDNSCollector,
    EmailExposureCollector,
    EmailLocalMetadataCollector,
    ExecutionResult,
    PhoneMetadataCollector,
    PhonePublicWebCollector,
    UsernameCollector,
)
from osint_lab.agents.email_exposure import normalize_email
from osint_lab.case_manifest import CaseManifest, SeedEntity
from osint_lab.case_storage import CaseStore
from osint_lab.intelligence import IntelligenceCore, IntelligenceSummary
from osint_lab.orchestrator.audit import AuditLog, AuditVerification, verify_audit_log
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.policies.gate import PolicyDecision, PolicyGate
from osint_lab.reporting import ReportEngine, ReportReference
from osint_lab.schemas import FindingStatus
from osint_lab.verification.contradictions import (
    ContradictionAssertion,
    ContradictionResult,
    detect_contradictions,
)


class CaseRunStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    DENIED = "DENIED"


@dataclass(frozen=True, kw_only=True)
class PlannedStep:
    step_id: str
    seed_reference: str
    seed_type: str
    collector_name: str
    source_class: SourceClass
    reason: str
    execution_order: int
    dependencies: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "seed_reference": self.seed_reference,
            "seed_type": self.seed_type,
            "collector_name": self.collector_name,
            "source_class": self.source_class.value,
            "reason": self.reason,
            "execution_order": self.execution_order,
            "dependencies": list(self.dependencies),
        }


@dataclass(frozen=True, kw_only=True)
class SkippedStep:
    seed_reference: str
    seed_type: str
    collector_name: str | None
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "seed_reference": self.seed_reference,
            "seed_type": self.seed_type,
            "collector_name": self.collector_name,
            "reason": self.reason,
        }


@dataclass(frozen=True, kw_only=True)
class CaseExecutionPlan:
    case_id: str
    created_at: datetime
    requested_seed_types: tuple[str, ...]
    planned_steps: tuple[PlannedStep, ...]
    skipped_steps: tuple[SkippedStep, ...]
    denied_steps: tuple[PlannedStep, ...]
    warnings: tuple[str, ...]
    available_collectors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "created_at": self.created_at.isoformat(),
            "requested_seed_types": list(self.requested_seed_types),
            "planned_steps": [step.to_dict() for step in self.planned_steps],
            "skipped_steps": [step.to_dict() for step in self.skipped_steps],
            "denied_steps": [step.to_dict() for step in self.denied_steps],
            "warnings": list(self.warnings),
            "available_collectors": list(self.available_collectors),
        }


@dataclass(frozen=True, kw_only=True)
class CaseExecutionRecord:
    step: PlannedStep
    collector_version: str
    result_status: str
    result: ExecutionResult | None
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "step": self.step.to_dict(),
            "collector_version": self.collector_version,
            "result_status": self.result_status,
            "execution_id": self.result.execution_id if self.result is not None else None,
            "started_at": self.result.started_at.isoformat() if self.result is not None else None,
            "finished_at": self.result.finished_at.isoformat() if self.result is not None else None,
            "errors": list(self.result.errors) if self.result is not None else list(self.errors),
            "receipt": (
                self.result.receipt.to_dict()
                if self.result is not None and self.result.receipt is not None
                else None
            ),
            "observations": [
                {
                    "raw_status": item.raw_status,
                    "value_reference": item.value_reference,
                    "evidence_ref": item.evidence_ref,
                    "notes": item.notes,
                    "payload": dict(item.payload),
                }
                for item in (self.result.observations if self.result is not None else ())
            ],
            "findings": [
                {
                    "candidate_type": item.raw_status,
                    "normalized_status": item.normalized_status.value,
                    "value_reference": item.value_reference,
                    "evidence_ref": item.evidence_ref,
                    "notes": item.notes,
                }
                for item in (self.result.finding_candidates if self.result is not None else ())
            ],
        }


@dataclass(frozen=True, kw_only=True)
class CaseRunResult:
    case_id: str
    run_id: str
    started_at: datetime
    finished_at: datetime
    overall_status: CaseRunStatus
    executions: tuple[CaseExecutionRecord, ...]
    receipts: tuple[object, ...]
    findings_summary: Mapping[str, int]
    contradictions: ContradictionResult
    warnings: tuple[str, ...]
    report_reference: ReportReference | None
    audit_verification: AuditVerification
    intelligence_summary: IntelligenceSummary | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "overall_status": self.overall_status.value,
            "executions": [item.to_dict() for item in self.executions],
            "receipts": [item.to_dict() for item in self.receipts],
            "findings_summary": dict(self.findings_summary),
            "contradictions": {
                "severity": self.contradictions.severity.value,
                "reasons": list(self.contradictions.reasons),
                "evidence_refs": list(self.contradictions.evidence_refs),
            },
            "warnings": list(self.warnings),
            "report_reference": self.report_reference.to_dict() if self.report_reference else None,
            "audit_verification": {
                "valid": self.audit_verification.valid,
                "entry_count": self.audit_verification.entry_count,
                "head_hash": self.audit_verification.head_hash,
                "reason": self.audit_verification.reason,
            },
            "intelligence_summary": (
                self.intelligence_summary.to_dict() if self.intelligence_summary is not None else None
            ),
        }


def build_default_collectors() -> dict[str, Collector]:
    collectors: tuple[Collector, ...] = (
        PhoneMetadataCollector(),
        PhonePublicWebCollector(),
        DomainDNSCollector(),
        UsernameCollector(),
        EmailLocalMetadataCollector(),
        EmailExposureCollector(),
    )
    return {collector.agent_name: collector for collector in collectors}


class CaseRunner:
    """Plan and execute cases without bypassing registry, policy, or Orchestrator."""

    _SEED_COLLECTORS = {
        "PHONE": ("phone_metadata", "phone_public_web"),
        "DOMAIN": ("domain_dns",),
        "USERNAME": ("username_lookup",),
        "EMAIL": ("email_local_metadata", "email_exposure"),
    }

    def __init__(
        self,
        *,
        orchestrator: Orchestrator,
        registry: CollectorRegistry,
        collectors: Mapping[str, Collector],
        case_store: CaseStore,
        report_engine: ReportEngine,
        audit_log: AuditLog,
        clock: Callable[[], datetime],
        id_factory: Callable[[], str] | None = None,
        intelligence_core: IntelligenceCore | None = None,
    ) -> None:
        if not isinstance(orchestrator, Orchestrator):
            raise ValueError("Orchestrator required")
        if not isinstance(registry, CollectorRegistry):
            raise ValueError("CollectorRegistry required")
        if not isinstance(case_store, CaseStore):
            raise ValueError("CaseStore required")
        if not isinstance(report_engine, ReportEngine):
            raise ValueError("ReportEngine required")
        if not isinstance(audit_log, AuditLog):
            raise ValueError("AuditLog required")
        if not callable(clock):
            raise ValueError("clock must be callable")
        copied = dict(collectors)
        if any(name != collector.agent_name for name, collector in copied.items()):
            raise ValueError("collector mapping keys must match agent_name")
        self._orchestrator = orchestrator
        self._registry = registry
        self._collectors = copied
        self._case_store = case_store
        self._report_engine = report_engine
        self._audit_log = audit_log
        self._clock = clock
        self._id_factory = id_factory or (lambda: uuid4().hex)
        self._intelligence_core = intelligence_core or IntelligenceCore(clock=clock)

    def plan(
        self,
        manifest: CaseManifest,
        *,
        seeds: Iterable[SeedEntity] | None = None,
        include_email_domain_dns: bool = True,
        persist: bool = True,
    ) -> CaseExecutionPlan:
        if not isinstance(manifest, CaseManifest):
            raise ValueError("validated CaseManifest required")
        seed_values = tuple(manifest.seed_entities if seeds is None else seeds)
        if any(not isinstance(seed, SeedEntity) for seed in seed_values):
            raise ValueError("seeds must contain only SeedEntity values")

        planned: list[PlannedStep] = []
        denied: list[PlannedStep] = []
        skipped: list[SkippedStep] = []
        warnings: list[str] = []
        requested_types: list[str] = []
        seen_seeds: set[tuple[str, str]] = set()
        scheduled: set[tuple[str, str]] = set()
        available = self._available_collectors()
        order = 0

        def add_candidate(
            *,
            seed_reference: str,
            seed_type: str,
            collector_name: str,
            reason: str,
            dependencies: tuple[str, ...] = (),
        ) -> PlannedStep | None:
            nonlocal order
            key = (collector_name, seed_reference)
            if key in scheduled:
                warnings.append(f"duplicate planned step skipped: {collector_name} for {seed_type}")
                return None
            collector = self._collectors.get(collector_name)
            if collector is None:
                skipped.append(SkippedStep(
                    seed_reference=seed_reference,
                    seed_type=seed_type,
                    collector_name=collector_name,
                    reason="collector is unavailable",
                ))
                warnings.append(f"collector unavailable: {collector_name}")
                return None
            try:
                self._registry.validate(collector)
                collector.validate_input(seed_reference)
            except Exception as error:
                skipped.append(SkippedStep(
                    seed_reference=seed_reference,
                    seed_type=seed_type,
                    collector_name=collector_name,
                    reason=f"{type(error).__name__}: planning validation failed",
                ))
                warnings.append(f"planning validation failed for {collector_name}")
                return None
            order += 1
            step = PlannedStep(
                step_id=f"step-{order:03d}",
                seed_reference=seed_reference,
                seed_type=seed_type,
                collector_name=collector_name,
                source_class=collector.source_class,
                reason=reason,
                execution_order=order,
                dependencies=dependencies,
            )
            scheduled.add(key)
            policy = PolicyGate.decide(
                manifest,
                agent_type=collector.agent_type,
                source_class=collector.source_class,
            )
            if policy.decision is PolicyDecision.DENY:
                denied.append(PlannedStep(**{**step.__dict__, "reason": policy.reason}))
            else:
                suffix = (
                    " Per-run authorization is required."
                    if policy.decision is PolicyDecision.REQUIRE_EXPLICIT_APPROVAL
                    else ""
                )
                planned.append(PlannedStep(**{**step.__dict__, "reason": f"{reason}{suffix}"}))
            return step

        for seed in seed_values:
            seed_type = seed.entity_type.strip().upper()
            seed_reference = seed.value.strip()
            if seed_type not in requested_types:
                requested_types.append(seed_type)
            seed_key = (seed_type, seed_reference)
            if seed_key in seen_seeds:
                skipped.append(SkippedStep(
                    seed_reference=seed_reference,
                    seed_type=seed_type,
                    collector_name=None,
                    reason="duplicate seed",
                ))
                warnings.append(f"duplicate seed skipped: {seed_type}")
                continue
            seen_seeds.add(seed_key)
            collector_names = self._SEED_COLLECTORS.get(seed_type)
            if collector_names is None:
                skipped.append(SkippedStep(
                    seed_reference=seed_reference,
                    seed_type=seed_type,
                    collector_name=None,
                    reason="unknown seed type",
                ))
                warnings.append(f"unknown seed type: {seed_type}")
                continue
            local_email_step: PlannedStep | None = None
            for collector_name in collector_names:
                step = add_candidate(
                    seed_reference=seed_reference,
                    seed_type=seed_type,
                    collector_name=collector_name,
                    reason=f"MVP mapping {seed_type} -> {collector_name}",
                )
                if collector_name == "email_local_metadata" and step is not None:
                    local_email_step = step
            if seed_type == "EMAIL" and include_email_domain_dns and local_email_step is not None:
                try:
                    _, _, domain = normalize_email(seed_reference)
                except ValueError:
                    continue
                add_candidate(
                    seed_reference=domain,
                    seed_type="DOMAIN",
                    collector_name="domain_dns",
                    reason="Email domain DNS follow-up through a separate orchestration step",
                    dependencies=(local_email_step.step_id,),
                )

        created_at = self._now()
        plan = CaseExecutionPlan(
            case_id=manifest.case_id,
            created_at=created_at,
            requested_seed_types=tuple(requested_types),
            planned_steps=tuple(sorted(planned, key=lambda item: item.execution_order)),
            skipped_steps=tuple(skipped),
            denied_steps=tuple(sorted(denied, key=lambda item: item.execution_order)),
            warnings=tuple(warnings),
            available_collectors=available,
        )
        if persist:
            self._case_store.save_plan(
                case_id=manifest.case_id,
                created_at=created_at,
                payload=plan.to_dict(),
            )
        return plan

    def run(
        self,
        manifest: CaseManifest,
        *,
        seeds: Iterable[SeedEntity] | None = None,
        dry_run: bool = False,
        include_email_domain_dns: bool = True,
        authorization_ids: Mapping[str, str] | None = None,
        contradiction_assertions: Iterable[ContradictionAssertion] = (),
        progress_callback: Callable[[str], None] | None = None,
    ) -> CaseRunResult | CaseExecutionPlan:
        if progress_callback is not None and not callable(progress_callback):
            raise ValueError("progress_callback must be callable")
        plan = self.plan(
            manifest,
            seeds=seeds,
            include_email_domain_dns=include_email_domain_dns,
            persist=True,
        )
        if dry_run:
            return plan
        started_at = self._now()
        run_id = f"case-run-{self._id_factory()}"
        authorizations = dict(authorization_ids or {})
        records: list[CaseExecutionRecord] = []
        warnings = list(plan.warnings)
        completed: dict[str, str] = {}
        steps = sorted(
            (*plan.planned_steps, *plan.denied_steps),
            key=lambda item: item.execution_order,
        )
        denied_step_ids = {step.step_id for step in plan.denied_steps}
        stop_after_failure = False

        for step in steps:
            collector = self._collectors[step.collector_name]
            if step.collector_name == "phone_public_web":
                self._notify(progress_callback, "phone_public:search")
                self._notify(progress_callback, "phone_public:verify")
            else:
                self._notify(progress_callback, f"collector:{step.collector_name}")
            if stop_after_failure:
                record = CaseExecutionRecord(
                    step=step,
                    collector_version=collector.version,
                    result_status="FAILED",
                    result=None,
                    errors=("case execution stopped after a fail-closed infrastructure error",),
                )
                records.append(record)
                completed[step.step_id] = record.result_status
                continue
            if step.step_id not in denied_step_ids and any(
                completed.get(dependency) not in {"SUCCESS", "PARTIAL"}
                for dependency in step.dependencies
            ):
                record = CaseExecutionRecord(
                    step=step,
                    collector_version=collector.version,
                    result_status="FAILED",
                    result=None,
                    errors=("required execution dependency did not complete successfully",),
                )
                records.append(record)
                completed[step.step_id] = record.result_status
                warnings.append(f"dependency prevented {step.collector_name}")
                continue
            try:
                result = self._orchestrator.execute(
                    manifest=manifest,
                    collector=collector,
                    seed_reference=step.seed_reference,
                    purpose=f"CaseRunner {run_id}: {step.reason}",
                    requested_by="case-runner",
                    authorization_id=authorizations.get(step.collector_name),
                )
                record = CaseExecutionRecord(
                    step=step,
                    collector_version=collector.version,
                    result_status=result.status.value,
                    result=result,
                )
            except Exception as error:
                record = CaseExecutionRecord(
                    step=step,
                    collector_version=collector.version,
                    result_status="FAILED",
                    result=None,
                    errors=(f"{type(error).__name__}: orchestrator execution failed closed",),
                )
                warnings.append(f"fail-closed infrastructure error at {step.collector_name}")
                stop_after_failure = True
            records.append(record)
            completed[step.step_id] = record.result_status

        contradiction_values = tuple(contradiction_assertions)
        if any(item.case_id != manifest.case_id for item in contradiction_values):
            raise ValueError("contradiction assertions must belong to the current case")
        contradiction = detect_contradictions(contradiction_values)
        findings_summary = self._finding_counts(records)
        audit_verification = verify_audit_log(self._audit_log, manifest.case_id)
        if not audit_verification.valid:
            warnings.append(f"audit verification failed: {audit_verification.reason}")
        status = self._overall_status(
            records,
            has_denied=bool(plan.denied_steps),
            findings_summary=findings_summary,
            audit_valid=audit_verification.valid,
        )
        finished_at = self._now()
        receipts = tuple(
            record.result.receipt
            for record in records
            if record.result is not None and record.result.receipt is not None
        )
        self._notify(progress_callback, "intelligence")
        intelligence_summary = self._intelligence_core.analyze(
            manifest=manifest,
            executions=records,
            contradiction=contradiction,
        )

        report_reference: ReportReference | None = None
        try:
            self._notify(progress_callback, "report")
            model = self._report_engine.build_model(
                manifest=manifest,
                run_id=run_id,
                started_at=started_at,
                finished_at=finished_at,
                overall_status=status.value,
                executions=records,
                findings_summary=findings_summary,
                contradiction=contradiction,
                warnings=warnings,
                audit_verification=audit_verification,
                intelligence_summary=intelligence_summary,
            )
            report_reference = self._report_engine.write(
                manifest=manifest,
                run_id=run_id,
                model=model,
            )
        except Exception as error:
            warnings.append(f"{type(error).__name__}: required report write failed")
            status = CaseRunStatus.PARTIAL if self._has_success(records) else CaseRunStatus.FAILED

        result = CaseRunResult(
            case_id=manifest.case_id,
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            overall_status=status,
            executions=tuple(records),
            receipts=receipts,
            findings_summary=findings_summary,
            contradictions=contradiction,
            warnings=tuple(warnings),
            report_reference=report_reference,
            audit_verification=audit_verification,
            intelligence_summary=intelligence_summary,
        )
        try:
            self._case_store.save_run_summary(
                case_id=manifest.case_id,
                finished_at=finished_at,
                payload=result.to_dict(),
            )
        except Exception as error:
            degraded = CaseRunStatus.PARTIAL if self._has_success(records) else CaseRunStatus.FAILED
            result = CaseRunResult(
                **{
                    **result.__dict__,
                    "overall_status": degraded,
                    "warnings": (*result.warnings, f"{type(error).__name__}: run summary write failed"),
                }
            )
        return result

    def regenerate_latest_report(self, case_id: str) -> ReportReference:
        manifest = self._case_store.load(case_id)
        summary = self._case_store.latest_run_summary(case_id)
        reference = summary.get("report_reference")
        if not isinstance(reference, dict) or not isinstance(reference.get("json_path"), str):
            raise ValueError("latest run has no reusable JSON report")
        return self._report_engine.regenerate(
            manifest=manifest,
            run_id=f"report-{self._id_factory()}",
            existing_json_path=reference["json_path"],
        )

    def _available_collectors(self) -> tuple[str, ...]:
        values: list[str] = []
        for name, collector in sorted(self._collectors.items()):
            try:
                self._registry.validate(collector)
            except (PermissionError, ValueError):
                continue
            values.append(name)
        return tuple(values)

    @staticmethod
    def _finding_counts(records: Iterable[CaseExecutionRecord]) -> dict[str, int]:
        counts = {status.value: 0 for status in FindingStatus}
        for record in records:
            if record.result is None:
                continue
            for candidate in record.result.finding_candidates:
                counts[candidate.normalized_status.value] += 1
        return counts

    @classmethod
    def _overall_status(
        cls,
        records: list[CaseExecutionRecord],
        *,
        has_denied: bool,
        findings_summary: Mapping[str, int],
        audit_valid: bool,
    ) -> CaseRunStatus:
        if not records:
            return CaseRunStatus.DENIED if has_denied else CaseRunStatus.FAILED
        statuses = [record.result_status for record in records]
        if all(status == "DENIED" for status in statuses):
            return CaseRunStatus.DENIED
        has_success = cls._has_success(records)
        if not has_success:
            return CaseRunStatus.FAILED
        if (
            all(status == "SUCCESS" for status in statuses)
            and not has_denied
            and findings_summary.get(FindingStatus.UNKNOWN.value, 0) == 0
            and audit_valid
        ):
            return CaseRunStatus.SUCCESS
        return CaseRunStatus.PARTIAL

    @staticmethod
    def _has_success(records: Iterable[CaseExecutionRecord]) -> bool:
        return any(record.result_status in {"SUCCESS", "PARTIAL"} for record in records)

    @staticmethod
    def _notify(callback: Callable[[str], None] | None, event: str) -> None:
        if callback is None:
            return
        try:
            callback(event)
        except Exception:
            return

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("CaseRunner clock must return a timezone-aware datetime")
        return value
