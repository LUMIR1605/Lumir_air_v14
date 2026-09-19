"""Policy-enforcing orchestrator; the only public collector execution path."""

from collections.abc import Callable
from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4

from osint_lab.agents.base import (
    Collector,
    ExecutionResult,
    ExecutionStatus,
    FindingCandidate,
    RawObservation,
)
from osint_lab.agents.registry import CollectorMetadata, CollectorRegistry
from osint_lab.case_manifest import CaseManifest
from osint_lab.evidence import EvidenceVault
from osint_lab.policies.gate import PolicyDecision, PolicyGate

from .audit import AuditEntry, AuditEventType, AuditLog
from .authorization import AuthorizationCheck
from .authorization_store import AuthorizationStore
from .context import _create_execution_context
from .receipt import ExecutionReceipt


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _reference_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class Orchestrator:
    """Execute a collector only after policy, authorization and audit checks."""

    def __init__(
        self,
        *,
        audit_log: AuditLog,
        authorization_store: AuthorizationStore,
        collector_registry: CollectorRegistry,
        evidence_vault: EvidenceVault,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(audit_log, AuditLog):
            raise ValueError("AuditLog required")
        if not isinstance(authorization_store, AuthorizationStore):
            raise ValueError("AuthorizationStore required")
        if not isinstance(collector_registry, CollectorRegistry):
            raise ValueError("CollectorRegistry required")
        if not isinstance(evidence_vault, EvidenceVault):
            raise ValueError("EvidenceVault required")
        self._audit_log = audit_log
        self._authorization_store = authorization_store
        self._collector_registry = collector_registry
        self._evidence_vault = evidence_vault
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def execute(
        self,
        *,
        manifest: CaseManifest,
        collector: Collector,
        seed_reference: str,
        purpose: str,
        requested_by: str,
        authorization_id: str | None = None,
    ) -> ExecutionResult:
        if not isinstance(manifest, CaseManifest):
            raise ValueError("validated CaseManifest required")
        if not isinstance(collector, Collector):
            raise ValueError("Collector required")
        for name, value in (
            ("seed_reference", seed_reference),
            ("purpose", purpose),
            ("requested_by", requested_by),
        ):
            _require_text(name, value)
        if authorization_id is not None:
            _require_text("authorization_id", authorization_id)

        registry_metadata = self._collector_registry.validate(collector)
        execution_id = f"run-{uuid4().hex}"
        started_at = self._now()
        private_metadata = {
            "seed_reference_sha256": _reference_hash(seed_reference),
            "purpose_sha256": _reference_hash(purpose),
            "requested_by_sha256": _reference_hash(requested_by),
        }
        self._audit(
            manifest=manifest,
            collector=collector,
            execution_id=execution_id,
            authorization_id=authorization_id,
            event_type=AuditEventType.RUN_REQUESTED,
            decision="PENDING",
            message="Collector run requested.",
            metadata=private_metadata,
        )

        policy = PolicyGate.decide(
            manifest,
            agent_type=collector.agent_type,
            source_class=collector.source_class,
        )
        self._audit(
            manifest=manifest,
            collector=collector,
            execution_id=execution_id,
            authorization_id=authorization_id,
            event_type=AuditEventType.POLICY_EVALUATED,
            decision=policy.decision.value,
            message=policy.reason,
            metadata={},
        )
        if policy.decision is PolicyDecision.DENY:
            return self._deny(
                manifest=manifest,
                collector=collector,
                execution_id=execution_id,
                authorization_id=authorization_id,
                started_at=started_at,
                reason=policy.reason,
            )

        checked_authorization_id: str | None = None
        if policy.decision is PolicyDecision.REQUIRE_EXPLICIT_APPROVAL:
            check = self._check_authorization(
                authorization_id=authorization_id,
                manifest=manifest,
                collector=collector,
            )
            checked_authorization_id = authorization_id
            self._audit(
                manifest=manifest,
                collector=collector,
                execution_id=execution_id,
                authorization_id=checked_authorization_id,
                event_type=AuditEventType.AUTHORIZATION_CHECKED,
                decision="APPROVED" if check.valid else "DENIED",
                message=check.reason,
                metadata={},
            )
            if not check.valid:
                return self._deny(
                    manifest=manifest,
                    collector=collector,
                    execution_id=execution_id,
                    authorization_id=checked_authorization_id,
                    started_at=started_at,
                    reason=check.reason,
                )
        else:
            self._audit(
                manifest=manifest,
                collector=collector,
                execution_id=execution_id,
                authorization_id=None,
                event_type=AuditEventType.AUTHORIZATION_CHECKED,
                decision="NOT_REQUIRED",
                message="PolicyGate allowed this source class without per-run approval.",
                metadata={},
            )

        self._audit(
            manifest=manifest,
            collector=collector,
            execution_id=execution_id,
            authorization_id=checked_authorization_id,
            event_type=AuditEventType.RUN_ALLOWED,
            decision="ALLOW",
            message="All required execution controls passed.",
            metadata={},
        )
        context = _create_execution_context(
            case_id=manifest.case_id,
            execution_id=execution_id,
            authorization_id=checked_authorization_id,
            agent_name=collector.agent_name,
            source_class=collector.source_class,
            started_at=started_at,
            purpose=purpose,
            seed_reference=seed_reference,
        )
        self._audit(
            manifest=manifest,
            collector=collector,
            execution_id=execution_id,
            authorization_id=checked_authorization_id,
            event_type=AuditEventType.AGENT_STARTED,
            decision="ALLOW",
            message="Collector execution started.",
            metadata={},
        )

        try:
            observations = collector.run(context, seed_reference)
            candidates, errors = self._normalize(collector, observations)
            if errors and candidates:
                status = ExecutionStatus.PARTIAL
            elif errors:
                status = ExecutionStatus.FAILED
            else:
                status = ExecutionStatus.SUCCESS
        except Exception as error:
            observations = ()
            candidates = ()
            errors = (f"{type(error).__name__}: collector execution failed",)
            status = ExecutionStatus.FAILED
        finished_at = self._now()
        return self._persist_and_publish(
            manifest=manifest,
            collector=collector,
            registry_metadata=registry_metadata,
            execution_id=execution_id,
            authorization_id=checked_authorization_id,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            errors=errors,
            observations=observations,
            candidates=candidates,
            private_metadata=private_metadata,
        )

    def _persist_and_publish(
        self,
        *,
        manifest: CaseManifest,
        collector: Collector,
        registry_metadata: CollectorMetadata,
        execution_id: str,
        authorization_id: str | None,
        started_at: datetime,
        finished_at: datetime,
        status: ExecutionStatus,
        errors: tuple[str, ...],
        observations: tuple[RawObservation, ...],
        candidates: tuple[FindingCandidate, ...],
        private_metadata: dict[str, str],
    ) -> ExecutionResult:
        verification = self._audit_log.verify(manifest.case_id)
        if not verification.valid:
            raise OSError(f"audit hash chain verification failed: {verification.reason}")
        record = {
            "execution_metadata": {
                "execution_id": execution_id,
                "case_id": manifest.case_id,
                "collector": collector.agent_name,
                "collector_type": collector.agent_type,
                "collector_version": collector.version,
                "source_class": collector.source_class.value,
                "authorization_id": authorization_id,
                "started_at": started_at.isoformat(),
                "finished_at": finished_at.isoformat(),
                "result_status": status.value,
                "registry_provenance": registry_metadata.provenance,
                "implementation_identifier": registry_metadata.implementation_identifier,
                **private_metadata,
            },
            "raw_observations": [
                {
                    "raw_status": item.raw_status,
                    "value_reference": item.value_reference,
                    "evidence_ref": item.evidence_ref,
                    "notes": item.notes,
                }
                for item in observations
            ],
            "normalized_candidates": [
                {
                    "raw_status": item.raw_status,
                    "normalized_status": item.normalized_status.value,
                    "value_reference": item.value_reference,
                    "evidence_ref": item.evidence_ref,
                    "notes": item.notes,
                }
                for item in candidates
            ],
            "audit_reference": {
                "entry_count": verification.entry_count,
                "head_hash_before_completion": verification.head_hash,
            },
            "collector_evidence_refs": [
                item.evidence_ref for item in observations if item.evidence_ref is not None
            ],
            "safe_errors": list(errors),
        }
        payload = json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        try:
            self._evidence_vault.create_case(manifest)
            execution_artifact = self._evidence_vault.store_bytes(
                case_id=manifest.case_id,
                filename=f"{execution_id}.json",
                content=payload,
                original_source="orchestrator:execution-record",
                collected_at=finished_at,
                media_type="application/json",
                collector_name=collector.agent_name,
                collector_version=collector.version,
                execution_id=execution_id,
                source_class=collector.source_class,
                notes="Raw observations, normalized candidates and execution metadata.",
                category="raw",
            )
        except Exception as error:
            return self._vault_failure(
                manifest=manifest,
                collector=collector,
                execution_id=execution_id,
                authorization_id=authorization_id,
                started_at=started_at,
                observations=observations,
                error=error,
            )

        final_event = AuditEventType.AGENT_FAILED if status is ExecutionStatus.FAILED else AuditEventType.AGENT_FINISHED
        audit_head_hash = self._audit(
            manifest=manifest,
            collector=collector,
            execution_id=execution_id,
            authorization_id=authorization_id,
            event_type=final_event,
            decision=status.value,
            message="Collector execution completed and evidence was stored.",
            metadata={
                "observation_count": len(observations),
                "candidate_count": len(candidates),
                "error_count": len(errors),
                "evidence_id": execution_artifact.evidence_id,
            },
        )
        receipt = ExecutionReceipt(
            execution_id=execution_id,
            case_id=manifest.case_id,
            collector=collector.agent_name,
            collector_version=collector.version,
            source_class=collector.source_class,
            authorization_id=authorization_id,
            started_at=started_at,
            finished_at=finished_at,
            result_status=status,
            observation_count=len(observations),
            evidence_refs=(execution_artifact.evidence_id,),
            audit_head_hash=audit_head_hash,
        )
        try:
            receipt_payload = json.dumps(receipt.to_dict(), ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            self._evidence_vault.store_bytes(
                case_id=manifest.case_id,
                filename=f"{execution_id}-receipt.json",
                content=receipt_payload,
                original_source="orchestrator:execution-receipt",
                collected_at=finished_at,
                media_type="application/json",
                collector_name=collector.agent_name,
                collector_version=collector.version,
                execution_id=execution_id,
                source_class=collector.source_class,
                notes="Execution receipt bound to the audit head and evidence record.",
                category="reports",
            )
        except Exception as error:
            return self._vault_failure(
                manifest=manifest,
                collector=collector,
                execution_id=execution_id,
                authorization_id=authorization_id,
                started_at=started_at,
                observations=observations,
                error=error,
            )
        return ExecutionResult(
            execution_id=execution_id,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            errors=errors,
            observations=observations,
            finding_candidates=candidates,
            receipt=receipt,
        )

    def _vault_failure(
        self,
        *,
        manifest: CaseManifest,
        collector: Collector,
        execution_id: str,
        authorization_id: str | None,
        started_at: datetime,
        observations: tuple[RawObservation, ...],
        error: Exception,
    ) -> ExecutionResult:
        safe_error = f"{type(error).__name__}: required Evidence Vault write failed"
        finished_at = self._now()
        self._audit(
            manifest=manifest,
            collector=collector,
            execution_id=execution_id,
            authorization_id=authorization_id,
            event_type=AuditEventType.AGENT_FAILED,
            decision=ExecutionStatus.FAILED.value,
            message=safe_error,
            metadata={"observation_count": len(observations)},
        )
        return ExecutionResult(
            execution_id=execution_id,
            started_at=started_at,
            finished_at=finished_at,
            status=ExecutionStatus.FAILED,
            errors=(safe_error,),
            observations=(),
        )

    def _check_authorization(
        self,
        *,
        authorization_id: str | None,
        manifest: CaseManifest,
        collector: Collector,
    ) -> AuthorizationCheck:
        if authorization_id is None:
            return AuthorizationCheck(False, "valid per-run authorization is required")
        try:
            authorization = self._authorization_store.load(manifest.case_id, authorization_id)
        except (FileNotFoundError, OSError, ValueError):
            return AuthorizationCheck(False, "authorization lookup failed or record is invalid")
        return authorization.check(
            case_id=manifest.case_id,
            agent_name=collector.agent_name,
            source_class=collector.source_class,
            at=self._now(),
        )

    @staticmethod
    def _normalize(
        collector: Collector,
        observations: tuple[RawObservation, ...],
    ) -> tuple[tuple[FindingCandidate, ...], tuple[str, ...]]:
        candidates: list[FindingCandidate] = []
        errors: list[str] = []
        for index, observation in enumerate(observations):
            try:
                candidate = collector.normalize(observation)
                if not isinstance(candidate, FindingCandidate):
                    raise ValueError("normalize must return FindingCandidate")
                candidates.append(candidate)
            except Exception as error:
                errors.append(f"observation {index}: {type(error).__name__}: normalization failed")
        return tuple(candidates), tuple(errors)

    def _deny(
        self,
        *,
        manifest: CaseManifest,
        collector: Collector,
        execution_id: str,
        authorization_id: str | None,
        started_at: datetime,
        reason: str,
    ) -> ExecutionResult:
        self._audit(
            manifest=manifest,
            collector=collector,
            execution_id=execution_id,
            authorization_id=authorization_id,
            event_type=AuditEventType.RUN_DENIED,
            decision=ExecutionStatus.DENIED.value,
            message=reason,
            metadata={},
        )
        return ExecutionResult(
            execution_id=execution_id,
            started_at=started_at,
            finished_at=self._now(),
            status=ExecutionStatus.DENIED,
            errors=(reason,),
            observations=(),
        )

    def _audit(
        self,
        *,
        manifest: CaseManifest,
        collector: Collector,
        execution_id: str,
        authorization_id: str | None,
        event_type: AuditEventType,
        decision: str,
        message: str,
        metadata: dict[str, str | int | float | bool | None],
    ) -> str:
        result = self._audit_log.append(AuditEntry(
            audit_id=f"audit-{uuid4().hex}",
            case_id=manifest.case_id,
            execution_id=execution_id,
            authorization_id=authorization_id,
            agent_name=collector.agent_name,
            source_class=collector.source_class,
            event_type=event_type,
            decision=decision,
            timestamp=self._now(),
            message=message,
            metadata=metadata,
        ))
        return result.entry_hash

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("orchestrator clock must return timezone-aware datetime")
        return value
