"""Policy-enforcing orchestrator; the only public collector execution path."""

from collections.abc import Callable
from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from osint_lab.agents.base import (
    Collector,
    ExecutionResult,
    ExecutionStatus,
    FindingCandidate,
    RawObservation,
)
from osint_lab.case_manifest import CaseManifest
from osint_lab.policies.gate import PolicyDecision, PolicyGate

from .audit import AuditEntry, AuditEventType, AuditLog
from .authorization import AuthorizationCheck, RunAuthorization
from .context import _create_execution_context


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
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(audit_log, AuditLog):
            raise ValueError("AuditLog required")
        self._audit_log = audit_log
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def execute(
        self,
        *,
        manifest: CaseManifest,
        collector: Collector,
        seed_reference: str,
        purpose: str,
        requested_by: str,
        authorization: RunAuthorization | None = None,
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
        if authorization is not None and not isinstance(authorization, RunAuthorization):
            raise ValueError("authorization must be a RunAuthorization")

        execution_id = f"run-{uuid4().hex}"
        started_at = self._now()
        authorization_id = authorization.authorization_id if authorization else None
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
                authorization=authorization,
                manifest=manifest,
                collector=collector,
            )
            if authorization is not None:
                checked_authorization_id = authorization.authorization_id
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
        except Exception as error:
            finished_at = self._now()
            safe_error = f"{type(error).__name__}: collector execution failed"
            self._audit(
                manifest=manifest,
                collector=collector,
                execution_id=execution_id,
                authorization_id=checked_authorization_id,
                event_type=AuditEventType.AGENT_FAILED,
                decision=ExecutionStatus.FAILED.value,
                message=safe_error,
                metadata={"observation_count": 0},
            )
            return ExecutionResult(
                execution_id=execution_id,
                started_at=started_at,
                finished_at=finished_at,
                status=ExecutionStatus.FAILED,
                errors=(safe_error,),
                observations=(),
            )

        candidates, errors = self._normalize(collector, observations)
        finished_at = self._now()
        if errors and candidates:
            status = ExecutionStatus.PARTIAL
        elif errors:
            status = ExecutionStatus.FAILED
        else:
            status = ExecutionStatus.SUCCESS
        event_type = AuditEventType.AGENT_FAILED if status is ExecutionStatus.FAILED else AuditEventType.AGENT_FINISHED
        self._audit(
            manifest=manifest,
            collector=collector,
            execution_id=execution_id,
            authorization_id=checked_authorization_id,
            event_type=event_type,
            decision=status.value,
            message="Collector execution finished." if status is not ExecutionStatus.FAILED else "Collector normalization failed.",
            metadata={
                "observation_count": len(observations),
                "candidate_count": len(candidates),
                "error_count": len(errors),
            },
        )
        return ExecutionResult(
            execution_id=execution_id,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            errors=errors,
            observations=observations,
            finding_candidates=candidates,
        )

    def _check_authorization(
        self,
        *,
        authorization: RunAuthorization | None,
        manifest: CaseManifest,
        collector: Collector,
    ) -> AuthorizationCheck:
        if authorization is None:
            return AuthorizationCheck(False, "valid per-run authorization is required")
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
    ) -> None:
        self._audit_log.append(AuditEntry(
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

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("orchestrator clock must return timezone-aware datetime")
        return value
