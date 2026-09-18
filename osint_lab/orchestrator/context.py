"""Single-use execution context issued only by the orchestrator."""

from dataclasses import dataclass
from datetime import datetime

from osint_lab.case_manifest import validate_case_id
from osint_lab.policies import SourceClass


_CONTEXT_FACTORY_KEY = object()


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


@dataclass(frozen=True)
class _ExecutionPermit:
    execution_id: str
    agent_name: str
    source_class: SourceClass
    seed_reference: str
    _consumed: bool = False

    def consume(
        self,
        *,
        execution_id: str,
        agent_name: str,
        source_class: SourceClass,
        seed_reference: str,
    ) -> None:
        if self._consumed:
            raise PermissionError("execution context has already been consumed")
        if (
            self.execution_id != execution_id
            or self.agent_name != agent_name
            or self.source_class is not source_class
            or self.seed_reference != seed_reference
        ):
            raise PermissionError("execution context does not match this collector run")
        object.__setattr__(self, "_consumed", True)


@dataclass(frozen=True, kw_only=True, init=False)
class ExecutionContext:
    case_id: str
    execution_id: str
    authorization_id: str | None
    agent_name: str
    source_class: SourceClass
    started_at: datetime
    purpose: str
    seed_reference: str
    _permit: _ExecutionPermit

    def __init__(
        self,
        *,
        case_id: str,
        execution_id: str,
        authorization_id: str | None,
        agent_name: str,
        source_class: SourceClass,
        started_at: datetime,
        purpose: str,
        seed_reference: str,
        _factory_key: object | None = None,
    ) -> None:
        if _factory_key is not _CONTEXT_FACTORY_KEY:
            raise TypeError("ExecutionContext can only be created by the orchestrator")
        validate_case_id(case_id)
        for name, value in (
            ("execution_id", execution_id),
            ("agent_name", agent_name),
            ("purpose", purpose),
            ("seed_reference", seed_reference),
        ):
            _require_text(name, value)
        if authorization_id is not None:
            _require_text("authorization_id", authorization_id)
        if not isinstance(source_class, SourceClass):
            raise ValueError("source_class must be a SourceClass")
        _require_aware("started_at", started_at)
        object.__setattr__(self, "case_id", case_id)
        object.__setattr__(self, "execution_id", execution_id)
        object.__setattr__(self, "authorization_id", authorization_id)
        object.__setattr__(self, "agent_name", agent_name)
        object.__setattr__(self, "source_class", source_class)
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "purpose", purpose)
        object.__setattr__(self, "seed_reference", seed_reference)
        object.__setattr__(
            self,
            "_permit",
            _ExecutionPermit(execution_id, agent_name, source_class, seed_reference),
        )

    def _consume_for(self, *, agent_name: str, source_class: SourceClass, seed_reference: str) -> None:
        self._permit.consume(
            execution_id=self.execution_id,
            agent_name=agent_name,
            source_class=source_class,
            seed_reference=seed_reference,
        )


def _create_execution_context(
    *,
    case_id: str,
    execution_id: str,
    authorization_id: str | None,
    agent_name: str,
    source_class: SourceClass,
    started_at: datetime,
    purpose: str,
    seed_reference: str,
) -> ExecutionContext:
    return ExecutionContext(
        case_id=case_id,
        execution_id=execution_id,
        authorization_id=authorization_id,
        agent_name=agent_name,
        source_class=source_class,
        started_at=started_at,
        purpose=purpose,
        seed_reference=seed_reference,
        _factory_key=_CONTEXT_FACTORY_KEY,
    )
