"""Scoped, expiring authorization for one collector run."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from osint_lab.case_manifest import validate_case_id
from osint_lab.policies import SourceClass


class AuthorizationDecision(str, Enum):
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


def _require_text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _require_aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


@dataclass(frozen=True)
class AuthorizationCheck:
    valid: bool
    reason: str


@dataclass(frozen=True, kw_only=True)
class RunAuthorization:
    authorization_id: str
    case_id: str
    requested_agent: str
    requested_source_class: SourceClass
    requested_at: datetime
    requested_by: str
    purpose: str
    decision: AuthorizationDecision
    decision_at: datetime
    approved_by: str | None
    expires_at: datetime
    scope: str
    notes: str = ""

    def __post_init__(self) -> None:
        _require_text("authorization_id", self.authorization_id)
        validate_case_id(self.case_id)
        for name in ("requested_agent", "requested_by", "purpose", "scope"):
            _require_text(name, getattr(self, name))
        if self.requested_agent.strip() == "*" or self.scope.strip() == "*":
            raise ValueError("global authorization is not permitted")
        if not isinstance(self.requested_source_class, SourceClass):
            raise ValueError("requested_source_class must be a SourceClass")
        if not isinstance(self.decision, AuthorizationDecision):
            raise ValueError("decision must be an AuthorizationDecision")
        for name in ("requested_at", "decision_at", "expires_at"):
            _require_aware(name, getattr(self, name))
        if self.decision_at < self.requested_at:
            raise ValueError("decision_at must not precede requested_at")
        if self.expires_at <= self.decision_at:
            raise ValueError("expires_at must be later than decision_at")
        if self.decision is AuthorizationDecision.APPROVED:
            if self.approved_by is None:
                raise ValueError("approved_by is required for approved authorization")
            _require_text("approved_by", self.approved_by)
        elif self.approved_by is not None:
            _require_text("approved_by", self.approved_by)
        if not isinstance(self.notes, str):
            raise ValueError("notes must be a string")

    def check(
        self,
        *,
        case_id: str,
        agent_name: str,
        source_class: SourceClass,
        at: datetime,
    ) -> AuthorizationCheck:
        validate_case_id(case_id)
        _require_text("agent_name", agent_name)
        if not isinstance(source_class, SourceClass):
            raise ValueError("source_class must be a SourceClass")
        _require_aware("at", at)
        if self.case_id != case_id:
            return AuthorizationCheck(False, "authorization belongs to another case")
        if self.requested_agent != agent_name:
            return AuthorizationCheck(False, "authorization belongs to another agent")
        if self.requested_source_class is not source_class:
            return AuthorizationCheck(False, "authorization belongs to another source class")
        if self.decision is not AuthorizationDecision.APPROVED:
            return AuthorizationCheck(False, f"authorization decision is {self.decision.value}")
        if at < self.decision_at:
            return AuthorizationCheck(False, "authorization is not effective yet")
        if at >= self.expires_at:
            return AuthorizationCheck(False, "authorization has expired")
        return AuthorizationCheck(True, "authorization is approved and in scope")
