"""Validated models for the separate, user-authorized account audit mode."""

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from typing import Mapping


def _text(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")


def _aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")


class AccountAuditStatus(str, Enum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"
    RATE_LIMITED = "RATE_LIMITED"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


class AccountAuditConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class DetectionMethod(str, Enum):
    REGISTER = "register"
    LOGIN = "login"
    FORGOT_PASSWORD = "forgot-password"
    OTHER = "other"


class AccountReviewStatus(str, Enum):
    UNREVIEWED = "UNREVIEWED"
    KEEP = "KEEP"
    CHECK_MANUALLY = "CHECK_MANUALLY"
    DELETE_CANDIDATE = "DELETE_CANDIDATE"
    DELETED = "DELETED"
    CANNOT_ACCESS = "CANNOT_ACCESS"


class CleanupPriority(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DependencyStatus(str, Enum):
    INSTALLED = "INSTALLED"
    NOT_INSTALLED = "NOT_INSTALLED"
    INCOMPATIBLE = "INCOMPATIBLE"


@dataclass(frozen=True, kw_only=True)
class AccountAuditBudget:
    max_services: int = 130
    global_timeout_seconds: float = 180.0
    per_service_timeout_seconds: float = 12.0
    max_concurrency: int = 4

    def __post_init__(self) -> None:
        for name in ("max_services", "max_concurrency"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("global_timeout_seconds", "per_service_timeout_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{name} must be positive")
        if self.max_concurrency > 8:
            raise ValueError("max_concurrency must remain low (8 or fewer)")

    def to_dict(self) -> dict[str, object]:
        return {
            "max_services": self.max_services,
            "global_timeout_seconds": self.global_timeout_seconds,
            "per_service_timeout_seconds": self.per_service_timeout_seconds,
            "max_concurrency": self.max_concurrency,
        }


@dataclass(frozen=True, kw_only=True)
class ProviderDiagnostic:
    status: DependencyStatus
    provider_id: str
    provider_version: str | None
    python_interpreter: str
    python_version: str | None
    cli_available: bool
    library_available: bool
    provider_modules_detected: int
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "python_interpreter": self.python_interpreter,
            "python_version": self.python_version,
            "cli_available": self.cli_available,
            "library_available": self.library_available,
            "provider_modules_detected": self.provider_modules_detected,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ProviderDiagnostic":
        return cls(
            status=DependencyStatus(str(payload["status"])),
            provider_id=str(payload["provider_id"]),
            provider_version=payload.get("provider_version") or None,
            python_interpreter=str(payload["python_interpreter"]),
            python_version=payload.get("python_version") or None,
            cli_available=bool(payload["cli_available"]),
            library_available=bool(payload["library_available"]),
            provider_modules_detected=int(payload["provider_modules_detected"]),
            reason=str(payload["reason"]),
        )


@dataclass(frozen=True, kw_only=True)
class AccountAuditResult:
    service_id: str
    service_name: str
    domain: str
    category: str
    status: AccountAuditStatus
    confidence: AccountAuditConfidence
    detection_method: DetectionMethod
    source_adapter: str
    checked_at: datetime
    rate_limited: bool
    error_code: str | None
    recovery_email_masked: str | None
    recovery_phone_masked: str | None
    notes: str
    review_status: AccountReviewStatus = AccountReviewStatus.UNREVIEWED
    deletion_url: str | None = None
    privacy_url: str | None = None
    provider_version: str | None = None
    module_version: str | None = None
    user_note: str = ""
    cleanup_priority: CleanupPriority = CleanupPriority.LOW

    def __post_init__(self) -> None:
        for name in ("service_id", "service_name", "domain", "category", "source_adapter", "notes"):
            _text(name, getattr(self, name))
        _aware("checked_at", self.checked_at)
        if not isinstance(self.status, AccountAuditStatus):
            raise ValueError("status must be AccountAuditStatus")
        if not isinstance(self.confidence, AccountAuditConfidence):
            raise ValueError("confidence must be AccountAuditConfidence")
        if not isinstance(self.detection_method, DetectionMethod):
            raise ValueError("detection_method must be DetectionMethod")
        if not isinstance(self.review_status, AccountReviewStatus):
            raise ValueError("review_status must be AccountReviewStatus")
        if not isinstance(self.cleanup_priority, CleanupPriority):
            raise ValueError("cleanup_priority must be CleanupPriority")
        if not isinstance(self.rate_limited, bool):
            raise ValueError("rate_limited must be boolean")

    def with_review(self, status: AccountReviewStatus, note: str) -> "AccountAuditResult":
        return replace(self, review_status=status, user_note=note)

    def to_dict(self) -> dict[str, object]:
        return {
            "service_id": self.service_id,
            "service_name": self.service_name,
            "domain": self.domain,
            "category": self.category,
            "status": self.status.value,
            "confidence": self.confidence.value,
            "detection_method": self.detection_method.value,
            "source_adapter": self.source_adapter,
            "checked_at": self.checked_at.isoformat(),
            "rate_limited": self.rate_limited,
            "error_code": self.error_code,
            "recovery_email_masked": self.recovery_email_masked,
            "recovery_phone_masked": self.recovery_phone_masked,
            "notes": self.notes,
            "review_status": self.review_status.value,
            "deletion_url": self.deletion_url,
            "privacy_url": self.privacy_url,
            "provider_version": self.provider_version,
            "module_version": self.module_version,
            "user_note": self.user_note,
            "cleanup_priority": self.cleanup_priority.value,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "AccountAuditResult":
        return cls(
            service_id=str(payload["service_id"]), service_name=str(payload["service_name"]),
            domain=str(payload["domain"]), category=str(payload["category"]),
            status=AccountAuditStatus(str(payload["status"])),
            confidence=AccountAuditConfidence(str(payload["confidence"])),
            detection_method=DetectionMethod(str(payload["detection_method"])),
            source_adapter=str(payload["source_adapter"]),
            checked_at=datetime.fromisoformat(str(payload["checked_at"])),
            rate_limited=bool(payload["rate_limited"]),
            error_code=payload.get("error_code") or None,
            recovery_email_masked=payload.get("recovery_email_masked") or None,
            recovery_phone_masked=payload.get("recovery_phone_masked") or None,
            notes=str(payload["notes"]),
            review_status=AccountReviewStatus(str(payload.get("review_status", "UNREVIEWED"))),
            deletion_url=payload.get("deletion_url") or None,
            privacy_url=payload.get("privacy_url") or None,
            provider_version=payload.get("provider_version") or None,
            module_version=payload.get("module_version") or None,
            user_note=str(payload.get("user_note") or ""),
            cleanup_priority=CleanupPriority(str(payload.get("cleanup_priority", "LOW"))),
        )


@dataclass(frozen=True, kw_only=True)
class AccountAuditRun:
    case_id: str
    started_at: datetime
    finished_at: datetime
    provider: ProviderDiagnostic
    results: tuple[AccountAuditResult, ...]
    email_hash: str
    status: str
    cancelled: bool
    report_paths: Mapping[str, str] = field(default_factory=dict)

    def summary(self) -> dict[str, int]:
        counts = {status.value: 0 for status in AccountAuditStatus}
        for item in self.results:
            counts[item.status.value] += 1
        counts["SERVICES_CHECKED"] = len(self.results)
        counts["HIGH_CONFIDENCE_FOUND"] = sum(
            item.status is AccountAuditStatus.FOUND
            and item.confidence is AccountAuditConfidence.HIGH
            for item in self.results
        )
        counts["NEEDS_MANUAL_REVIEW"] = sum(
            item.status in {AccountAuditStatus.UNKNOWN, AccountAuditStatus.RATE_LIMITED,
                            AccountAuditStatus.BLOCKED, AccountAuditStatus.ERROR}
            for item in self.results
        )
        return counts

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": "ACCOUNT_AUDIT",
            "case_id": self.case_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "provider": self.provider.to_dict(),
            "email_hash": self.email_hash,
            "status": self.status,
            "cancelled": self.cancelled,
            "summary": self.summary(),
            "results": [item.to_dict() for item in self.results],
            "report_paths": dict(self.report_paths),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "AccountAuditRun":
        provider = payload["provider"]
        results = payload["results"]
        report_paths = payload.get("report_paths", {})
        if not isinstance(provider, Mapping) or not isinstance(results, list) or not isinstance(report_paths, Mapping):
            raise ValueError("invalid stored account-audit run")
        return cls(
            case_id=str(payload["case_id"]),
            started_at=datetime.fromisoformat(str(payload["started_at"])),
            finished_at=datetime.fromisoformat(str(payload["finished_at"])),
            provider=ProviderDiagnostic.from_dict(provider),
            results=tuple(AccountAuditResult.from_dict(item) for item in results if isinstance(item, Mapping)),
            email_hash=str(payload["email_hash"]),
            status=str(payload["status"]),
            cancelled=bool(payload["cancelled"]),
            report_paths={str(key): str(value) for key, value in report_paths.items()},
        )
