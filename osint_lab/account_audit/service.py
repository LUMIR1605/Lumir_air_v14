"""Separate ACCOUNT_AUDIT service with explicit authorization and privacy gates."""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import re
from pathlib import Path
import threading
from typing import Callable

from osint_lab.graph import CaseEvent, CaseEventType, GraphStore
from osint_lab.orchestrator.audit import AuditEntry, AuditEventType, AuditLog
from osint_lab.policies import SourceClass

from .cleanup import AccountCleanupCatalog
from .export import AccountAuditExporter
from .graph import project_account_audit
from .models import (
    AccountAuditBudget,
    AccountAuditRun,
    AccountReviewStatus,
    DependencyStatus,
)
from .provider import AccountAuditProvider, ProgressCallback
from .storage import AccountAuditStore


_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class AccountAuditAuthorizationError(PermissionError):
    pass


class AccountAuditService:
    def __init__(
        self,
        *,
        repo_root: Path,
        case_root: Path,
        audit_log: AuditLog,
        provider: AccountAuditProvider,
        catalog: AccountCleanupCatalog | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.case_root = Path(case_root).resolve()
        self.audit_log = audit_log
        self.provider = provider
        self.catalog = catalog or AccountCleanupCatalog()
        self.store = AccountAuditStore(repo_root=self.repo_root, case_root=self.case_root)
        self.exporter = AccountAuditExporter(case_root=self.case_root, catalog=self.catalog)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def diagnose(self):
        return self.provider.diagnose()

    def run(
        self,
        *,
        email: str,
        authorization_confirmed: bool,
        privacy_disclosure_accepted: bool,
        budget: AccountAuditBudget | None = None,
        progress_callback: ProgressCallback | None = None,
        cancel_event: threading.Event | None = None,
    ) -> AccountAuditRun:
        if authorization_confirmed is not True:
            raise AccountAuditAuthorizationError("SELF_AUDIT_AUTHORIZATION_REQUIRED")
        if privacy_disclosure_accepted is not True:
            raise AccountAuditAuthorizationError("ACCOUNT_AUDIT_PRIVACY_DISCLOSURE_REQUIRED")
        normalized = email.strip().casefold() if isinstance(email, str) else ""
        if not _EMAIL.fullmatch(normalized):
            raise ValueError("valid email address required")
        started = self._now()
        case_id = self._case_id(started)
        email_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        self.store.save_private_input(case_id=case_id, email=normalized, created_at=started)
        self._record_authorization(case_id=case_id, email_hash=email_hash, timestamp=started)
        diagnostic = self.provider.diagnose()
        values = budget or AccountAuditBudget()
        results = ()
        status = "DEPENDENCY_MISSING"
        if diagnostic.status is DependencyStatus.INSTALLED:
            results = self.provider.audit(
                normalized,
                budget=values,
                progress_callback=progress_callback,
                cancel_event=cancel_event,
            )
            status = str(getattr(self.provider, "last_run_status", "COMPLETE"))
            if cancel_event is not None and cancel_event.is_set():
                status = "CANCELLED"
        elif diagnostic.status is DependencyStatus.INCOMPATIBLE:
            status = "DEPENDENCY_INCOMPATIBLE"
        finished = self._now()
        graph_store = GraphStore(repo_root=self.repo_root, case_root=self.case_root, case_id=case_id)
        project_account_audit(
            store=graph_store,
            case_id=case_id,
            email_hash=email_hash,
            results=results,
            timestamp=finished,
        )
        run = AccountAuditRun(
            case_id=case_id,
            started_at=started,
            finished_at=finished,
            provider=diagnostic,
            results=results,
            email_hash=email_hash,
            status=status,
            cancelled=status == "CANCELLED",
        )
        paths = self.exporter.export(run)
        run = replace(run, report_paths=paths)
        self.exporter.export(run)
        self.store.save_run(case_id=case_id, payload=run.to_dict())
        return run

    def record_review(
        self,
        *,
        case_id: str,
        service_id: str,
        status: AccountReviewStatus,
        note: str,
    ) -> Path:
        timestamp = self._now()
        run = AccountAuditRun.from_dict(self.store.load_run(case_id))
        if not any(item.service_id == service_id for item in run.results):
            raise ValueError("reviewed account-audit service was not found")
        updated_results = tuple(
            item.with_review(status, note) if item.service_id == service_id else item
            for item in run.results
        )
        updated_run = replace(run, results=updated_results)
        path = self.store.append_review(
            case_id=case_id,
            service_id=service_id,
            status=status,
            note=note,
            timestamp=timestamp,
        )
        self.exporter.export(updated_run)
        self.store.save_run(case_id=case_id, payload=updated_run.to_dict())
        self.audit_log.append(AuditEntry(
            audit_id="audit-" + hashlib.sha256(
                f"review|{case_id}|{service_id}|{timestamp.isoformat()}".encode("utf-8")
            ).hexdigest()[:24],
            case_id=case_id,
            execution_id="account-review-" + hashlib.sha256(service_id.encode("utf-8")).hexdigest()[:16],
            authorization_id=None,
            agent_name="account_audit_review",
            source_class=SourceClass.LOCAL,
            event_type=AuditEventType.REVIEW_DECISION,
            decision=status.value,
            timestamp=timestamp,
            message="Manual account cleanup status recorded in private case storage.",
            metadata={"service_id_sha256": hashlib.sha256(service_id.encode("utf-8")).hexdigest()},
        ))
        return path

    def _record_authorization(self, *, case_id: str, email_hash: str, timestamp: datetime) -> None:
        token = hashlib.sha256(f"{case_id}|{timestamp.isoformat()}".encode("utf-8")).hexdigest()[:24]
        self.audit_log.append(AuditEntry(
            audit_id=f"audit-{token}",
            case_id=case_id,
            execution_id=f"account-audit-{token}",
            authorization_id=None,
            agent_name="account_audit_gate",
            source_class=SourceClass.LOCAL,
            event_type=AuditEventType.SELF_AUDIT_AUTHORIZATION_CONFIRMED,
            decision="ALLOW",
            timestamp=timestamp,
            message="User confirmed control of the email address or explicit owner authorization.",
            metadata={"email_sha256": email_hash, "privacy_disclosure_accepted": True},
        ))
        store = GraphStore(repo_root=self.repo_root, case_root=self.case_root, case_id=case_id)
        store.add_batch(events=(CaseEvent(
            event_id=f"evt-{token}",
            case_id=case_id,
            event_type=CaseEventType.SELF_AUDIT_AUTHORIZATION_CONFIRMED,
            timestamp=timestamp,
            subject_id=f"email-sha256:{email_hash[:16]}",
            evidence_refs=(),
            attributes={"mode": "ACCOUNT_AUDIT", "privacy_disclosure_accepted": True},
        ),))

    def _case_id(self, timestamp: datetime) -> str:
        base = timestamp.strftime("account_%Y%m%d_%H%M%S")
        for index in range(100):
            candidate = base if index == 0 else f"{base}_{index:02d}"
            if not (self.case_root / candidate).exists():
                return candidate
        raise RuntimeError("could not allocate account-audit case id")

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("account-audit clock must be timezone-aware")
        return value
