"""Provider contract for optional account-audit engines."""

from __future__ import annotations

from typing import Callable, Protocol
import threading

from .models import AccountAuditBudget, AccountAuditResult, ProviderDiagnostic


ProgressCallback = Callable[[int, int, AccountAuditResult], None]


class AccountAuditProvider(Protocol):
    provider_id: str

    def diagnose(self) -> ProviderDiagnostic:
        """Return local dependency state without contacting audited services."""

    def audit(
        self,
        email: str,
        *,
        budget: AccountAuditBudget,
        progress_callback: ProgressCallback | None = None,
        cancel_event: threading.Event | None = None,
    ) -> tuple[AccountAuditResult, ...]:
        """Run only after the caller has enforced the explicit self-audit gate."""
