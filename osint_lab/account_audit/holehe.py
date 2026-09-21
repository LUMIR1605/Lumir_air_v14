"""Optional Holehe 1.61 adapter using a bounded local subprocess bridge."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from typing import Callable, Mapping

from .models import (
    AccountAuditBudget,
    AccountAuditConfidence,
    AccountAuditResult,
    AccountAuditStatus,
    CleanupPriority,
    DependencyStatus,
    DetectionMethod,
    ProviderDiagnostic,
)
from .provider import ProgressCallback


PINNED_HOLEHE_VERSION = "1.61"


def default_holehe_python(environment: Mapping[str, str] | None = None) -> Path:
    values = os.environ if environment is None else environment
    root = values.get("LOCALAPPDATA")
    if not root:
        return Path(sys.executable)
    return Path(root) / "LumirOSINTLab" / "account_audit_env" / "Scripts" / "python.exe"


def normalize_holehe_result(
    payload: Mapping[str, object],
    *,
    checked_at: datetime,
    provider_version: str | None = PINNED_HOLEHE_VERSION,
) -> AccountAuditResult:
    """Map Holehe output without ever turning errors into NOT_FOUND."""

    name = str(payload.get("name") or payload.get("service_id") or "unknown").strip().casefold()
    domain = str(payload.get("domain") or name).strip().casefold()
    rate_limited = payload.get("rateLimit") is True or payload.get("rate_limited") is True
    error = payload.get("error") is True
    error_code = str(payload.get("error_code") or "") or None
    blocked = error_code in {"BLOCKED", "CHALLENGE", "CAPTCHA"}
    exists = payload.get("exists")
    if rate_limited:
        status = AccountAuditStatus.RATE_LIMITED
        confidence = AccountAuditConfidence.UNKNOWN
        notes = "Provider ograniczył zapytanie; nie podjęto próby obejścia blokady."
    elif blocked:
        status = AccountAuditStatus.BLOCKED
        confidence = AccountAuditConfidence.UNKNOWN
        notes = "Provider zablokował lub zakwestionował zapytanie; nie podjęto próby obejścia."
    elif error:
        status = AccountAuditStatus.ERROR
        confidence = AccountAuditConfidence.UNKNOWN
        notes = "Błąd techniczny providera; nie jest to sygnał braku konta."
        error_code = error_code or "PROVIDER_ERROR"
    elif exists is True:
        status = AccountAuditStatus.FOUND
        confidence = AccountAuditConfidence.HIGH
        notes = "Provider wskazuje prawdopodobne powiązanie adresu z kontem; nie potwierdza właściciela."
    elif exists is False:
        status = AccountAuditStatus.NOT_FOUND
        confidence = AccountAuditConfidence.HIGH
        notes = "Provider nie zwrócił sygnału konta w chwili sprawdzenia."
    else:
        status = AccountAuditStatus.UNKNOWN
        confidence = AccountAuditConfidence.UNKNOWN
        notes = "Odpowiedź providera była niejednoznaczna."
    method_value = str(payload.get("detection_method") or "other")
    try:
        method = DetectionMethod(method_value)
    except ValueError:
        method = DetectionMethod.OTHER
    category = str(payload.get("category") or "account-service")
    priority = CleanupPriority.LOW
    if status is AccountAuditStatus.FOUND:
        priority = CleanupPriority.HIGH if category in {"cloud", "commerce", "profile"} else CleanupPriority.MEDIUM
    return AccountAuditResult(
        service_id=name,
        service_name=str(payload.get("service_name") or name.replace("_", " ").title()),
        domain=domain,
        category=category,
        status=status,
        confidence=confidence,
        detection_method=method,
        source_adapter="holehe_v1",
        checked_at=checked_at,
        rate_limited=rate_limited,
        error_code=error_code,
        recovery_email_masked=_optional_text(payload.get("emailrecovery")),
        recovery_phone_masked=_optional_text(payload.get("phoneNumber")),
        notes=notes,
        provider_version=provider_version,
        module_version=_optional_text(payload.get("module_version")) or provider_version,
        cleanup_priority=priority,
    )


def _optional_text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


class HoleheAccountAuditAdapter:
    """Run an installed Holehe library in its isolated Windows interpreter."""

    provider_id = "holehe_v1"

    def __init__(
        self,
        *,
        interpreter: Path | None = None,
        repo_root: Path | None = None,
        clock: Callable[[], datetime] | None = None,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        popen_factory: Callable[..., subprocess.Popen[str]] | None = None,
    ) -> None:
        self.interpreter = (default_holehe_python() if interpreter is None else Path(interpreter)).resolve()
        self.repo_root = (Path(__file__).resolve().parents[2] if repo_root is None else Path(repo_root)).resolve()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._command_runner = command_runner or subprocess.run
        self._popen_factory = popen_factory or subprocess.Popen

    def diagnose(self) -> ProviderDiagnostic:
        if not self.interpreter.is_file():
            return ProviderDiagnostic(
                status=DependencyStatus.NOT_INSTALLED,
                provider_id=self.provider_id,
                provider_version=None,
                python_interpreter=str(self.interpreter),
                python_version=None,
                cli_available=False,
                library_available=False,
                provider_modules_detected=0,
                reason="DEPENDENCY_MISSING: isolated account-audit environment was not found",
            )
        command = [str(self.interpreter), str(Path(__file__).with_name("holehe_worker.py")), "--diagnose"]
        try:
            completed = self._command_runner(
                command,
                capture_output=True,
                text=True,
                timeout=15,
                env=self._environment(),
                check=False,
            )
            payload = json.loads(completed.stdout.strip()) if completed.returncode == 0 else {}
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, TypeError, ValueError):
            payload = {}
        if payload.get("library_available") is not True:
            return ProviderDiagnostic(
                status=DependencyStatus.NOT_INSTALLED,
                provider_id=self.provider_id,
                provider_version=_optional_text(payload.get("version")),
                python_interpreter=str(self.interpreter),
                python_version=_optional_text(payload.get("python_version")),
                cli_available=bool(payload.get("cli_available")),
                library_available=False,
                provider_modules_detected=int(payload.get("provider_modules_detected") or 0),
                reason="DEPENDENCY_MISSING: Holehe library is unavailable in the isolated environment",
            )
        version = _optional_text(payload.get("version"))
        python_version = _optional_text(payload.get("python_version"))
        python_parts = tuple(int(item) for item in python_version.split(".")[:2]) if python_version else ()
        compatible = version == PINNED_HOLEHE_VERSION and python_parts in {(3, 10), (3, 11), (3, 12)}
        return ProviderDiagnostic(
            status=DependencyStatus.INSTALLED if compatible else DependencyStatus.INCOMPATIBLE,
            provider_id=self.provider_id,
            provider_version=version,
            python_interpreter=str(self.interpreter),
            python_version=python_version,
            cli_available=bool(payload.get("cli_available")),
            library_available=True,
            provider_modules_detected=int(payload.get("provider_modules_detected") or 0),
            reason=("Pinned Holehe dependency is available" if compatible else
                    f"INCOMPATIBLE_DEPENDENCY: expected Holehe {PINNED_HOLEHE_VERSION} on "
                    f"Python 3.10-3.12, found {version or 'unknown'} on {python_version or 'unknown'}"),
        )

    def audit(
        self,
        email: str,
        *,
        budget: AccountAuditBudget,
        progress_callback: ProgressCallback | None = None,
        cancel_event: threading.Event | None = None,
    ) -> tuple[AccountAuditResult, ...]:
        self.last_run_status = "COMPLETE"
        diagnostic = self.diagnose()
        if diagnostic.status is not DependencyStatus.INSTALLED:
            return ()
        process = self._popen_factory(
            [str(self.interpreter), str(Path(__file__).with_name("holehe_worker.py"))],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=self._environment(),
            bufsize=1,
        )
        request = json.dumps({"email": email, "budget": budget.to_dict()}, ensure_ascii=False) + "\n"
        assert process.stdin is not None
        process.stdin.write(request)
        process.stdin.close()
        lines: queue.Queue[str] = queue.Queue()
        stderr_lines: list[str] = []
        assert process.stdout is not None and process.stderr is not None
        stdout_thread = threading.Thread(target=lambda: [lines.put(line) for line in process.stdout], daemon=True)
        stderr_thread = threading.Thread(target=lambda: stderr_lines.extend(process.stderr), daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        started = time.monotonic()
        results: list[AccountAuditResult] = []
        total = diagnostic.provider_modules_detected
        termination_requested = False
        while process.poll() is None or not lines.empty():
            if not termination_requested and cancel_event is not None and cancel_event.is_set():
                self.last_run_status = "CANCELLED"
                process.terminate()
                termination_requested = True
            if not termination_requested and time.monotonic() - started > budget.global_timeout_seconds:
                self.last_run_status = "GLOBAL_TIMEOUT"
                process.terminate()
                termination_requested = True
            try:
                line = lines.get(timeout=0.05)
            except queue.Empty:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(raw, dict) or raw.get("event") != "result":
                continue
            result = normalize_holehe_result(
                raw.get("payload", {}),
                checked_at=self._now(),
                provider_version=diagnostic.provider_version,
            )
            results.append(result)
            if progress_callback is not None:
                progress_callback(len(results), min(total, budget.max_services), result)
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        return tuple(results)

    def _environment(self) -> dict[str, str]:
        values = dict(os.environ)
        existing = values.get("PYTHONPATH")
        values["PYTHONPATH"] = str(self.repo_root) + (os.pathsep + existing if existing else "")
        values["PYTHONIOENCODING"] = "utf-8"
        return values

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("account-audit clock must be timezone-aware")
        return value
