"""Testable backend adapter for the Windows Tk desktop launcher."""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Callable

from osint_lab.application import ApplicationServices, create_case_manifest
from osint_lab.case_manifest import SeedEntity
from osint_lab.case_runner import CaseExecutionPlan, CaseRunResult


class DesktopValidationError(ValueError):
    pass


class DesktopAnalysisError(RuntimeError):
    pass


@dataclass(frozen=True, kw_only=True)
class DesktopInput:
    phone: str = ""
    email: str = ""
    username: str = ""
    domain: str = ""
    allow_passive_web: bool = False


@dataclass(frozen=True, kw_only=True)
class DesktopAnalysisSummary:
    case_id: str
    overall_status: str
    possible_count: int
    unknown_count: int
    not_found_count: int
    contradiction_count: int
    public_matches_verified: int
    rejected_false_positives: int
    target_pages_checked: int
    report_html_path: str | None
    case_folder_path: str
    warnings: tuple[str, ...]
    graph_viewer_path: str | None = None


class DesktopBackend:
    """Create and run one private case through the existing application services."""

    _STATUS_BY_EVENT = {
        "collector:phone_metadata": "Analiza telefonu...",
        "collector:domain_dns": "Analiza domeny...",
        "collector:username_lookup": "Analiza username...",
        "collector:email_local_metadata": "Analiza e-mail...",
        "collector:email_exposure": "Analiza e-mail...",
        "phone_public:search": "Szukanie publicznych wyników...",
        "phone_public:verify": "Weryfikacja stron źródłowych...",
        "intelligence": "Analiza dowodów...",
        "graph": "Budowanie grafu wiedzy...",
        "report": "Generowanie raportu...",
    }

    def __init__(
        self,
        *,
        application: ApplicationServices,
        clock: Callable[[], datetime] | None = None,
        path_opener: Callable[[str], object] | None = None,
    ) -> None:
        if not isinstance(application, ApplicationServices):
            raise ValueError("ApplicationServices required")
        self._application = application
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._path_opener = path_opener or self._open_windows_path
        self._last_summary: DesktopAnalysisSummary | None = None

    @property
    def last_summary(self) -> DesktopAnalysisSummary | None:
        return self._last_summary

    def analyze(
        self,
        values: DesktopInput,
        *,
        status_callback: Callable[[str], None] | None = None,
    ) -> DesktopAnalysisSummary:
        if not isinstance(values, DesktopInput):
            raise ValueError("DesktopInput required")
        if status_callback is not None and not callable(status_callback):
            raise ValueError("status_callback must be callable")
        seeds = self._seeds(values)
        if not seeds:
            raise DesktopValidationError("Nie podano żadnych danych.")
        self._emit(status_callback, "Przygotowanie...")
        created_at = self._now()
        case_id = self._unique_case_id(created_at)
        manifest = create_case_manifest(
            case_id=case_id,
            case_name="LUMIR Desktop Analysis",
            authorized_by="Local user",
            purpose="Authorized local OSINT self-audit / user-provided data",
            legal_note=(
                "User explicitly provided the identifiers for analysis in the local application."
            ),
            seeds=seeds,
            allow_passive_web=values.allow_passive_web,
            created_at=created_at,
        )
        try:
            self._application.case_store.create(manifest)
            result = self._application.runner.run(
                manifest,
                progress_callback=lambda event: self._emit(
                    status_callback,
                    self._STATUS_BY_EVENT.get(event, "Przetwarzanie..."),
                ),
            )
        except DesktopValidationError:
            raise
        except Exception as error:
            self.record_error(error)
            raise DesktopAnalysisError("Nie udało się uruchomić analizy.") from error
        if isinstance(result, CaseExecutionPlan) or not isinstance(result, CaseRunResult):
            error = RuntimeError("CaseRunner returned an unexpected desktop result")
            self.record_error(error)
            raise DesktopAnalysisError("Nie udało się uruchomić analizy.")
        report_path = result.report_reference.html_path if result.report_reference else None
        graph_path = None
        if result.graph_bundle is not None:
            exports = result.graph_bundle.get("exports")
            if isinstance(exports, dict) and isinstance(exports.get("viewer_path"), str):
                graph_path = exports["viewer_path"]
        public_matches, rejected_targets, checked_targets = self._phone_public_counts(result)
        summary = DesktopAnalysisSummary(
            case_id=case_id,
            overall_status=result.overall_status.value,
            possible_count=result.findings_summary.get("POSSIBLE", 0),
            unknown_count=result.findings_summary.get("UNKNOWN", 0),
            not_found_count=result.findings_summary.get("NOT_FOUND", 0),
            contradiction_count=len(result.contradictions.reasons),
            public_matches_verified=public_matches,
            rejected_false_positives=rejected_targets,
            target_pages_checked=checked_targets,
            report_html_path=report_path,
            case_folder_path=str((self._application.case_store.root / case_id).resolve()),
            warnings=result.warnings,
            graph_viewer_path=graph_path,
        )
        self._last_summary = summary
        self._emit(status_callback, "Gotowe.")
        return summary

    @staticmethod
    def _phone_public_counts(result: CaseRunResult) -> tuple[int, int, int]:
        verified = 0
        rejected = 0
        checked = 0
        for record in result.executions:
            if record.step.collector_name != "phone_public_web" or record.result is None:
                continue
            for observation in record.result.observations:
                payload = observation.payload
                if payload.get("stage") != "TARGET_PAGE_VALIDATION":
                    continue
                checked += 1
                if payload.get("target_verified") is True:
                    verified += 1
                else:
                    rejected += 1
        return verified, rejected, checked

    def open_report(self, summary: DesktopAnalysisSummary | None = None) -> Path:
        selected = summary or self._last_summary
        if selected is None or selected.report_html_path is None:
            raise DesktopValidationError("Raport HTML nie jest dostępny.")
        path = self.validate_report_path(selected.case_id, selected.report_html_path)
        self._path_opener(str(path))
        return path

    def open_case_folder(self, summary: DesktopAnalysisSummary | None = None) -> Path:
        selected = summary or self._last_summary
        if selected is None:
            raise DesktopValidationError("Folder sprawy nie jest dostępny.")
        path = self.validate_case_folder(selected.case_id, selected.case_folder_path)
        self._path_opener(str(path))
        return path

    def open_graph(self, summary: DesktopAnalysisSummary | None = None) -> Path:
        selected = summary or self._last_summary
        if selected is None or selected.graph_viewer_path is None:
            raise DesktopValidationError("Graf sprawy nie jest dostępny.")
        path = self.validate_graph_path(selected.case_id, selected.graph_viewer_path)
        self._path_opener(str(path))
        return path

    def validate_report_path(self, case_id: str, report_path: str) -> Path:
        path = Path(report_path).resolve()
        reports_directory = (self._application.case_store.root / case_id / "reports").resolve()
        if reports_directory not in path.parents or path.suffix.casefold() != ".html" or not path.is_file():
            raise DesktopValidationError("Nieprawidłowa ścieżka raportu HTML.")
        return path

    def validate_case_folder(self, case_id: str, folder_path: str) -> Path:
        path = Path(folder_path).resolve()
        expected = (self._application.case_store.root / case_id).resolve()
        if path != expected or not path.is_dir():
            raise DesktopValidationError("Nieprawidłowa ścieżka folderu sprawy.")
        return path

    def validate_graph_path(self, case_id: str, graph_path: str) -> Path:
        path = Path(graph_path).resolve()
        graph_directory = (self._application.case_store.root / case_id / "graph").resolve()
        if graph_directory not in path.parents or path.name != "graph_viewer.html" or not path.is_file():
            raise DesktopValidationError("Nieprawidłowa ścieżka grafu.")
        return path

    def record_error(self, error: Exception) -> None:
        log_directory = (self._application.case_store.root.parent / "logs").resolve()
        log_directory.mkdir(parents=True, exist_ok=True)
        traceback = error.__traceback__
        while traceback is not None and traceback.tb_next is not None:
            traceback = traceback.tb_next
        location = None
        if traceback is not None:
            code = traceback.tb_frame.f_code
            location = f"{Path(code.co_filename).name}:{traceback.tb_lineno}:{code.co_name}"
        payload = {
            "timestamp": self._now().isoformat(),
            "component": "desktop",
            "error_type": type(error).__name__,
            "location": location,
            "message": "Desktop analysis failed; raw identifiers intentionally omitted.",
        }
        line = json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"
        descriptor = os.open(log_directory / "desktop.jsonl", os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, line.encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _unique_case_id(self, value: datetime) -> str:
        base = value.strftime("lumir_%Y%m%d_%H%M%S")
        for index in range(100):
            candidate = base if index == 0 else f"{base}_{index:02d}"
            if not (self._application.case_store.root / candidate).exists():
                return candidate
        raise DesktopAnalysisError("Nie udało się utworzyć unikalnego identyfikatora sprawy.")

    @staticmethod
    def _seeds(values: DesktopInput) -> tuple[SeedEntity, ...]:
        fields = (
            ("PHONE", values.phone),
            ("EMAIL", values.email),
            ("USERNAME", values.username),
            ("DOMAIN", values.domain),
        )
        return tuple(
            SeedEntity(entity_type=entity_type, value=value.strip())
            for entity_type, value in fields
            if isinstance(value, str) and value.strip()
        )

    @staticmethod
    def _emit(callback: Callable[[str], None] | None, message: str) -> None:
        if callback is not None:
            callback(message)

    @staticmethod
    def _open_windows_path(path: str) -> None:
        startfile = getattr(os, "startfile", None)
        if startfile is None:
            raise OSError("Windows path opening is unavailable")
        startfile(path)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("desktop clock must return a timezone-aware datetime")
        return value
