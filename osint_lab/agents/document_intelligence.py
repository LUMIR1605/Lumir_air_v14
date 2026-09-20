"""Bounded text-only metadata extraction for public PDF/TXT/HTML documents."""

from datetime import datetime, timezone
from io import BytesIO
from pathlib import PurePosixPath
from typing import Callable, Mapping
from urllib.parse import urlsplit

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus

from .base import Collector, FindingCandidate, RawObservation
from .source_adapter_utils import DATE_PATTERN, DOMAIN_PATTERN, EMAIL_PATTERN, PHONE_PATTERN, parse_html
from .target_page_fetcher import FetchStatus, TargetPageFetcher, canonicalize_url


class DocumentIntelligenceCollector(Collector):
    agent_name = "document_intelligence"
    agent_type = "DOCUMENT"
    version = "1.0.0"
    source_class = SourceClass.PASSIVE_WEB
    network_required = True
    _TYPES = frozenset({"application/pdf", "text/plain", "text/html", "application/xhtml+xml"})

    def __init__(self, *, fetcher=None, clock: Callable[[], datetime] | None = None,
                 max_text_chars: int = 500_000) -> None:
        super().__init__()
        self._fetcher = fetcher or TargetPageFetcher(
            max_response_bytes=2_000_000, supported_content_types=self._TYPES,
        )
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if max_text_chars <= 0:
            raise ValueError("max_text_chars must be positive")
        self._max_text_chars = max_text_chars

    def validate_input(self, seed_reference: str) -> None:
        value = canonicalize_url(seed_reference)
        suffix = PurePosixPath(urlsplit(value).path).suffix.casefold()
        if suffix in {".exe", ".dll", ".msi", ".zip", ".rar", ".7z", ".docm", ".xlsm"}:
            raise ValueError("executable, archive and macro content is forbidden")

    def _run(self, context: ExecutionContext, seed_reference: str) -> tuple[RawObservation, ...]:
        url = canonicalize_url(seed_reference)
        result = self._fetcher.fetch(url)
        if result.fetch_status is not FetchStatus.SUCCESS:
            return (self._unknown(url, result.error_code or result.fetch_status.value),)
        try:
            text, metadata = self._text(result.content_type, result.body, result.raw_bytes, result.final_url or url)
        except (ValueError, ImportError):
            return (self._unknown(url, "PARSER_FAILURE"),)
        text = text[:self._max_text_chars]
        payload = {
            "source_id": "first_party_document", "source_role": "EVIDENCE",
            "source_reputation": "FIRST_PARTY", "document_url": result.final_url or url,
            "content_type": result.content_type, "title": metadata.get("title"),
            "author": metadata.get("author"), "emails": sorted(set(EMAIL_PATTERN.findall(text))),
            "phones": sorted(set(item.strip() for item in PHONE_PATTERN.findall(text))),
            "domains": sorted(set(item.casefold() for item in DOMAIN_PATTERN.findall(text))),
            "dates": sorted(set(DATE_PATTERN.findall(text))), "body_sha256": result.body_sha256,
            "text_chars": len(text), "collected_at": self._clock().isoformat(),
            "failure_status": "SUCCESS", "javascript_executed": False,
            "embedded_files_executed": False,
        }
        return (RawObservation(raw_status="FOUND", value_reference=f"document:{result.final_url or url}",
                               notes="Text-only public document metadata; old dates remain historical evidence.",
                               payload=payload),)

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        return FindingCandidate(raw_status=f"DOCUMENT_{observation.raw_status}",
            normalized_status=FindingStatus.POSSIBLE if observation.raw_status == "FOUND" else FindingStatus.UNKNOWN,
            value_reference=observation.value_reference, evidence_ref=observation.evidence_ref,
            notes="Extracted document contacts are occurrence evidence, not current ownership proof.")

    def describe_capabilities(self) -> Mapping[str, object]:
        return {"network": True, "method": "GET", "ssrf_protection": True,
                "max_bytes": 2_000_000, "pdf_text_only": True, "html_text_only": True,
                "archives": False, "macros": False, "javascript": False, "embedded_execution": False}

    @staticmethod
    def _text(content_type: str | None, body: str, raw: bytes, url: str) -> tuple[str, dict[str, object]]:
        if content_type in {"text/html", "application/xhtml+xml"}:
            parser = parse_html(body, url)
            return parser.visible_text, {"title": parser.title, "author": parser.meta.get("author")}
        if content_type == "text/plain":
            return body, {"title": PurePosixPath(urlsplit(url).path).name or None, "author": None}
        if content_type == "application/pdf":
            from pypdf import PdfReader
            reader = PdfReader(BytesIO(raw), strict=True)
            if reader.is_encrypted:
                raise ValueError("encrypted PDF unsupported")
            text = "\n".join((page.extract_text() or "") for page in reader.pages[:100])
            metadata = reader.metadata or {}
            return text, {"title": metadata.get("/Title"), "author": metadata.get("/Author")}
        raise ValueError("unsupported content type")

    @staticmethod
    def _unknown(url: str, reason: str) -> RawObservation:
        return RawObservation(raw_status="UNKNOWN", value_reference=f"document:{url}",
                              notes="Document processing was inconclusive or unsupported.",
                              payload={"source_id": "first_party_document",
                                       "failure_status": "UNSUPPORTED" if "UNSUPPORTED" in reason else reason,
                                       "error_reason": reason})
