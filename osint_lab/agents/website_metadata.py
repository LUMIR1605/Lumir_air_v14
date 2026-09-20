"""SSRF-guarded public website metadata collector."""

from datetime import datetime, timezone
from typing import Callable, Mapping
from urllib.parse import urlsplit

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus

from .base import Collector, FindingCandidate, RawObservation
from .source_adapter_utils import DOMAIN_PATTERN, EMAIL_PATTERN, PHONE_PATTERN, parse_html
from .target_page_fetcher import FetchStatus, TargetPageFetcher, canonicalize_url


class WebsiteMetadataCollector(Collector):
    agent_name = "website_metadata"
    agent_type = "WEBSITE"
    version = "1.0.0"
    source_class = SourceClass.PASSIVE_WEB
    network_required = True

    def __init__(self, *, fetcher=None, clock: Callable[[], datetime] | None = None) -> None:
        super().__init__()
        self._fetcher = fetcher or TargetPageFetcher()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def validate_input(self, seed_reference: str) -> None:
        self._url(seed_reference)

    def _run(self, context: ExecutionContext, seed_reference: str) -> tuple[RawObservation, ...]:
        requested = self._url(seed_reference)
        result = self._fetcher.fetch(requested)
        if result.fetch_status is not FetchStatus.SUCCESS:
            return (RawObservation(raw_status="UNKNOWN", value_reference=f"website:{requested}",
                    notes="Website metadata fetch was inconclusive.",
                    payload={"source_id": "first_party_web", "failure_status": result.error_code or result.fetch_status.value}),)
        parser = parse_html(result.body, result.final_url or requested)
        organizations = list(parser.organizations())
        text = parser.visible_text
        payload = {
            "source_id": "first_party_web", "source_role": "EVIDENCE",
            "source_reputation": "FIRST_PARTY", "final_url": result.final_url,
            "redirect_chain": list(result.redirect_chain), "title": parser.title,
            "meta_description": parser.meta.get("description") or parser.meta.get("og:description"),
            "canonical": parser.canonical, "server_header": (result.response_headers or {}).get("server"),
            "content_language": parser.language or (result.response_headers or {}).get("content-language"),
            "tls": dict(result.tls_certificate or {}), "organizations": organizations,
            "public_emails": sorted(set(EMAIL_PATTERN.findall(text)) | set(parser.mailto)),
            "public_phones": sorted(set(item.strip() for item in PHONE_PATTERN.findall(text))),
            "linked_domains": sorted({urlsplit(item).hostname for item in parser.links if urlsplit(item).hostname}),
            "body_sha256": result.body_sha256, "collected_at": self._clock().isoformat(),
            "failure_status": "SUCCESS",
        }
        return (RawObservation(raw_status="FOUND", value_reference=f"website:{result.final_url or requested}",
                               notes="Public first-party page metadata; publication does not guarantee truth.",
                               payload=payload),)

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        return FindingCandidate(raw_status=f"WEBSITE_{observation.raw_status}",
            normalized_status=FindingStatus.POSSIBLE if observation.raw_status == "FOUND" else FindingStatus.UNKNOWN,
            value_reference=observation.value_reference, evidence_ref=observation.evidence_ref,
            notes="Website metadata is technical/textual evidence, not an identity conclusion.")

    def describe_capabilities(self) -> Mapping[str, object]:
        return {"network": True, "method": "GET", "ssrf_protection": True,
                "redirect_guard": True, "html_metadata": True, "tls_metadata": True,
                "structured_organization": True, "authentication": False, "javascript": False}

    @staticmethod
    def _url(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("website input must be non-empty")
        candidate = value.strip()
        if "://" not in candidate:
            domain = candidate.casefold().rstrip(".")
            if DOMAIN_PATTERN.fullmatch(domain) is None:
                raise ValueError("website input must be an HTTP(S) URL or qualified domain")
            candidate = "https://" + domain + "/"
        return canonicalize_url(candidate)
