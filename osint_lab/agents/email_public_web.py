"""Exact public email occurrence adapter with strict semantic validation."""

from datetime import datetime, timezone
import hashlib
from typing import Callable, Mapping
from urllib.parse import quote, urlsplit

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus

from .base import Collector, FindingCandidate, RawObservation
from .email_exposure import normalize_email
from .phone_public_http import RequestsPhonePublicHttpClient
from .source_adapter_utils import parse_html, parse_search_urls
from .target_page_fetcher import FetchStatus, TargetPageFetcher


class EmailPublicWebCollector(Collector):
    agent_name = "email_public_web"
    agent_type = "EMAIL"
    version = "1.0.0"
    source_class = SourceClass.PASSIVE_WEB
    network_required = True
    search_url = "https://html.duckduckgo.com/html/?q={query}"

    def __init__(self, *, search_client=None, target_fetcher=None,
                 clock: Callable[[], datetime] | None = None, max_targets: int = 5) -> None:
        super().__init__()
        self._search = search_client or RequestsPhonePublicHttpClient()
        self._fetcher = target_fetcher or TargetPageFetcher()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if max_targets <= 0:
            raise ValueError("max_targets must be positive")
        self._max_targets = max_targets

    def validate_input(self, seed_reference: str) -> None:
        normalize_email(seed_reference)

    def _run(self, context: ExecutionContext, seed_reference: str) -> tuple[RawObservation, ...]:
        email, local, domain = normalize_email(seed_reference)
        request_url = self.search_url.format(query=quote(f'"{email}"', safe=""))
        try:
            response = self._search.get(request_url, timeout=8.0,
                                        headers={"User-Agent": "LumirOSINTLab-EmailPublicWeb/1.0"})
        except Exception:
            return (self._unknown(email, "SEARCH_FAILURE"),)
        if response.status_code == 429:
            return (self._unknown(email, "RATE_LIMITED"),)
        if response.status_code != 200 or response.body_truncated:
            return (self._unknown(email, "SEARCH_UNKNOWN"),)
        urls = parse_search_urls(response.body, self._max_targets)
        observations = []
        for url in urls:
            result = self._fetcher.fetch(url)
            if result.fetch_status is not FetchStatus.SUCCESS:
                continue
            parser = parse_html(result.body, result.final_url or url)
            visible = parser.visible_text.casefold()
            exact = email.casefold() in visible
            structured = email.casefold() in {item.casefold() for item in parser.mailto}
            obfuscated_forms = (
                f"{local} [at] {domain}", f"{local} (at) {domain}", f"{local} at {domain}",
            )
            obfuscated = any(item.casefold() in visible for item in obfuscated_forms)
            username_only = local.casefold() in visible and not (exact or structured or obfuscated)
            if not (exact or structured or obfuscated):
                continue
            status = "STRUCTURED_EMAIL_MATCH" if structured else (
                "EXACT_EMAIL_MATCH" if exact else "OBFUSCATED_EMAIL_MATCH"
            )
            observations.append(RawObservation(
                raw_status=status, value_reference=f"email-public:{hashlib.sha256(email.encode()).hexdigest()}",
                notes="Public occurrence only; no ownership or identity inference.",
                payload={"source_id": "first_party_web", "source_role": "EVIDENCE",
                         "source_reputation": "FIRST_PARTY" if urlsplit(result.final_url or url).hostname == domain else "PUBLIC_PLATFORM",
                         "email": email, "target_url": result.final_url or url,
                         "match_type": status, "username_only": username_only,
                         "domain": domain, "body_sha256": result.body_sha256,
                         "collected_at": self._clock().isoformat(), "failure_status": "SUCCESS"},
            ))
        return tuple(observations) or (self._unknown(email, "NO_MATCH"),)

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        if observation.raw_status in {"EXACT_EMAIL_MATCH", "STRUCTURED_EMAIL_MATCH", "OBFUSCATED_EMAIL_MATCH"}:
            status = FindingStatus.POSSIBLE
        elif observation.payload.get("error_reason") == "NO_MATCH":
            status = FindingStatus.NOT_FOUND
        else:
            status = FindingStatus.UNKNOWN
        return FindingCandidate(raw_status=observation.raw_status, normalized_status=status,
                                value_reference=observation.value_reference,
                                evidence_ref=observation.evidence_ref,
                                notes="Exact/structured occurrence is evidence; obfuscation remains only POSSIBLE.")

    def describe_capabilities(self) -> Mapping[str, object]:
        return {"network": True, "method": "GET", "exact_email_match": True,
                "structured_mailto": True, "obfuscated_match": True, "ssrf_protection": True,
                "authentication": False, "captcha_bypass": False, "identity_confirmation": False,
                "max_targets": self._max_targets}

    @staticmethod
    def _unknown(email: str, reason: str) -> RawObservation:
        failure = "NO_MATCH" if reason == "NO_MATCH" else reason
        return RawObservation(raw_status="UNKNOWN", value_reference="email-public:" + hashlib.sha256(email.encode()).hexdigest(),
                              notes="Public email search was inconclusive.",
                              payload={"source_id": "duckduckgo_html", "failure_status": failure,
                                       "error_reason": reason})
