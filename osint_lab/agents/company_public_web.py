"""Conservative public company-page discovery with exact structured-name validation."""

from datetime import datetime, timezone
import hashlib
from typing import Callable, Mapping
from urllib.parse import quote, urlsplit

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus
from osint_lab.graph.models import GraphEntityType
from osint_lab.sources.discovery import MultiProviderDiscoveryEngine

from .base import Collector, FindingCandidate, RawObservation
from .phone_public_http import RequestsPhonePublicHttpClient
from .source_adapter_utils import EMAIL_PATTERN, PHONE_PATTERN, parse_html, parse_search_urls
from .target_page_fetcher import FetchStatus, TargetPageFetcher


class CompanyPublicWebCollector(Collector):
    agent_name = "company_public_web"
    agent_type = "COMPANY"
    version = "1.0.0"
    source_class = SourceClass.PASSIVE_WEB
    network_required = True
    search_url = "https://html.duckduckgo.com/html/?q={query}"

    def __init__(self, *, search_client=None, target_fetcher=None,
                 clock: Callable[[], datetime] | None = None, max_targets: int = 4,
                 discovery_engine: MultiProviderDiscoveryEngine | None = None) -> None:
        super().__init__()
        self._search = search_client or RequestsPhonePublicHttpClient()
        self._fetcher = target_fetcher or TargetPageFetcher()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_targets = max_targets
        self._discovery_engine = discovery_engine

    def validate_input(self, seed_reference: str) -> None:
        if not isinstance(seed_reference, str) or not 2 <= len(seed_reference.strip()) <= 200:
            raise ValueError("company name must contain 2-200 characters")

    def _run(self, context: ExecutionContext, seed_reference: str) -> tuple[RawObservation, ...]:
        name = " ".join(seed_reference.split())
        output = []
        if self._discovery_engine is not None:
            run = self._discovery_engine.discover(
                case_id=context.case_id, entity_type=GraphEntityType.COMPANY, value=name)
            urls = tuple(item.url for item in run.results[:self._max_targets])
            output.extend(self._provider_observation(name, item, run.coverage.to_dict())
                          for item in run.provider_responses)
        else:
            request_url = self.search_url.format(query=quote(f'"{name}" kontakt', safe=""))
            try:
                response = self._search.get(request_url, timeout=8.0,
                                            headers={"User-Agent": "LumirOSINTLab-CompanyPublicWeb/1.0"})
            except Exception:
                return (self._unknown(name, "SEARCH_FAILURE"),)
            if response.status_code != 200 or response.body_truncated:
                return (self._unknown(name, "RATE_LIMITED" if response.status_code == 429 else "SEARCH_UNKNOWN"),)
            urls = parse_search_urls(response.body, self._max_targets)
        for url in urls:
            result = self._fetcher.fetch(url)
            if result.fetch_status is not FetchStatus.SUCCESS:
                continue
            parser = parse_html(result.body, result.final_url or url)
            organizations = [item for item in parser.organizations()
                             if isinstance(item.get("name"), str)
                             and self._normalized(str(item["name"])) == self._normalized(name)]
            if not organizations:
                continue
            text = parser.visible_text
            host = (urlsplit(result.final_url or url).hostname or "").casefold()
            output.append(RawObservation(
                raw_status="STRUCTURED_COMPANY_MATCH",
                value_reference="company-public:" + hashlib.sha256(name.casefold().encode()).hexdigest(),
                notes="Exact structured organization name on a public page; no person association.",
                payload={"source_id": "first_party_web", "source_role": "EVIDENCE",
                         "source_reputation": "FIRST_PARTY", "company_name": name,
                         "target_url": result.final_url or url, "domain": host,
                         "organizations": organizations,
                         "emails": sorted(set(EMAIL_PATTERN.findall(text))),
                         "phones": sorted(set(item.strip() for item in PHONE_PATTERN.findall(text))),
                         "body_sha256": result.body_sha256, "match_type": "EXACT_STRUCTURED_NAME",
                         "collected_at": self._clock().isoformat(), "failure_status": "SUCCESS"},
            ))
        return tuple(output) or (self._unknown(name, "NO_MATCH"),)

    @staticmethod
    def _provider_observation(name, response, coverage):
        failure = {
            "SUCCESS": "SUCCESS", "NO_RESULTS": "NO_MATCH", "AUTH_REQUIRED": "AUTH_REQUIRED",
            "RATE_LIMITED": "RATE_LIMITED", "TIMEOUT": "TIMEOUT", "PARSER_ERROR": "PARSER_FAILURE",
        }.get(response.status.value, "UNKNOWN")
        return RawObservation(
            raw_status="DISCOVERY_STATUS", value_reference="company-discovery:" +
            hashlib.sha256(f"{response.provider_id}|{name}".encode()).hexdigest(),
            notes="Search result is discovery only and is not evidence.",
            payload={"source_id": response.provider_id, "provider_id": response.provider_id,
                     "source_role": "DISCOVERY", "stage": "SEARCH_DISCOVERY",
                     "provider_status": response.status.value, "failure_status": failure,
                     "query_id": response.query_id,
                     "query_sha256": hashlib.sha256(response.query_text.encode()).hexdigest(),
                     "result_count": len(response.results), "error_code": response.error_code,
                     "discovery_coverage": coverage},
        )

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        return FindingCandidate(raw_status=observation.raw_status,
            normalized_status=FindingStatus.POSSIBLE if observation.raw_status == "STRUCTURED_COMPANY_MATCH"
            else (FindingStatus.NOT_FOUND if observation.payload.get("error_reason") == "NO_MATCH"
                  else FindingStatus.UNKNOWN),
            value_reference=observation.value_reference, evidence_ref=observation.evidence_ref,
            notes="Structured company match only; company names are never auto-merged with people.")

    def describe_capabilities(self) -> Mapping[str, object]:
        return {"network": True, "method": "GET", "structured_company_match": True,
                "ssrf_protection": True, "fuzzy_auto_merge": False, "identity_confirmation": False,
                "authentication": False, "max_targets": self._max_targets}

    @staticmethod
    def _normalized(value: str) -> str:
        return " ".join(value.casefold().split())

    @staticmethod
    def _unknown(name: str, reason: str) -> RawObservation:
        return RawObservation(raw_status="UNKNOWN",
                              value_reference="company-public:" + hashlib.sha256(name.casefold().encode()).hexdigest(),
                              notes="Public company search was inconclusive.",
                              payload={"source_id": "duckduckgo_html", "failure_status": reason,
                                       "error_reason": reason})
