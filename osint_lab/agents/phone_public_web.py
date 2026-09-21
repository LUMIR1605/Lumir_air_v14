"""Exact-match public web occurrence collector for phone numbers."""

from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Mapping
from urllib.parse import quote, urlsplit

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus
from osint_lab.graph.models import GraphEntityType
from osint_lab.sources.discovery import (
    BraveSearchConfig, DiscoveryProviderStatus, MultiProviderDiscoveryEngine,
)

from .base import Collector, FindingCandidate, RawObservation
from .phone_public_extract import extract_discovered_entities
from .phone_public_http import (
    PhonePublicHttpConnectionError,
    PhonePublicHttpResponse,
    PhonePublicHttpTimeout,
    RequestsPhonePublicHttpClient,
)
from .phone_public_parsers import ParsedPhonePublicResult, parse_phone_public_results, parse_target_page
from .phone_public_providers import DEFAULT_PHONE_PUBLIC_PROVIDERS, PhonePublicProvider
from .phone_public_semantics import PhoneMatchLevel, TargetPhoneValidator
from .phone_variants import PhoneVariant, generate_phone_variants
from .target_page_analysis import classify_page_role, normalized_visible_text_hash
from .target_page_fetcher import FetchStatus, TargetPageFetcher, canonicalize_url


@dataclass(frozen=True, kw_only=True)
class _DiscoveryCandidate:
    provider: PhonePublicProvider
    query_variant: PhoneVariant
    result: ParsedPhonePublicResult
    discovery_body_sha256: str
    discovered_at: datetime
    query_id: str | None = None
    query_text: str | None = None
    result_hash: str | None = None
    source_channels: tuple[str, ...] = ()
    result_rank: int | None = None


class PhonePublicWebCollector(Collector):
    """Find exact public occurrences without inferring a subscriber or owner."""

    agent_name = "phone_public_web"
    agent_type = "PHONE"
    version = "1.1.0"
    source_class = SourceClass.PASSIVE_WEB
    network_required = True
    default_region = "PL"
    _USER_AGENT = "LumirOSINTLab-PhonePublicWeb/1.0"

    def __init__(
        self,
        *,
        providers: tuple[PhonePublicProvider, ...] = DEFAULT_PHONE_PUBLIC_PROVIDERS,
        http_client=None,
        target_fetcher: TargetPageFetcher | None = None,
        target_validator: TargetPhoneValidator | None = None,
        clock: Callable[[], datetime] | None = None,
        max_targets_per_provider: int = 3,
        max_targets_total: int = 8,
        max_targets_per_host: int = 3,
        discovery_engine: MultiProviderDiscoveryEngine | None = None,
    ) -> None:
        super().__init__()
        if not isinstance(providers, tuple) or any(not isinstance(item, PhonePublicProvider) for item in providers):
            raise ValueError("providers must contain PhonePublicProvider values")
        if len({item.provider_id for item in providers}) != len(providers):
            raise ValueError("provider_id values must be unique")
        self._providers = providers
        self._http_client = http_client or RequestsPhonePublicHttpClient()
        if not hasattr(self._http_client, "get"):
            raise ValueError("http_client must provide get()")
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._target_fetcher = target_fetcher or TargetPageFetcher(clock=self._clock)
        if not hasattr(self._target_fetcher, "fetch"):
            raise ValueError("target_fetcher must provide fetch()")
        self._target_validator = target_validator or TargetPhoneValidator()
        for name, value in (
            ("max_targets_per_provider", max_targets_per_provider),
            ("max_targets_total", max_targets_total),
            ("max_targets_per_host", max_targets_per_host),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self._max_targets_per_provider = max_targets_per_provider
        self._max_targets_total = max_targets_total
        self._max_targets_per_host = max_targets_per_host
        if discovery_engine is not None and not isinstance(discovery_engine, MultiProviderDiscoveryEngine):
            raise ValueError("discovery_engine must be MultiProviderDiscoveryEngine")
        self._discovery_engine = discovery_engine

    def validate_input(self, seed_reference: str) -> None:
        generate_phone_variants(seed_reference, default_region=self.default_region)

    def _run(self, context: ExecutionContext, seed_reference: str) -> tuple[RawObservation, ...]:
        variants = generate_phone_variants(seed_reference, default_region=self.default_region)
        if self._discovery_engine is not None:
            return self._run_multi_provider(context, seed_reference, variants)
        observations: list[RawObservation] = []
        grouped_candidates: dict[str, list[_DiscoveryCandidate]] = {}
        for provider in self._providers:
            if not provider.enabled:
                continue
            candidates, status_observation = self._discover_provider(provider, variants)
            if status_observation is not None:
                observations.append(status_observation)
            for candidate in candidates:
                try:
                    key = canonicalize_url(candidate.result.result_url)
                except (ValueError, PermissionError):
                    key = candidate.result.result_url.casefold().rstrip("/")
                grouped_candidates.setdefault(key, []).append(candidate)
        host_counts: dict[str, int] = {}
        for _, candidates in list(grouped_candidates.items())[:self._max_targets_total]:
            host = (urlsplit(candidates[0].result.result_url).hostname or "").casefold()
            if host_counts.get(host, 0) >= self._max_targets_per_host:
                observations.append(self._target_limit_observation(candidates, variants, "PER_HOST_TARGET_LIMIT"))
                continue
            host_counts[host] = host_counts.get(host, 0) + 1
            observations.append(self._validate_target(candidates, variants))
        return tuple(observations)

    def _run_multi_provider(
        self,
        context: ExecutionContext,
        seed_reference: str,
        variants: tuple[PhoneVariant, ...],
    ) -> tuple[RawObservation, ...]:
        queries = self._discovery_engine.query_engine.phone_queries(seed_reference, variants)
        run = self._discovery_engine.discover(
            case_id=context.case_id,
            entity_type=GraphEntityType.PHONE,
            value=variants[0].canonical_e164,
            queries=queries,
        )
        coverage = run.coverage.to_dict()
        observations: list[RawObservation] = []
        responses_by_provider: dict[str, list[object]] = {}
        for item in run.provider_responses:
            responses_by_provider.setdefault(item.provider_id, []).append(item)
        for provider_id, responses in responses_by_provider.items():
            response = next((item for item in responses
                             if item.status is DiscoveryProviderStatus.SUCCESS), None)
            if response is None and all(item.status is DiscoveryProviderStatus.NO_RESULTS
                                        for item in responses):
                response = responses[0]
            if response is None:
                response = next((item for item in responses
                                 if item.status is not DiscoveryProviderStatus.NO_RESULTS), responses[0])
            result_count = sum(len(item.results) for item in responses)
            raw_status = {
                DiscoveryProviderStatus.SUCCESS: "NO_MATCH" if result_count == 0 else "UNKNOWN",
                DiscoveryProviderStatus.NO_RESULTS: "NO_MATCH",
            }.get(response.status, "UNKNOWN")
            observations.append(self._status_observation(
                provider=self._provider_metadata(provider_id), variants=variants,
                status=raw_status,
                base={
                    "source_id": provider_id,
                    "source_role": "DISCOVERY",
                    "failure_status": self._failure_status(response.status),
                    "provider_status": response.status.value,
                    "query_id": response.query_id,
                    "query_sha256": hashlib.sha256(response.query_text.encode("utf-8")).hexdigest(),
                    "http_status": response.http_status,
                    "requests_made": sum(item.requests_made for item in responses),
                    "result_count": result_count,
                    "discovery_queries": [item.to_dict() for item in responses],
                    "discovery_coverage": coverage,
                },
                error_code=response.error_code,
                error_reason=(response.error_code or response.status.value),
            ))
        grouped: dict[str, list[_DiscoveryCandidate]] = {}
        canonical_variant = variants[0]
        for item in run.results:
            provider = self._provider_metadata(item.provider_id)
            parsed = ParsedPhonePublicResult(
                result_url=item.url, page_title=item.title, snippet=item.snippet,
                visible_text=f"{item.title or ''} {item.snippet}", source_date=None,
                html_fragment="", page_html="",
            )
            candidate = _DiscoveryCandidate(
                provider=provider, query_variant=canonical_variant, result=parsed,
                discovery_body_sha256=item.result_hash, discovered_at=item.discovered_at,
                query_id=item.query_id, query_text=item.query_text,
                result_hash=item.result_hash, source_channels=item.source_channels,
                result_rank=item.rank,
            )
            grouped.setdefault(item.url, []).append(candidate)
        host_counts: dict[str, int] = {}
        for candidates in list(grouped.values())[:self._max_targets_total]:
            host = (urlsplit(candidates[0].result.result_url).hostname or "").casefold()
            if host_counts.get(host, 0) >= self._max_targets_per_host:
                observations.append(self._target_limit_observation(candidates, variants, "PER_HOST_TARGET_LIMIT"))
                continue
            host_counts[host] = host_counts.get(host, 0) + 1
            result = self._validate_target(candidates, variants)
            observations.append(RawObservation(
                raw_status=result.raw_status, value_reference=result.value_reference,
                evidence_ref=result.evidence_ref, notes=result.notes,
                payload={**dict(result.payload), "discovery_coverage": coverage,
                         "source_id": "first_party_web", "source_role": "EVIDENCE"},
            ))
        return tuple(observations)

    @staticmethod
    def _failure_status(status: DiscoveryProviderStatus) -> str:
        return {
            DiscoveryProviderStatus.SUCCESS: "SUCCESS",
            DiscoveryProviderStatus.NO_RESULTS: "NO_MATCH",
            DiscoveryProviderStatus.AUTH_REQUIRED: "AUTH_REQUIRED",
            DiscoveryProviderStatus.RATE_LIMITED: "RATE_LIMITED",
            DiscoveryProviderStatus.CHALLENGE: "UNKNOWN",
            DiscoveryProviderStatus.TIMEOUT: "TIMEOUT",
            DiscoveryProviderStatus.HTTP_ERROR: "UNKNOWN",
            DiscoveryProviderStatus.PARSER_ERROR: "PARSER_FAILURE",
            DiscoveryProviderStatus.UNKNOWN: "UNKNOWN",
        }[status]

    @staticmethod
    def _provider_metadata(provider_id: str) -> PhonePublicProvider:
        existing = next((item for item in DEFAULT_PHONE_PUBLIC_PROVIDERS
                         if item.provider_id == provider_id), None)
        if existing is not None:
            return existing
        return PhonePublicProvider(
            provider_id=provider_id, name="Brave Search API",
            search_url_template="https://api.search.brave.com/res/v1/web/search?q={query}",
            method="GET", source_class=SourceClass.PASSIVE_WEB,
            exact_match_required=True, enabled=True, reviewed_at="2026-09-21", timeout=8.0,
            privacy_notes="Provider receives the bounded search query and network metadata.",
            terms_limitations_note="Official API; authenticated and locally budgeted.",
            result_parser="brave-web-json-v1", notes="Discovery only; target validation is required.",
            home_url="https://api.search.brave.com/",
        )

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        if not isinstance(observation, RawObservation):
            raise ValueError("RawObservation required")
        status = observation.payload.get("status")
        normalized = {
            "MATCH": FindingStatus.POSSIBLE,
            "NO_MATCH": FindingStatus.NOT_FOUND,
            "UNKNOWN": FindingStatus.UNKNOWN,
            "ERROR": FindingStatus.UNKNOWN,
        }.get(status, FindingStatus.UNKNOWN)
        return FindingCandidate(
            raw_status=f"PHONE_PUBLIC_{status or 'UNKNOWN'}",
            normalized_status=normalized,
            value_reference=observation.value_reference,
            evidence_ref=observation.evidence_ref,
            notes="Public occurrence only; possible association, not independently verified ownership or identity.",
        )

    def describe_capabilities(self) -> Mapping[str, object]:
        if self._providers == DEFAULT_PHONE_PUBLIC_PROVIDERS:
            brave_config = BraveSearchConfig.from_environment()
            payload = [asdict(provider) for provider in self._providers]
            payload.append({"provider_id": "brave_search_api", "config": brave_config.public_dict()})
            provider_ids = ["brave_search_api", *[item.provider_id for item in self._providers]]
            enabled_ids = (["brave_search_api"] if brave_config.api_key_present else []) + [
                item.provider_id for item in self._providers if item.enabled
            ]
        else:
            payload = [asdict(provider) for provider in self._providers]
            provider_ids = [item.provider_id for item in self._providers]
            enabled_ids = [item.provider_id for item in self._providers if item.enabled]
        provider_hash = hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        return {
            "network": True,
            "method": "GET",
            "providers": provider_ids,
            "enabled_providers": enabled_ids,
            "provider_config_sha256": provider_hash,
            "exact_phone_match": True,
            "target_page_fetch": True,
            "ssrf_protection": True,
            "max_targets_per_provider": self._max_targets_per_provider,
            "max_targets_total": self._max_targets_total,
            "max_targets_per_host": self._max_targets_per_host,
            "entity_extraction": True,
            "browser_automation": False,
            "authentication": False,
            "captcha_bypass": False,
            "identity_confirmation": False,
            "multi_provider_discovery": self._providers == DEFAULT_PHONE_PUBLIC_PROVIDERS,
            "discovery_budget": {
                "max_queries_per_entity": 8, "max_queries_per_provider": 6,
                "max_results_per_query": 10, "max_unique_candidates": 30,
                "max_unique_domains": 15, "max_candidates_per_domain": 3,
            } if self._providers == DEFAULT_PHONE_PUBLIC_PROVIDERS else None,
        }

    def _discover_provider(
        self,
        provider: PhonePublicProvider,
        variants: tuple[PhoneVariant, ...],
    ) -> tuple[tuple[_DiscoveryCandidate, ...], RawObservation | None]:
        candidates: dict[str, _DiscoveryCandidate] = {}
        statuses: list[RawObservation] = []
        for variant in variants:
            discovered, status = self._discover_variant(provider, variant, variants)
            if status is not None:
                statuses.append(status)
            for candidate in discovered:
                try:
                    key = canonicalize_url(candidate.result.result_url)
                except (ValueError, PermissionError):
                    key = candidate.result.result_url.casefold().rstrip("/")
                candidates.setdefault(key, candidate)
                if len(candidates) >= self._max_targets_per_provider:
                    break
            if len(candidates) >= self._max_targets_per_provider:
                break
        if candidates:
            return tuple(candidates.values()), None
        if statuses and all(item.raw_status == "NO_MATCH" for item in statuses):
            return (), statuses[0]
        if statuses and all(item.raw_status == "ERROR" for item in statuses):
            return (), statuses[0]
        unknown = next((item for item in statuses if item.raw_status == "UNKNOWN"), None)
        return (), unknown or (statuses[0] if statuses else None)

    def _discover_variant(
        self,
        provider: PhonePublicProvider,
        query_variant: PhoneVariant,
        variants: tuple[PhoneVariant, ...],
    ) -> tuple[tuple[_DiscoveryCandidate, ...], RawObservation | None]:
        query = quote(f'"{query_variant.variant}"', safe="")
        request_url = provider.search_url_template.format(query=query)
        base = {
            "provider_id": provider.provider_id,
            "provider_name": provider.name,
            "canonical_phone": query_variant.canonical_e164,
            "query_variant": query_variant.variant,
            "query_variant_type": query_variant.variant_type,
            "request_url": request_url,
            "request_method": provider.method,
            "source_class": provider.source_class.value,
            "privacy_notes": provider.privacy_notes,
            "collector_version": self.version,
            "collected_at": self._now().isoformat(),
            "stage": "SEARCH_DISCOVERY",
            "discovery_only": True,
            "reviewed_at": provider.reviewed_at,
            "terms_limitations_note": provider.terms_limitations_note,
        }
        try:
            response = self._http_client.get(
                request_url,
                timeout=provider.timeout,
                headers={"User-Agent": self._USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
            )
        except PhonePublicHttpTimeout:
            return (), self._status_observation(provider=provider, variants=variants, base=base, status="UNKNOWN",
                                                error_code="TIMEOUT", error_reason="Public provider timed out.")
        except PhonePublicHttpConnectionError:
            return (), self._status_observation(provider=provider, variants=variants, base=base, status="UNKNOWN",
                                                error_code="CONNECTION_ERROR",
                                                error_reason="Public provider request failed.")
        except Exception as error:
            return (), self._status_observation(provider=provider, variants=variants, base=base, status="ERROR",
                                                error_code=type(error).__name__.upper(),
                                                error_reason="HTTP client raised an unexpected technical error.")
        if not isinstance(response, PhonePublicHttpResponse):
            return (), self._status_observation(provider=provider, variants=variants, base=base, status="ERROR",
                                                error_code="MALFORMED_RESPONSE",
                                                error_reason="HTTP client returned an invalid response.")
        body_hash = hashlib.sha256(response.body.encode("utf-8")).hexdigest()
        response_base = {
            **base,
            "http_status": response.status_code,
            "final_url": response.final_url,
            "redirected": response.redirected,
            "body_sha256": body_hash,
            "body_truncated": response.body_truncated,
        }
        body_casefold = response.body.casefold()
        if any(signal.casefold() in body_casefold for signal in provider.challenge_signals):
            return (), self._status_observation(provider=provider, variants=variants, base=response_base,
                                                status="UNKNOWN", error_code="CHALLENGE",
                                                error_reason="CAPTCHA, rate-limit, or JS challenge detected.")
        if response.status_code in {403, 429}:
            return (), self._status_observation(provider=provider, variants=variants, base=response_base,
                                                status="UNKNOWN", error_code=f"HTTP_{response.status_code}",
                                                error_reason="HTTP denial is not a NO_MATCH.")
        if response.status_code >= 500:
            return (), self._status_observation(provider=provider, variants=variants, base=response_base,
                                                status="UNKNOWN", error_code="HTTP_SERVER_ERROR",
                                                error_reason="Provider server failure is inconclusive.")
        if not 200 <= response.status_code < 300:
            return (), self._status_observation(provider=provider, variants=variants, base=response_base,
                                                status="UNKNOWN", error_code="UNEXPECTED_HTTP_STATUS",
                                                error_reason="Unexpected HTTP status is inconclusive.")
        if self._redirected_to_home(provider, response):
            return (), self._status_observation(provider=provider, variants=variants, base=response_base,
                                                status="UNKNOWN", error_code="REDIRECT_HOME",
                                                error_reason="Provider redirected to a generic homepage.")
        if any(signal.casefold() in body_casefold for signal in provider.no_match_signals):
            return (), self._status_observation(provider=provider, variants=variants, base=response_base,
                                                status="NO_MATCH", error_code=None,
                                                error_reason="Provider returned its reviewed no-results signal.")
        try:
            results = parse_phone_public_results(
                provider.result_parser,
                body=response.body,
                final_url=response.final_url,
            )
        except Exception as error:
            return (), self._status_observation(provider=provider, variants=variants, base=response_base,
                                                status="ERROR", error_code=type(error).__name__.upper(),
                                                error_reason="Reviewed result parser failed.")
        if not results:
            return (), self._status_observation(provider=provider, variants=variants, base=response_base,
                                                status="UNKNOWN", error_code="GENERIC_PAGE",
                                                error_reason="No reviewed result container was found.")
        discovered_at = self._now()
        candidates = tuple(
            _DiscoveryCandidate(
                provider=provider,
                query_variant=query_variant,
                result=item,
                discovery_body_sha256=body_hash,
                discovered_at=discovered_at,
            )
            for item in results
        )
        return candidates, None

    def _validate_target(
        self,
        candidates: list[_DiscoveryCandidate],
        variants: tuple[PhoneVariant, ...],
    ) -> RawObservation:
        primary = candidates[0]
        fetch = self._target_fetcher.fetch(primary.result.result_url)
        discoveries = [self._discovery_metadata(item) for item in candidates]
        base = {
            "provider_id": primary.provider.provider_id,
            "provider_name": primary.provider.name,
            "canonical_phone": variants[0].canonical_e164,
            "collector_version": self.version,
            "stage": "TARGET_PAGE_VALIDATION",
            "discovery_only": False,
            "discovery_provider": primary.provider.provider_id,
            "discovery_query_variant": primary.query_variant.variant,
            "discovery_result_url": primary.result.result_url,
            "discovery_channels": discoveries,
            "target_fetch": fetch.to_metadata(),
            "target_verified": False,
            "collected_at": self._now().isoformat(),
        }
        if fetch.fetch_status is not FetchStatus.SUCCESS or not fetch.final_url:
            evidence_ref = self._target_evidence_ref(primary.result.result_url, fetch.body_sha256 or fetch.error_code)
            return self._observation(
                base={
                    **base,
                    "status": "UNKNOWN",
                    "exact_match": False,
                    "numeric_exact_match": False,
                    "match_level": PhoneMatchLevel.SEARCH_DISCOVERY_ONLY.value,
                    "semantic_match": False,
                    "matched_variant": None,
                    "matched_variant_type": None,
                    "match_location": None,
                    "semantic_reason": "Target page could not be safely verified.",
                    "result_url": primary.result.result_url,
                    "source_domain": (urlsplit(primary.result.result_url).hostname or "").casefold() or None,
                    "source_date": "UNKNOWN",
                    "page_role": "UNKNOWN",
                    "discovered_entities": [],
                },
                status="UNKNOWN",
                evidence_ref=evidence_ref,
                error_code=fetch.error_code or fetch.fetch_status.value,
                error_reason="Target page could not be safely verified.",
            )
        parsed = parse_target_page(body=fetch.body, final_url=fetch.final_url)
        target_url = self._sensible_canonical(parsed.canonical_url, fetch.final_url)
        if target_url != parsed.result_url:
            parsed = ParsedPhonePublicResult(**{**parsed.__dict__, "result_url": target_url})
        semantic = self._target_validator.validate(parsed, variants)
        matched = semantic.matched_variant
        location = semantic.match_location
        source_domain = (urlsplit(target_url).hostname or "").casefold() or None
        visible_hash = normalized_visible_text_hash(parsed.visible_text)
        evidence_ref = self._target_evidence_ref(target_url, fetch.body_sha256)
        page_role = classify_page_role(parsed).value
        match_payload = {
            **base,
            "target_verified": semantic.accepted,
            "target_final_url": fetch.final_url,
            "target_canonical_url": target_url,
            "target_domain": source_domain,
            "target_body_sha256": fetch.body_sha256,
            "normalized_visible_text_sha256": visible_hash,
            "target_match_type": semantic.level.value,
            "target_signal_type": semantic.signal_type,
            "signal_path": semantic.signal_path,
            "normalized_phone": semantic.normalized_phone,
            "raw_visible_value": semantic.raw_visible_value,
            "context_before": semantic.context_before,
            "matched_text": semantic.matched_text,
            "context_after": semantic.context_after,
            "context_snippet": self._context_snippet(semantic),
            "page_role": page_role,
            "body_sha256": fetch.body_sha256,
            "content_hash": fetch.body_sha256,
            "result_url": target_url,
            "source_domain": source_domain,
            "page_title": parsed.page_title,
            "source_date": parsed.source_date or "UNKNOWN",
            "source_date_warning": self._source_date_warning(parsed.source_date),
            "exact_match": semantic.accepted,
            "numeric_exact_match": matched is not None,
            "match_level": semantic.level.value,
            "semantic_match": semantic.accepted,
            "matched_variant": matched.variant if matched else None,
            "matched_variant_type": matched.variant_type if matched else None,
            "match_location": location,
            "semantic_reason": semantic.reason,
        }
        if not semantic.accepted:
            error_code = {
                PhoneMatchLevel.REJECTED_NUMERIC_ID: "REJECTED_NUMERIC_ID",
                PhoneMatchLevel.NUMERIC_MATCH: "PHONE_CONTEXT_MISSING",
                PhoneMatchLevel.NUMERIC_MATCH_ONLY: "PHONE_CONTEXT_MISSING",
                PhoneMatchLevel.UNKNOWN: "NON_EXACT_CANDIDATE",
            }.get(semantic.level, "SEMANTIC_MATCH_UNKNOWN")
            return self._observation(
                base={
                    **match_payload,
                    "status": "UNKNOWN",
                    "discovered_entities": [],
                },
                status="UNKNOWN",
                evidence_ref=evidence_ref,
                error_code=error_code,
                error_reason=semantic.reason,
            )
        entities = extract_discovered_entities(parsed, evidence_ref=evidence_ref)
        return self._observation(
            base={
                **match_payload,
                "status": "MATCH",
                "discovered_entities": [item.to_dict() for item in entities],
            },
            status="MATCH",
            evidence_ref=evidence_ref,
        )

    def _target_limit_observation(
        self,
        candidates: list[_DiscoveryCandidate],
        variants: tuple[PhoneVariant, ...],
        error_code: str,
    ) -> RawObservation:
        primary = candidates[0]
        return self._observation(
            base={
                "provider_id": primary.provider.provider_id,
                "provider_name": primary.provider.name,
                "canonical_phone": variants[0].canonical_e164,
                "stage": "TARGET_PAGE_VALIDATION",
                "status": "UNKNOWN",
                "exact_match": False,
                "numeric_exact_match": False,
                "match_level": PhoneMatchLevel.SEARCH_DISCOVERY_ONLY.value,
                "semantic_match": False,
                "matched_variant": None,
                "matched_variant_type": None,
                "match_location": None,
                "result_url": primary.result.result_url,
                "source_domain": (urlsplit(primary.result.result_url).hostname or "").casefold() or None,
                "source_date": "UNKNOWN",
                "page_role": "UNKNOWN",
                "discovery_channels": [self._discovery_metadata(item) for item in candidates],
                "target_verified": False,
                "discovered_entities": [],
            },
            status="UNKNOWN",
            error_code=error_code,
            error_reason="Target page was not fetched because the bounded run limit was reached.",
        )

    @staticmethod
    def _discovery_metadata(candidate: _DiscoveryCandidate) -> dict[str, object]:
        return {
            "provider_id": candidate.provider.provider_id,
            "provider_name": candidate.provider.name,
            "query_variant": candidate.query_variant.variant,
            "query_variant_type": candidate.query_variant.variant_type,
            "result_url": candidate.result.result_url,
            "result_title": candidate.result.page_title,
            "result_snippet": candidate.result.snippet[:500],
            "discovery_body_sha256": candidate.discovery_body_sha256,
            "discovered_at": candidate.discovered_at.isoformat(),
            "query_id": candidate.query_id,
            "query_text": candidate.query_text,
            "result_hash": candidate.result_hash,
            "source_channels": list(candidate.source_channels),
            "rank": candidate.result_rank,
        }

    @staticmethod
    def _target_evidence_ref(url: str, fingerprint: str | None) -> str:
        return "phone-target:" + hashlib.sha256(f"{url}|{fingerprint or 'UNKNOWN'}".encode("utf-8")).hexdigest()

    @staticmethod
    def _sensible_canonical(canonical: str | None, final_url: str) -> str:
        final = canonicalize_url(final_url)
        if not canonical:
            return final
        try:
            candidate = canonicalize_url(canonical)
        except (ValueError, PermissionError):
            return final
        return candidate if urlsplit(candidate).hostname == urlsplit(final).hostname else final

    @staticmethod
    def _context_snippet(semantic) -> str | None:
        values = (semantic.context_before, semantic.matched_text, semantic.context_after)
        text = " ".join(item.strip() for item in values if isinstance(item, str) and item.strip())
        return text[:300] or None

    def _status_observation(
        self,
        *,
        provider: PhonePublicProvider,
        variants: tuple[PhoneVariant, ...],
        status: str,
        base: Mapping[str, object] | None = None,
        error_code: str | None,
        error_reason: str,
    ) -> RawObservation:
        canonical = variants[0].canonical_e164
        payload = {
            "provider_id": provider.provider_id,
            "provider_name": provider.name,
            "canonical_phone": canonical,
            "status": status,
            "exact_match": False,
            "numeric_exact_match": False,
            "match_level": PhoneMatchLevel.SEARCH_DISCOVERY_ONLY.value,
            "semantic_match": False,
            "matched_variant": None,
            "matched_variant_type": None,
            "match_location": None,
            "result_url": None,
            "source_domain": None,
            "source_date": "UNKNOWN",
            "stage": "SEARCH_DISCOVERY",
            "discovery_only": True,
            "target_verified": False,
            "discovered_entities": [],
            **dict(base or {}),
        }
        return self._observation(
            base=payload,
            status=status,
            error_code=error_code,
            error_reason=error_reason,
        )

    @staticmethod
    def _observation(
        *,
        base: Mapping[str, object],
        status: str,
        evidence_ref: str | None = None,
        error_code: str | None = None,
        error_reason: str | None = None,
    ) -> RawObservation:
        provider_id = str(base["provider_id"])
        canonical = str(base["canonical_phone"])
        digest = hashlib.sha256(f"{provider_id}|{canonical}|{status}".encode("utf-8")).hexdigest()[:20]
        payload = {**dict(base), "status": status, "error_code": error_code, "error_reason": error_reason}
        return RawObservation(
            raw_status=status,
            value_reference=f"phone-public:{provider_id}:{digest}",
            evidence_ref=evidence_ref,
            notes="Public occurrence or provider status only; no subscriber, owner, or identity conclusion.",
            payload=payload,
        )

    @staticmethod
    def _redirected_to_home(provider: PhonePublicProvider, response: PhonePublicHttpResponse) -> bool:
        if not response.redirected or not provider.home_url:
            return False
        final = urlsplit(response.final_url)
        home = urlsplit(provider.home_url)
        return (
            final.scheme.casefold(), final.netloc.casefold(), final.path.rstrip("/").casefold(), final.query
        ) == (
            home.scheme.casefold(), home.netloc.casefold(), home.path.rstrip("/").casefold(), home.query
        )

    def _source_date_warning(self, source_date: str | None) -> str | None:
        if not source_date:
            return None
        try:
            value = datetime.fromisoformat(source_date.replace("Z", "+00:00"))
        except ValueError:
            return "Source date was present but could not be normalized."
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        if (self._now() - value).days > 730:
            return "Source is older than 24 months and may not describe the current state."
        return None

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collector clock must return a timezone-aware datetime")
        return value
