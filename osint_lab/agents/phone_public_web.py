"""Exact-match public web occurrence collector for phone numbers."""

from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Mapping
from urllib.parse import quote, urlsplit

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus

from .base import Collector, FindingCandidate, RawObservation
from .phone_public_extract import extract_discovered_entities
from .phone_public_http import (
    PhonePublicHttpConnectionError,
    PhonePublicHttpResponse,
    PhonePublicHttpTimeout,
    RequestsPhonePublicHttpClient,
)
from .phone_public_parsers import ParsedPhonePublicResult, parse_phone_public_results
from .phone_public_providers import DEFAULT_PHONE_PUBLIC_PROVIDERS, PhonePublicProvider
from .phone_variants import PhoneVariant, generate_phone_variants


class PhonePublicWebCollector(Collector):
    """Find exact public occurrences without inferring a subscriber or owner."""

    agent_name = "phone_public_web"
    agent_type = "PHONE"
    version = "1.0.0"
    source_class = SourceClass.PASSIVE_WEB
    network_required = True
    default_region = "PL"
    _USER_AGENT = "LumirOSINTLab-PhonePublicWeb/1.0"

    def __init__(
        self,
        *,
        providers: tuple[PhonePublicProvider, ...] = DEFAULT_PHONE_PUBLIC_PROVIDERS,
        http_client=None,
        clock: Callable[[], datetime] | None = None,
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

    def validate_input(self, seed_reference: str) -> None:
        generate_phone_variants(seed_reference, default_region=self.default_region)

    def _run(self, context: ExecutionContext, seed_reference: str) -> tuple[RawObservation, ...]:
        variants = generate_phone_variants(seed_reference, default_region=self.default_region)
        observations: list[RawObservation] = []
        for provider in self._providers:
            observations.extend(self._query_provider(provider, variants))
        return tuple(observations)

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
        payload = [asdict(provider) for provider in self._providers]
        provider_hash = hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        return {
            "network": True,
            "method": "GET",
            "providers": [item.provider_id for item in self._providers],
            "provider_config_sha256": provider_hash,
            "exact_phone_match": True,
            "entity_extraction": True,
            "browser_automation": False,
            "authentication": False,
            "captcha_bypass": False,
            "identity_confirmation": False,
        }

    def _query_provider(
        self,
        provider: PhonePublicProvider,
        variants: tuple[PhoneVariant, ...],
    ) -> tuple[RawObservation, ...]:
        if not provider.enabled:
            return (self._status_observation(
                provider=provider,
                variants=variants,
                status="UNKNOWN",
                error_code="PROVIDER_DISABLED",
                error_reason="Provider is disabled by reviewed configuration.",
            ),)
        all_observations: list[RawObservation] = []
        for variant in variants:
            all_observations.extend(self._query_variant(provider, variant, variants))
        matches = [item for item in all_observations if item.raw_status == "MATCH"]
        if matches:
            deduped: dict[str, RawObservation] = {}
            for item in matches:
                url = str(item.payload.get("result_url") or item.value_reference).casefold().rstrip("/")
                deduped.setdefault(url, item)
            return tuple(deduped.values())
        if all_observations and all(item.raw_status == "NO_MATCH" for item in all_observations):
            return (all_observations[0],)
        if all_observations and all(item.raw_status == "ERROR" for item in all_observations):
            return (all_observations[0],)
        unknown = next((item for item in all_observations if item.raw_status == "UNKNOWN"), None)
        return (unknown or all_observations[0],) if all_observations else ()

    def _query_variant(
        self,
        provider: PhonePublicProvider,
        query_variant: PhoneVariant,
        variants: tuple[PhoneVariant, ...],
    ) -> tuple[RawObservation, ...]:
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
        }
        try:
            response = self._http_client.get(
                request_url,
                timeout=provider.timeout,
                headers={"User-Agent": self._USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
            )
        except PhonePublicHttpTimeout:
            return (self._status_observation(provider=provider, variants=variants, base=base, status="UNKNOWN",
                                             error_code="TIMEOUT", error_reason="Public provider timed out."),)
        except PhonePublicHttpConnectionError:
            return (self._status_observation(provider=provider, variants=variants, base=base, status="UNKNOWN",
                                             error_code="CONNECTION_ERROR", error_reason="Public provider request failed."),)
        except Exception as error:
            return (self._status_observation(provider=provider, variants=variants, base=base, status="ERROR",
                                             error_code=type(error).__name__.upper(),
                                             error_reason="HTTP client raised an unexpected technical error."),)
        if not isinstance(response, PhonePublicHttpResponse):
            return (self._status_observation(provider=provider, variants=variants, base=base, status="ERROR",
                                             error_code="MALFORMED_RESPONSE",
                                             error_reason="HTTP client returned an invalid response."),)
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
            return (self._status_observation(provider=provider, variants=variants, base=response_base,
                                             status="UNKNOWN", error_code="CHALLENGE",
                                             error_reason="CAPTCHA, rate-limit, or JS challenge detected."),)
        if response.status_code in {403, 429}:
            return (self._status_observation(provider=provider, variants=variants, base=response_base,
                                             status="UNKNOWN", error_code=f"HTTP_{response.status_code}",
                                             error_reason="HTTP denial is not a NO_MATCH."),)
        if response.status_code >= 500:
            return (self._status_observation(provider=provider, variants=variants, base=response_base,
                                             status="UNKNOWN", error_code="HTTP_SERVER_ERROR",
                                             error_reason="Provider server failure is inconclusive."),)
        if not 200 <= response.status_code < 300:
            return (self._status_observation(provider=provider, variants=variants, base=response_base,
                                             status="UNKNOWN", error_code="UNEXPECTED_HTTP_STATUS",
                                             error_reason="Unexpected HTTP status is inconclusive."),)
        if self._redirected_to_home(provider, response):
            return (self._status_observation(provider=provider, variants=variants, base=response_base,
                                             status="UNKNOWN", error_code="REDIRECT_HOME",
                                             error_reason="Provider redirected to a generic homepage."),)
        if any(signal.casefold() in body_casefold for signal in provider.no_match_signals):
            return (self._status_observation(provider=provider, variants=variants, base=response_base,
                                             status="NO_MATCH", error_code=None,
                                             error_reason="Provider returned its reviewed no-results signal."),)
        try:
            results = parse_phone_public_results(
                provider.result_parser,
                body=response.body,
                final_url=response.final_url,
            )
        except Exception as error:
            return (self._status_observation(provider=provider, variants=variants, base=response_base,
                                             status="ERROR", error_code=type(error).__name__.upper(),
                                             error_reason="Reviewed result parser failed."),)
        if not results:
            return (self._status_observation(provider=provider, variants=variants, base=response_base,
                                             status="UNKNOWN", error_code="GENERIC_PAGE",
                                             error_reason="No reviewed result container was found."),)
        matches = [self._match_observation(provider, variants, response_base, item) for item in results]
        exact = tuple(item for item in matches if item.raw_status == "MATCH")
        if exact:
            return exact
        return (matches[0],)

    def _match_observation(
        self,
        provider: PhonePublicProvider,
        variants: tuple[PhoneVariant, ...],
        base: dict[str, object],
        result: ParsedPhonePublicResult,
    ) -> RawObservation:
        matched, location = self._find_match(result, variants)
        source_domain = (urlsplit(result.result_url).hostname or "").casefold() or None
        evidence_ref = "phone-public:" + hashlib.sha256(
            f"{provider.provider_id}|{result.result_url}|{base['body_sha256']}".encode("utf-8")
        ).hexdigest()
        if matched is None:
            return self._observation(
                base={
                    **base,
                    "status": "UNKNOWN",
                    "exact_match": False,
                    "matched_variant": None,
                    "matched_variant_type": None,
                    "match_location": None,
                    "snippet": result.snippet[:500],
                    "result_url": result.result_url,
                    "source_domain": source_domain,
                    "page_title": result.page_title,
                    "source_date": result.source_date or "UNKNOWN",
                    "discovered_entities": [],
                },
                status="UNKNOWN",
                evidence_ref=evidence_ref,
                error_code="NON_EXACT_CANDIDATE",
                error_reason="A result URL was returned but no exact phone occurrence was present.",
            )
        entities = extract_discovered_entities(result, evidence_ref=evidence_ref)
        return self._observation(
            base={
                **base,
                "status": "MATCH",
                "exact_match": True,
                "matched_variant": matched.variant,
                "matched_variant_type": matched.variant_type,
                "match_location": location,
                "snippet": result.snippet[:500],
                "result_url": result.result_url,
                "source_domain": source_domain,
                "page_title": result.page_title,
                "source_date": result.source_date or "UNKNOWN",
                "source_date_warning": self._source_date_warning(result.source_date),
                "discovered_entities": [item.to_dict() for item in entities],
            },
            status="MATCH",
            evidence_ref=evidence_ref,
        )

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
            "matched_variant": None,
            "matched_variant_type": None,
            "match_location": None,
            "result_url": None,
            "source_domain": None,
            "source_date": "UNKNOWN",
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
    def _find_match(
        result: ParsedPhonePublicResult,
        variants: tuple[PhoneVariant, ...],
    ) -> tuple[PhoneVariant | None, str | None]:
        for location, text in (("snippet", result.snippet), ("body", result.visible_text)):
            for variant in sorted(variants, key=lambda item: len(item.variant), reverse=True):
                pattern = rf"(?<!\d){re.escape(variant.variant)}(?!\d)"
                if re.search(pattern, text):
                    return variant, location
        return None, None

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
