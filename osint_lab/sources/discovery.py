"""Bounded multi-provider discovery; search results are candidates, never evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from typing import Mapping, Protocol, Sequence
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import requests

from osint_lab.graph.models import GraphEntityType
from .runtime import RateLimiter, RequestBudget


class DiscoveryProviderStatus(str, Enum):
    SUCCESS = "SUCCESS"
    NO_RESULTS = "NO_RESULTS"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    RATE_LIMITED = "RATE_LIMITED"
    CHALLENGE = "CHALLENGE"
    TIMEOUT = "TIMEOUT"
    HTTP_ERROR = "HTTP_ERROR"
    PARSER_ERROR = "PARSER_ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, kw_only=True)
class DiscoveryResult:
    provider_id: str
    query_id: str
    query_text: str
    title: str | None
    url: str
    snippet: str
    rank: int
    discovered_at: datetime
    raw_status: str
    result_hash: str
    source_channels: tuple[str, ...] = ()
    score: int = 0

    def __post_init__(self) -> None:
        if not self.provider_id or not self.query_id or not self.query_text or not self.url:
            raise ValueError("complete discovery provenance is required")
        if self.rank <= 0 or self.discovered_at.tzinfo is None:
            raise ValueError("valid rank and timezone-aware discovered_at are required")
        if len(self.result_hash) != 64:
            raise ValueError("result_hash must be SHA-256")

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["discovered_at"] = self.discovered_at.isoformat()
        value["source_channels"] = list(self.source_channels)
        return value


@dataclass(frozen=True, kw_only=True)
class DiscoveryProviderResponse:
    provider_id: str
    status: DiscoveryProviderStatus
    query_id: str
    query_text: str
    results: tuple[DiscoveryResult, ...] = ()
    error_code: str | None = None
    http_status: int | None = None
    requests_made: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "status": self.status.value,
            "query_id": self.query_id,
            "query_sha256": hashlib.sha256(self.query_text.encode("utf-8")).hexdigest(),
            "result_count": len(self.results),
            "error_code": self.error_code,
            "http_status": self.http_status,
            "requests_made": self.requests_made,
        }


class DiscoveryProvider(Protocol):
    provider_id: str
    configured: bool
    endpoint: str

    def search(self, *, query_id: str, query_text: str,
               max_results: int) -> DiscoveryProviderResponse: ...


@dataclass(frozen=True, kw_only=True)
class DiscoveryBudget:
    max_queries_per_entity: int = 8
    max_queries_per_provider: int = 6
    max_results_per_query: int = 10
    max_unique_candidates: int = 30
    max_unique_domains: int = 15
    max_candidates_per_domain: int = 3

    def __post_init__(self) -> None:
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0
               for value in self.__dict__.values()):
            raise ValueError("discovery budget values must be positive integers")


@dataclass(frozen=True, kw_only=True)
class DiscoveryCoverageSummary:
    providers_eligible: int
    providers_configured: int
    providers_considered: int
    providers_executed: int
    providers_successful: int
    providers_failed: int
    queries_planned: int
    queries_executed: int
    raw_results: int
    total_results: int
    duplicate_results_removed: int
    unique_urls: int
    unique_candidates: int
    unique_domains: int
    candidates_selected: int
    requests_made: int
    budget_exhausted: bool
    candidates_verified: int = 0
    candidates_rejected: int = 0
    candidates_unknown: int = 0
    verified_phone_occurrences: int = 0
    discovered_entities: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, kw_only=True)
class DiscoveryRun:
    results: tuple[DiscoveryResult, ...]
    provider_responses: tuple[DiscoveryProviderResponse, ...]
    coverage: DiscoveryCoverageSummary


class DiscoveryQueryEngine:
    """Generate conservative, entity-specific query matrices."""

    def queries(self, entity_type: GraphEntityType, value: str) -> tuple[str, ...]:
        if not isinstance(entity_type, GraphEntityType) or not isinstance(value, str) or not value.strip():
            raise ValueError("valid entity type and value are required")
        clean = " ".join(value.split())
        quoted = f'"{clean}"'
        strategies = {
            GraphEntityType.PHONE: (
                quoted, f"{quoted} telefon", f"{quoted} kontakt", f"{quoted} firma",
                f"{quoted} ogłoszenie", f"{quoted} phone", f"{quoted} contact",
                f"{quoted} filetype:pdf",
            ),
            GraphEntityType.EMAIL: (
                quoted, f"{quoted} kontakt", f"{quoted} contact", f"{quoted} firma",
                f"{quoted} company", f"{quoted} filetype:pdf",
            ),
            GraphEntityType.USERNAME: (
                quoted, f"{quoted} profil", f"{quoted} profile", f"{quoted} site:github.com",
                f"{quoted} site:gitlab.com",
            ),
            GraphEntityType.DOMAIN: (f"site:{clean}", f'"{clean}"', f'"{clean}" filetype:pdf'),
            GraphEntityType.COMPANY: (
                quoted, f"{quoted} kontakt", f"{quoted} contact", f"{quoted} firma",
                f"{quoted} company", f"{quoted} KRS", f"{quoted} filetype:pdf",
            ),
            GraphEntityType.ORGANIZATION: (
                quoted, f"{quoted} kontakt", f"{quoted} contact", f"{quoted} filetype:pdf",
            ),
        }
        return tuple(dict.fromkeys(strategies.get(entity_type, (quoted,))))

    def phone_queries(self, raw_value: str, variants: Sequence[object]) -> tuple[str, ...]:
        values = [" ".join(raw_value.split())]
        for item in variants:
            candidate = getattr(item, "variant", None)
            if isinstance(candidate, str) and candidate.strip():
                values.append(candidate.strip())
        exact = [f'"{item}"' for item in dict.fromkeys(values)]
        canonical = getattr(variants[0], "canonical_e164", values[0]) if variants else values[0]
        matrix = exact[:3] + [
            f'"{canonical}" telefon kontakt', f'"{canonical}" firma',
            f'"{canonical}" ogłoszenie', f'"{canonical}" phone contact',
            f'"{canonical}" filetype:pdf',
        ]
        return tuple(dict.fromkeys(matrix))[:8]


@dataclass(frozen=True, kw_only=True)
class BraveSearchConfig:
    api_key: str | None = field(repr=False)
    endpoint: str = "https://api.search.brave.com/res/v1/web/search"
    timeout: float = 8.0
    max_response_bytes: int = 524_288
    user_agent: str = "LumirOSINTLab-Discovery/1.0"

    @classmethod
    def from_environment(cls, environ: Mapping[str, str] | None = None) -> "BraveSearchConfig":
        values = os.environ if environ is None else environ
        key = values.get("LUMIR_BRAVE_SEARCH_API_KEY", "").strip()
        return cls(api_key=key or None)

    @property
    def api_key_present(self) -> bool:
        return bool(self.api_key)

    def public_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint, "timeout": self.timeout,
            "max_response_bytes": self.max_response_bytes, "user_agent": self.user_agent,
            "api_key_present": self.api_key_present,
        }

    @property
    def config_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.public_dict(), sort_keys=True).encode("utf-8")).hexdigest()


class BraveSearchApiProvider:
    provider_id = "brave_search_api"

    def __init__(self, *, config: BraveSearchConfig | None = None, session=None, clock=None) -> None:
        self.config = config or BraveSearchConfig.from_environment()
        self.endpoint = self.config.endpoint
        self.configured = self.config.api_key_present
        self._session = session or requests.Session()
        if hasattr(self._session, "trust_env"):
            self._session.trust_env = False
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def search(self, *, query_id: str, query_text: str, max_results: int) -> DiscoveryProviderResponse:
        if not self.configured:
            return DiscoveryProviderResponse(
                provider_id=self.provider_id, status=DiscoveryProviderStatus.AUTH_REQUIRED,
                query_id=query_id, query_text=query_text, error_code="AUTH_REQUIRED",
            )
        try:
            response = self._session.get(
                self.endpoint,
                params={"q": query_text, "count": min(max_results, 20), "safesearch": "moderate"},
                timeout=self.config.timeout,
                headers={"Accept": "application/json", "User-Agent": self.config.user_agent,
                         "X-Subscription-Token": str(self.config.api_key)},
            )
        except requests.Timeout:
            return self._failure(query_id, query_text, DiscoveryProviderStatus.TIMEOUT, "TIMEOUT", 1)
        except requests.RequestException:
            return self._failure(query_id, query_text, DiscoveryProviderStatus.HTTP_ERROR,
                                 "CONNECTION_ERROR", 1)
        status = int(getattr(response, "status_code", 0))
        if status in {401, 403}:
            return self._failure(query_id, query_text, DiscoveryProviderStatus.AUTH_REQUIRED,
                                 f"HTTP_{status}", 1, status)
        if status == 429:
            return self._failure(query_id, query_text, DiscoveryProviderStatus.RATE_LIMITED,
                                 "HTTP_429", 1, status)
        if status < 200 or status >= 300:
            return self._failure(query_id, query_text, DiscoveryProviderStatus.HTTP_ERROR,
                                 f"HTTP_{status}", 1, status)
        raw = getattr(response, "content", None)
        if not isinstance(raw, (bytes, bytearray)):
            raw = str(getattr(response, "text", "")).encode("utf-8")
        if len(raw) > self.config.max_response_bytes:
            return self._failure(query_id, query_text, DiscoveryProviderStatus.PARSER_ERROR,
                                 "RESPONSE_TOO_LARGE", 1, status)
        try:
            payload = json.loads(bytes(raw).decode("utf-8"))
            rows = payload.get("web", {}).get("results", [])
            if not isinstance(rows, list):
                raise ValueError("invalid result list")
            results = tuple(
                self._result(query_id, query_text, row, rank)
                for rank, row in enumerate(rows[:max_results], start=1)
                if isinstance(row, Mapping) and isinstance(row.get("url"), str)
            )
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            return self._failure(query_id, query_text, DiscoveryProviderStatus.PARSER_ERROR,
                                 "INVALID_JSON", 1, status)
        return DiscoveryProviderResponse(
            provider_id=self.provider_id,
            status=DiscoveryProviderStatus.SUCCESS if results else DiscoveryProviderStatus.NO_RESULTS,
            query_id=query_id, query_text=query_text, results=results,
            http_status=status, requests_made=1,
        )

    def _result(self, query_id: str, query_text: str,
                row: Mapping[str, object], rank: int) -> DiscoveryResult:
        url = canonical_discovery_url(str(row["url"]))
        title = str(row["title"]) if isinstance(row.get("title"), str) else None
        snippet = str(row.get("description") or "")[:2000]
        digest = discovery_result_hash(self.provider_id, query_id, url, title, snippet)
        return DiscoveryResult(
            provider_id=self.provider_id, query_id=query_id, query_text=query_text,
            title=title, url=url, snippet=snippet, rank=rank,
            discovered_at=self._clock(), raw_status="FOUND", result_hash=digest,
            source_channels=(self.provider_id,),
        )

    def _failure(self, query_id, query_text, status, code, requests_made, http_status=None):
        return DiscoveryProviderResponse(
            provider_id=self.provider_id, status=status, query_id=query_id,
            query_text=query_text, error_code=code, http_status=http_status,
            requests_made=requests_made,
        )


BraveSearchProvider = BraveSearchApiProvider


class DuckDuckGoHtmlProvider:
    provider_id = "duckduckgo_html"
    endpoint = "https://html.duckduckgo.com/html/"
    configured = True

    def __init__(self, *, http_client=None, clock=None) -> None:
        from osint_lab.agents.phone_public_http import RequestsPhonePublicHttpClient
        self._http = http_client or RequestsPhonePublicHttpClient()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def search(self, *, query_id: str, query_text: str, max_results: int) -> DiscoveryProviderResponse:
        from osint_lab.agents.phone_public_http import PhonePublicHttpConnectionError, PhonePublicHttpTimeout
        from osint_lab.agents.phone_public_parsers import parse_phone_public_results
        url = self.endpoint + "?q=" + quote(query_text, safe="")
        try:
            response = self._http.get(url, timeout=8.0, headers={
                "User-Agent": "LumirOSINTLab-Discovery/1.0",
                "Accept": "text/html,application/xhtml+xml",
            })
        except PhonePublicHttpTimeout:
            return self._failure(query_id, query_text, DiscoveryProviderStatus.TIMEOUT, "TIMEOUT")
        except PhonePublicHttpConnectionError:
            return self._failure(query_id, query_text, DiscoveryProviderStatus.HTTP_ERROR,
                                 "CONNECTION_ERROR")
        except Exception:
            return self._failure(query_id, query_text, DiscoveryProviderStatus.HTTP_ERROR, "CLIENT_ERROR")
        body = str(getattr(response, "body", ""))
        lowered = body.casefold()
        if any(marker in lowered for marker in ("captcha", "too many requests", "enable javascript")):
            return self._failure(query_id, query_text, DiscoveryProviderStatus.CHALLENGE,
                                 "CHALLENGE", int(getattr(response, "status_code", 0)))
        status = int(getattr(response, "status_code", 0))
        if status == 429:
            return self._failure(query_id, query_text, DiscoveryProviderStatus.RATE_LIMITED,
                                 "HTTP_429", status)
        if status < 200 or status >= 300 or bool(getattr(response, "body_truncated", False)):
            return self._failure(query_id, query_text, DiscoveryProviderStatus.HTTP_ERROR,
                                 f"HTTP_{status}", status)
        try:
            rows = parse_phone_public_results("html_search_results_v1", body=body,
                                              final_url=str(getattr(response, "final_url", url)))
            results = tuple(
                self._result(query_id, query_text, row, rank)
                for rank, row in enumerate(rows[:max_results], start=1)
            )
        except Exception:
            return self._failure(query_id, query_text, DiscoveryProviderStatus.PARSER_ERROR,
                                 "PARSER_ERROR", status)
        return DiscoveryProviderResponse(
            provider_id=self.provider_id,
            status=DiscoveryProviderStatus.SUCCESS if results else DiscoveryProviderStatus.NO_RESULTS,
            query_id=query_id, query_text=query_text, results=results,
            http_status=status, requests_made=1,
        )

    def _result(self, query_id, query_text, row, rank):
        url = canonical_discovery_url(row.result_url)
        return DiscoveryResult(
            provider_id=self.provider_id, query_id=query_id, query_text=query_text,
            title=row.page_title, url=url, snippet=row.snippet[:2000], rank=rank,
            discovered_at=self._clock(), raw_status="FOUND",
            result_hash=discovery_result_hash(
                self.provider_id, query_id, url, row.page_title, row.snippet[:2000]),
            source_channels=(self.provider_id,),
        )

    def _failure(self, query_id, query_text, status, code, http_status=None):
        return DiscoveryProviderResponse(
            provider_id=self.provider_id, status=status, query_id=query_id,
            query_text=query_text, error_code=code, http_status=http_status, requests_made=1,
        )


class MultiProviderDiscoveryEngine:
    def __init__(self, *, providers: Sequence[DiscoveryProvider],
                 budget: DiscoveryBudget | None = None, rate_limiter: RateLimiter | None = None,
                 query_engine: DiscoveryQueryEngine | None = None) -> None:
        values = tuple(providers)
        if not values or len({item.provider_id for item in values}) != len(values):
            raise ValueError("unique discovery providers are required")
        self.providers = values
        self.budget = budget or DiscoveryBudget()
        self.rate_limiter = rate_limiter or RateLimiter(RequestBudget(
            max_case_requests=self.budget.max_queries_per_entity * len(values),
            max_provider_requests=self.budget.max_queries_per_provider,
            max_host_requests=self.budget.max_queries_per_provider,
        ))
        self.query_engine = query_engine or DiscoveryQueryEngine()

    def discover(self, *, case_id: str, entity_type: GraphEntityType, value: str,
                 queries: Sequence[str] | None = None) -> DiscoveryRun:
        planned = tuple(dict.fromkeys(queries or self.query_engine.queries(entity_type, value)))[
            :self.budget.max_queries_per_entity
        ]
        responses: list[DiscoveryProviderResponse] = []
        raw_results: list[DiscoveryResult] = []
        budget_exhausted = False
        for provider in self.providers:
            if not provider.configured:
                responses.append(provider.search(
                    query_id=self._query_id(provider.provider_id, "auth"),
                    query_text="AUTH_REQUIRED", max_results=0))
                continue
            for query_text in planned[:self.budget.max_queries_per_provider]:
                query_id = self._query_id(provider.provider_id, query_text)
                try:
                    self.rate_limiter.reserve(case_id=case_id, provider_id=provider.provider_id,
                                              url=provider.endpoint)
                except RuntimeError:
                    budget_exhausted = True
                    responses.append(DiscoveryProviderResponse(
                        provider_id=provider.provider_id, status=DiscoveryProviderStatus.UNKNOWN,
                        query_id=query_id, query_text=query_text,
                        error_code="REQUEST_BUDGET_EXHAUSTED",
                    ))
                    break
                try:
                    response = provider.search(
                        query_id=query_id, query_text=query_text,
                        max_results=self.budget.max_results_per_query)
                except Exception:
                    response = DiscoveryProviderResponse(
                        provider_id=provider.provider_id,
                        status=DiscoveryProviderStatus.HTTP_ERROR,
                        query_id=query_id, query_text=query_text,
                        error_code="PROVIDER_EXCEPTION", requests_made=1,
                    )
                responses.append(response)
                raw_results.extend(response.results)
        selected, duplicates = self._select(raw_results)
        successful = {item.provider_id for item in responses
                      if item.status in {DiscoveryProviderStatus.SUCCESS,
                                         DiscoveryProviderStatus.NO_RESULTS}}
        failed = {item.provider_id for item in responses
                  if item.status not in {DiscoveryProviderStatus.SUCCESS,
                                         DiscoveryProviderStatus.NO_RESULTS,
                                         DiscoveryProviderStatus.AUTH_REQUIRED}}
        executed = {item.provider_id for item in responses if item.requests_made > 0}
        coverage = DiscoveryCoverageSummary(
            providers_eligible=len(self.providers),
            providers_configured=sum(item.configured for item in self.providers),
            providers_considered=len(self.providers), providers_executed=len(executed),
            providers_successful=len(successful), providers_failed=len(failed),
            queries_planned=len(planned) * sum(item.configured for item in self.providers),
            queries_executed=sum(item.requests_made for item in responses),
            raw_results=len(raw_results), total_results=len(raw_results),
            duplicate_results_removed=duplicates,
            unique_urls=len(raw_results) - duplicates,
            unique_candidates=len(selected),
            unique_domains=len({normalized_domain(item.url) for item in selected}),
            candidates_selected=len(selected), requests_made=sum(item.requests_made for item in responses),
            budget_exhausted=budget_exhausted,
            candidates_unknown=len(selected),
        )
        return DiscoveryRun(results=selected, provider_responses=tuple(responses), coverage=coverage)

    def _select(self, values: Sequence[DiscoveryResult]) -> tuple[tuple[DiscoveryResult, ...], int]:
        grouped: dict[str, list[DiscoveryResult]] = {}
        for item in values:
            grouped.setdefault(canonical_discovery_url(item.url), []).append(item)
        candidates = []
        for url, group in grouped.items():
            best = max(group, key=lambda item: (candidate_score(item), -item.rank))
            channels = tuple(sorted({item.provider_id for item in group}))
            candidates.append(DiscoveryResult(
                **{**best.__dict__, "url": url, "source_channels": channels,
                   "score": candidate_score(best) + 3 * (len(channels) - 1)}
            ))
        candidates.sort(key=lambda item: (-item.score, item.rank, item.url))
        output: list[DiscoveryResult] = []
        domain_counts: dict[str, int] = {}
        domains: set[str] = set()
        for item in candidates:
            domain = normalized_domain(item.url)
            if domain not in domains and len(domains) >= self.budget.max_unique_domains:
                continue
            if domain_counts.get(domain, 0) >= self.budget.max_candidates_per_domain:
                continue
            domains.add(domain)
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
            output.append(item)
            if len(output) >= self.budget.max_unique_candidates:
                break
        return tuple(output), len(values) - len(grouped)

    @staticmethod
    def _query_id(provider_id: str, query_text: str) -> str:
        return "qry-" + hashlib.sha256(f"{provider_id}|{query_text}".encode("utf-8")).hexdigest()[:24]


def build_default_discovery_engine(*, environ: Mapping[str, str] | None = None,
                                   duckduckgo_http_client=None,
                                   rate_limiter=None) -> MultiProviderDiscoveryEngine:
    brave = BraveSearchApiProvider(config=BraveSearchConfig.from_environment(environ))
    return MultiProviderDiscoveryEngine(
        providers=(brave, DuckDuckGoHtmlProvider(http_client=duckduckgo_http_client)),
        rate_limiter=rate_limiter,
    )


def canonical_discovery_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("discovery URL must be HTTP(S)")
    host = parsed.hostname.casefold()
    port = f":{parsed.port}" if parsed.port and parsed.port not in {80, 443} else ""
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    clean_query = [
        (key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if not key.casefold().startswith("utm_")
        and key.casefold() not in {"fbclid", "gclid", "ref"}
    ]
    return urlunsplit((parsed.scheme.casefold(), host + port, path,
                       urlencode(sorted(clean_query)), ""))


def normalized_domain(url: str) -> str:
    return (urlsplit(url).hostname or "").casefold()


def discovery_result_hash(provider_id: str, query_id: str, url: str,
                          title: str | None, snippet: str) -> str:
    payload = {"provider_id": provider_id, "query_id": query_id, "url": url,
               "title": title, "snippet": snippet}
    return hashlib.sha256(json.dumps(payload, sort_keys=True,
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def candidate_score(item: DiscoveryResult) -> int:
    parsed = urlsplit(item.url)
    text = f"{parsed.path} {item.title or ''} {item.snippet}".casefold()
    score = max(0, 20 - item.rank)
    for marker, weight in (
        ("contact", 12), ("kontakt", 12), ("about", 8), ("o-nas", 8),
        ("company", 7), ("firma", 7), ("legal", 6), ("directory", 5),
        (".pdf", 6),
    ):
        if marker in text:
            score += weight
    if parsed.path in {"", "/"}:
        score -= 5
    if any(marker in text for marker in ("/assets/", "/static/", ".jpg", ".png", ".css", ".js")):
        score -= 20
    if any(marker in normalized_domain(item.url) for marker in ("cdn.", "media.", "tracking.")):
        score -= 12
    if any(segment.isdigit() and len(segment) >= 6 for segment in parsed.path.split("/")):
        score -= 10
    return score
