from datetime import datetime, timezone
import json
from types import SimpleNamespace

import pytest

from osint_lab.agents import PhonePublicWebCollector
from osint_lab.agents.target_page_fetcher import FetchStatus, TargetPageFetchResult
from osint_lab.graph import GraphEntityType
from osint_lab.sources import (
    BraveSearchApiProvider,
    BraveSearchConfig,
    DiscoveryBudget,
    DiscoveryProviderResponse,
    DiscoveryProviderStatus,
    DiscoveryQueryEngine,
    DiscoveryResult,
    MultiProviderDiscoveryEngine,
    build_default_source_registry,
    candidate_score,
)


NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
PHONE = "+48123456789"


class JsonResponse:
    def __init__(self, payload, status=200):
        self.status_code = status
        self.content = json.dumps(payload).encode("utf-8")


class RecordingSession:
    def __init__(self, response):
        self.response = response
        self.calls = []
        self.trust_env = True

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class StubProvider:
    def __init__(self, provider_id, *, results=(), status=DiscoveryProviderStatus.SUCCESS,
                 configured=True, raises=False):
        self.provider_id = provider_id
        self.endpoint = f"https://{provider_id}.example.test/search"
        self.configured = configured
        self.results = tuple(results)
        self.status = status
        self.raises = raises
        self.calls = []

    def search(self, *, query_id, query_text, max_results):
        self.calls.append((query_id, query_text, max_results))
        if self.raises:
            raise RuntimeError("synthetic provider failure")
        values = tuple(self._result(query_id, query_text, item, rank)
                       for rank, item in enumerate(self.results[:max_results], start=1))
        return DiscoveryProviderResponse(
            provider_id=self.provider_id, status=self.status,
            query_id=query_id, query_text=query_text, results=values,
            requests_made=1,
        )

    def _result(self, query_id, query_text, item, rank):
        url, title, snippet = item
        import hashlib
        return DiscoveryResult(
            provider_id=self.provider_id, query_id=query_id, query_text=query_text,
            title=title, url=url, snippet=snippet, rank=rank, discovered_at=NOW,
            raw_status="FOUND", result_hash=hashlib.sha256(
                f"{self.provider_id}|{query_id}|{url}".encode()).hexdigest(),
            source_channels=(self.provider_id,),
        )


class TargetFetcher:
    def __init__(self, body):
        self.body = body
        self.calls = []

    def fetch(self, url):
        self.calls.append(url)
        raw = self.body.encode()
        return TargetPageFetchResult(
            requested_url=url, final_url=url, http_status=200, content_type="text/html",
            content_length=len(raw), redirected=False, redirect_chain=(), fetched_at=NOW,
            body_sha256="a" * 64, body_truncated=False, fetch_status=FetchStatus.SUCCESS,
            error_code=None, body=self.body, raw_bytes=raw, response_headers={}, tls_certificate=None,
        )


def test_brave_env_configuration_and_auth_required_are_secret_safe():
    missing = BraveSearchConfig.from_environment({})
    assert missing.api_key_present is False
    assert "api_key" not in missing.public_dict()
    response = BraveSearchApiProvider(config=missing).search(
        query_id="q", query_text='"fixture"', max_results=10)
    assert response.status is DiscoveryProviderStatus.AUTH_REQUIRED
    registry = build_default_source_registry(brave_api_key_present=False)
    source = registry.get("brave_search_api")
    assert source.enabled is False
    assert source.api_key_present is False
    assert source.implementation_status.value == "AUTH_REQUIRED"


def test_brave_official_json_endpoint_header_timeout_and_mapping():
    session = RecordingSession(JsonResponse({"web": {"results": [{
        "title": "Kontakt", "url": "https://example.test/contact?utm_source=x",
        "description": "Telefon kontakt",
    }]}}))
    provider = BraveSearchApiProvider(
        config=BraveSearchConfig(api_key="x", timeout=3.0),
        session=session, clock=lambda: NOW)
    assert "api_key='x'" not in repr(provider.config)
    response = provider.search(query_id="query-1", query_text='"fixture"', max_results=10)
    assert response.status is DiscoveryProviderStatus.SUCCESS
    assert response.results[0].url == "https://example.test/contact"
    _, call = session.calls[0]
    assert call["headers"]["X-Subscription-Token"] == "x"
    assert call["timeout"] == 3.0
    assert call["params"]["count"] == 10
    assert provider.config.public_dict()["api_key_present"] is True


@pytest.mark.parametrize("status,expected", ((401, "AUTH_REQUIRED"), (403, "AUTH_REQUIRED"),
                                              (429, "RATE_LIMITED"), (500, "HTTP_ERROR")))
def test_brave_failure_statuses_are_explicit(status, expected):
    provider = BraveSearchApiProvider(
        config=BraveSearchConfig(api_key="x"), session=RecordingSession(JsonResponse({}, status)))
    assert provider.search(query_id="q", query_text="fixture", max_results=1).status.value == expected


def test_query_matrices_are_bounded_and_entity_specific():
    engine = DiscoveryQueryEngine()
    variants = (SimpleNamespace(variant=PHONE, canonical_e164=PHONE),
                SimpleNamespace(variant="123 456 789", canonical_e164=PHONE))
    phone = engine.phone_queries("+48 123-456-789", variants)
    assert len(phone) <= 8
    assert any("telefon" in item for item in phone)
    assert any("phone" in item for item in phone)
    assert any("ogłoszenie" in item for item in phone)
    assert engine.queries(GraphEntityType.EMAIL, "fixture@example.test") != phone
    assert any("company" in item for item in engine.queries(GraphEntityType.COMPANY, "Fixture Ltd"))
    assert any("profile" in item for item in engine.queries(GraphEntityType.USERNAME, "fixture_user"))


def test_multi_provider_failure_isolated_and_ddg_equivalent_channel_continues():
    failed = StubProvider("brave_search_api", raises=True)
    fallback = StubProvider("duckduckgo_html", results=((
        "https://example.test/contact", "Kontakt", "phone contact"),))
    run = MultiProviderDiscoveryEngine(
        providers=(failed, fallback),
        budget=DiscoveryBudget(max_queries_per_entity=1, max_queries_per_provider=1),
    ).discover(case_id="case", entity_type=GraphEntityType.PHONE, value=PHONE)
    assert run.results[0].provider_id == "duckduckgo_html"
    assert any(item.provider_id == "brave_search_api" and
               item.status is DiscoveryProviderStatus.HTTP_ERROR
               for item in run.provider_responses)
    assert run.coverage.providers_failed == 1
    assert run.coverage.providers_successful == 1


def test_brave_auth_missing_still_runs_duckduckgo_without_exception():
    brave = BraveSearchApiProvider(config=BraveSearchConfig(api_key=None))
    ddg = StubProvider("duckduckgo_html", results=((
        "https://example.test/contact", "Kontakt", "phone contact"),))
    run = MultiProviderDiscoveryEngine(
        providers=(brave, ddg),
        budget=DiscoveryBudget(max_queries_per_entity=1, max_queries_per_provider=1),
    ).discover(case_id="case", entity_type=GraphEntityType.PHONE, value=PHONE)
    assert run.results
    assert run.provider_responses[0].status is DiscoveryProviderStatus.AUTH_REQUIRED
    assert len(ddg.calls) == 1


@pytest.mark.parametrize("failed_id,failed_status,successful_id", (
    ("brave_search_api", DiscoveryProviderStatus.RATE_LIMITED, "duckduckgo_html"),
    ("duckduckgo_html", DiscoveryProviderStatus.CHALLENGE, "brave_search_api"),
))
def test_rate_limit_or_challenge_does_not_stop_other_provider(
        failed_id, failed_status, successful_id):
    failed = StubProvider(failed_id, status=failed_status)
    successful = StubProvider(successful_id, results=((
        "https://example.test/contact", "Kontakt", "phone contact"),))
    run = MultiProviderDiscoveryEngine(
        providers=(failed, successful),
        budget=DiscoveryBudget(max_queries_per_entity=1, max_queries_per_provider=1),
    ).discover(case_id="case", entity_type=GraphEntityType.PHONE, value=PHONE)
    assert run.results[0].provider_id == successful_id
    assert any(item.status is failed_status for item in run.provider_responses)


def test_dedup_preserves_channels_domain_diversity_and_tracking_normalization():
    duplicate = ("https://example.test/contact?utm_source=a", "Kontakt", "phone contact")
    brave = StubProvider("brave_search_api", results=(duplicate,))
    ddg = StubProvider("duckduckgo_html", results=((
        "https://example.test/contact", "Kontakt", "phone contact"),))
    run = MultiProviderDiscoveryEngine(
        providers=(brave, ddg),
        budget=DiscoveryBudget(max_queries_per_entity=1, max_queries_per_provider=1),
    ).discover(case_id="case", entity_type=GraphEntityType.PHONE, value=PHONE)
    assert len(run.results) == 1
    assert run.results[0].source_channels == ("brave_search_api", "duckduckgo_html")
    assert run.coverage.total_results == 2
    assert run.coverage.unique_urls == 1
    assert run.coverage.duplicate_results_removed == 1


def test_candidate_ranking_prefers_contact_over_numeric_asset_and_homepage():
    def result(url, title, snippet, rank=1):
        return DiscoveryResult(
            provider_id="fixture", query_id="q", query_text="fixture", title=title,
            url=url, snippet=snippet, rank=rank, discovered_at=NOW, raw_status="FOUND",
            result_hash="a" * 64,
        )
    contact = result("https://example.test/contact", "Kontakt", "phone contact")
    numeric = result("https://cdn.example.test/assets/123456789.png", "Asset", "")
    home = result("https://example.test/", "Home", "")
    assert candidate_score(contact) > candidate_score(home) > candidate_score(numeric)


def test_phone_engine_result_still_requires_target_validation_and_can_start_hop_one():
    provider = StubProvider("duckduckgo_html", results=((
        "https://example.test/contact", "Kontakt", f"telefon {PHONE}"),))
    engine = MultiProviderDiscoveryEngine(
        providers=(provider,),
        budget=DiscoveryBudget(max_queries_per_entity=1, max_queries_per_provider=1))
    fetcher = TargetFetcher(
        f'<html><a href="mailto:fixture@example.test">fixture@example.test</a>'
        f'<p>Telefon: {PHONE}</p></html>')
    collector = PhonePublicWebCollector(
        discovery_engine=engine, target_fetcher=fetcher, clock=lambda: NOW)
    observations = collector._run(SimpleNamespace(case_id="case-phone"), PHONE)
    target = next(item for item in observations
                  if item.payload.get("stage") == "TARGET_PAGE_VALIDATION")
    assert target.raw_status == "MATCH"
    assert target.evidence_ref
    assert target.payload["target_verified"] is True
    assert any(item["entity_type"] == "EMAIL" for item in target.payload["discovered_entities"])
    status = next(item for item in observations if item.payload.get("stage") == "SEARCH_DISCOVERY")
    assert status.evidence_ref is None
    assert status.payload["source_role"] == "DISCOVERY"


def test_discovery_budget_enforces_provider_query_cap():
    provider = StubProvider("duckduckgo_html")
    engine = MultiProviderDiscoveryEngine(
        providers=(provider,),
        budget=DiscoveryBudget(max_queries_per_entity=8, max_queries_per_provider=2))
    run = engine.discover(case_id="case", entity_type=GraphEntityType.PHONE, value=PHONE)
    assert len(provider.calls) == 2
    assert run.coverage.queries_executed == 2
    assert run.coverage.requests_made == 2
