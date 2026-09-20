from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from osint_lab.agents import (
    CompanyPublicWebCollector,
    DocumentIntelligenceCollector,
    DomainRdapCollector,
    EmailPublicWebCollector,
    RawObservation,
    WebsiteMetadataCollector,
    build_default_registry,
)
from osint_lab.agents.phone_public_http import PhonePublicHttpResponse
from osint_lab.agents.target_page_fetcher import FetchStatus, TargetPageFetchResult
from osint_lab.graph import (
    GraphEntityType, GraphProjector, PivotBudget, compare_source_expansion, score_benchmark,
)
from osint_lab.sources import (
    CorroborationEngine,
    DiscoveryQueryEngine,
    ExecutionMode,
    PrivateSourceCache,
    ProviderHealthStore,
    RateLimiter,
    ReliabilityClass,
    RequestBudget,
    SourceFailureStatus,
    SourceRole,
    build_default_source_registry,
    diversity_score,
    stale_penalty,
)


NOW = datetime(2026, 9, 20, 18, 0, tzinfo=timezone.utc)
EMAIL = "fixture.person@example.test"


class QueueFetcher:
    def __init__(self, *values):
        self.values = list(values)
        self.calls = []

    def fetch(self, url):
        self.calls.append(url)
        return self.values.pop(0)


class SearchClient:
    def __init__(self, body, *, status=200):
        self.body = body
        self.status = status
        self.calls = []

    def get(self, url, *, timeout, headers):
        self.calls.append(url)
        return PhonePublicHttpResponse(status_code=self.status, final_url=url, body=self.body,
                                       redirected=False, body_truncated=False)


def fetch_result(body, *, url="https://example.test/contact", content_type="text/html",
                 raw=None, headers=None, tls=None):
    encoded = body.encode() if raw is None else raw
    return TargetPageFetchResult(
        requested_url=url, final_url=url, http_status=200, content_type=content_type,
        content_length=len(encoded), redirected=False, redirect_chain=(), fetched_at=NOW,
        body_sha256="a" * 64, body_truncated=False, fetch_status=FetchStatus.SUCCESS,
        error_code=None, body=body, raw_bytes=encoded, response_headers=headers or {},
        tls_certificate=tls,
    )


def search_html(url="https://example.test/contact"):
    return f'<html><a class="result__a" href="{url}">Fixture</a></html>'


def test_source_registry_hard_review_roles_and_config_hash():
    registry = build_default_source_registry()
    assert len(registry.definitions) == 14
    assert sum(item.enabled for item in registry.definitions) == 10
    assert len(registry.config_hash) == 64
    assert all(item.roles for item in registry.definitions)
    assert all(not item.enabled or (item.terms_reviewed and item.automation_allowed)
               for item in registry.definitions)
    assert SourceRole.DISCOVERY in registry.get("duckduckgo_html").roles
    assert SourceRole.EVIDENCE in registry.get("first_party_web").roles


def test_disabled_candidates_are_not_returned_as_enabled():
    registry = build_default_source_registry()
    all_domain = registry.for_entity(GraphEntityType.DOMAIN)
    enabled_domain = registry.for_entity(GraphEntityType.DOMAIN, enabled_only=True)
    assert any(item.source_id == "certificate_transparency_candidate" and not item.enabled
               for item in all_domain)
    assert all(item.enabled for item in enabled_domain)
    with pytest.raises(ValueError, match="hard source review"):
        replace(registry.get("certificate_transparency_candidate"), enabled=True)


def test_default_collector_registry_contains_source_adapters():
    registry = build_default_registry()
    for collector in (
        EmailPublicWebCollector(), DomainRdapCollector(fetcher=QueueFetcher()),
        WebsiteMetadataCollector(fetcher=QueueFetcher()), CompanyPublicWebCollector(),
        DocumentIntelligenceCollector(fetcher=QueueFetcher()),
    ):
        assert registry.validate(collector).agent_name == collector.agent_name


def test_discovery_queries_are_entity_specific():
    engine = DiscoveryQueryEngine()
    assert engine.queries(GraphEntityType.PHONE, "+48123456789") != engine.queries(
        GraphEntityType.EMAIL, EMAIL)
    assert "site:example.test" in engine.queries(GraphEntityType.DOMAIN, "example.test")


def test_email_exact_and_structured_matches_are_evidence_candidates():
    body = f'<html><a href="mailto:{EMAIL}">mail</a><p>{EMAIL}</p></html>'
    collector = EmailPublicWebCollector(search_client=SearchClient(search_html()),
                                        target_fetcher=QueueFetcher(fetch_result(body)), clock=lambda: NOW)
    observation = collector._run(None, EMAIL)[0]
    assert observation.raw_status == "STRUCTURED_EMAIL_MATCH"
    assert observation.payload["email"] == EMAIL
    assert observation.payload["domain"] == "example.test"
    assert collector.normalize(observation).normalized_status.value == "POSSIBLE"


def test_email_generic_username_and_false_match_are_not_evidence():
    collector = EmailPublicWebCollector(search_client=SearchClient(search_html()),
        target_fetcher=QueueFetcher(fetch_result("<html>fixture.person but no address</html>")))
    observation = collector._run(None, EMAIL)[0]
    assert observation.raw_status == "UNKNOWN"
    assert observation.payload["error_reason"] == "NO_MATCH"


def test_email_obfuscated_match_remains_possible_with_reason():
    collector = EmailPublicWebCollector(search_client=SearchClient(search_html()),
        target_fetcher=QueueFetcher(fetch_result("<html>fixture.person [at] example.test</html>")))
    observation = collector._run(None, EMAIL)[0]
    assert observation.raw_status == "OBFUSCATED_EMAIL_MATCH"
    assert collector.normalize(observation).normalized_status.value == "POSSIBLE"


def test_rdap_parsing_and_redacted_registrant_stays_unknown():
    parsed = DomainRdapCollector.parse_response({
        "status": ["active"], "nameservers": [{"ldhName": "NS1.EXAMPLE.TEST"}],
        "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
        "entities": [{"roles": ["registrant"], "remarks": [{"description": ["REDACTED"]}]}],
        "notices": [{"title": "Terms", "description": ["Public data"]}],
        "links": [{"href": "https://rdap.example.test/domain/example.test"}],
    })
    assert parsed["nameservers"] == ["ns1.example.test"]
    assert parsed["registrant_disclosure"] == "UNKNOWN"
    assert parsed["registrar"] is None


def test_rdap_collector_uses_bootstrap_and_preserves_provenance():
    bootstrap = fetch_result('{"services":[[["test"],["https://rdap.example.test/"]]]}',
                             url="https://data.iana.org/rdap/dns.json", content_type="application/json")
    rdap = fetch_result('{"status":["active"],"nameservers":[],"events":[],"entities":[],"links":[]}',
                        url="https://rdap.example.test/domain/example.test", content_type="application/rdap+json")
    fetcher = QueueFetcher(bootstrap, rdap)
    observation = DomainRdapCollector(fetcher=fetcher, clock=lambda: NOW)._run(None, "example.test")[0]
    assert observation.raw_status == "FOUND"
    assert observation.payload["source_id"] == "registry_rdap"
    assert observation.payload["registrant_disclosure"] == "UNKNOWN"
    assert len(fetcher.calls) == 2


def test_website_metadata_extracts_first_party_structured_data_and_tls():
    html = """<html lang='pl'><head><title>Fixture</title><meta name='description' content='Opis'>
    <link rel='canonical' href='/contact'></head><body>mail@example.test +48 123 456 789
    <script type='application/ld+json'>{"@type":"Organization","name":"Fixture Sp. z o.o."}</script></body></html>"""
    result = fetch_result(html, headers={"server": "fixture", "content-language": "pl"},
                          tls={"subject": "commonName=example.test", "subject_alt_names": ["example.test"]})
    observation = WebsiteMetadataCollector(fetcher=QueueFetcher(result), clock=lambda: NOW)._run(
        None, "https://example.test/contact")[0]
    assert observation.payload["title"] == "Fixture"
    assert observation.payload["organizations"][0]["name"] == "Fixture Sp. z o.o."
    assert observation.payload["tls"]["subject_alt_names"] == ["example.test"]
    assert observation.payload["public_emails"] == ["mail@example.test"]


def test_company_requires_exact_structured_name_and_does_not_fuzzy_merge():
    exact = '<script type="application/ld+json">{"@type":"Organization","name":"ABC Polska"}</script>'
    collector = CompanyPublicWebCollector(search_client=SearchClient(search_html()),
                                           target_fetcher=QueueFetcher(fetch_result(exact)), clock=lambda: NOW)
    assert collector._run(None, "ABC Polska")[0].raw_status == "STRUCTURED_COMPANY_MATCH"
    fuzzy = CompanyPublicWebCollector(search_client=SearchClient(search_html()),
                                       target_fetcher=QueueFetcher(fetch_result(exact)))
    assert fuzzy._run(None, "ABC Sp. z o.o.")[0].raw_status == "UNKNOWN"


def test_document_html_is_bounded_text_only_and_extracts_contacts():
    html = "<html><head><title>Kontakt 2020</title></head><body>old@example.test +48 123 456 789 2020-01-02</body></html>"
    observation = DocumentIntelligenceCollector(fetcher=QueueFetcher(fetch_result(html)),
                                                  clock=lambda: NOW)._run(None, "https://example.test/file.html")[0]
    assert observation.raw_status == "FOUND"
    assert observation.payload["emails"] == ["old@example.test"]
    assert observation.payload["dates"] == ["2020-01-02"]
    assert observation.payload["javascript_executed"] is False
    assert observation.payload["embedded_files_executed"] is False


@pytest.mark.parametrize("suffix", ("exe", "zip", "docm", "xlsm"))
def test_document_rejects_executable_archive_and_macro_types(suffix):
    with pytest.raises(ValueError, match="forbidden"):
        DocumentIntelligenceCollector(fetcher=QueueFetcher()).validate_input(
            f"https://example.test/file.{suffix}")


def test_provider_health_is_private_and_persistent(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    root = tmp_path / "cases" / "case-1"
    store = ProviderHealthStore(repo_root=repo, case_root=root)
    first = store.record(provider_id="fixture", status=SourceFailureStatus.TIMEOUT,
                         timestamp=NOW, parser_version="1")
    second = store.record(provider_id="fixture", status=SourceFailureStatus.SUCCESS,
                          timestamp=NOW + timedelta(minutes=1), parser_version="1")
    assert first.consecutive_failures == 1
    assert second.consecutive_failures == 0
    assert store.load()["fixture"].last_success == (NOW + timedelta(minutes=1)).isoformat()
    with pytest.raises(ValueError, match="outside"):
        ProviderHealthStore(repo_root=repo, case_root=repo / "private")


def test_rate_limiter_enforces_provider_host_and_case_budgets():
    limiter = RateLimiter(RequestBudget(max_case_requests=2, max_provider_requests=1, max_host_requests=2))
    limiter.reserve(case_id="case", provider_id="a", url="https://one.test/")
    with pytest.raises(RuntimeError, match="provider"):
        limiter.reserve(case_id="case", provider_id="a", url="https://one.test/next")
    limiter.reserve(case_id="case", provider_id="b", url="https://one.test/")
    with pytest.raises(RuntimeError, match="case"):
        limiter.reserve(case_id="case", provider_id="c", url="https://two.test/")


def test_private_cache_has_version_fingerprint_hash_and_bound(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cache = PrivateSourceCache(repo_root=repo, case_root=tmp_path / "case", max_entries=1)
    first = cache.put(provider_id="a", provider_version="1", request_identity="one",
                      timestamp=NOW, payload={"value": 1})
    cache.put(provider_id="a", provider_version="1", request_identity="two",
              timestamp=NOW, payload={"value": 2})
    assert len(first["request_fingerprint"]) == 64
    assert len(first["content_hash"]) == 64
    assert len(list(cache.directory.glob("*.json"))) == 1


def test_source_diversity_and_corroboration_ignore_copied_result_count():
    evidence = [
        {"source_class": "PASSIVE_WEB", "source_url": "https://company.test/contact",
         "reputation_class": "FIRST_PARTY", "subject": "phone", "relation": "USES_PHONE",
         "object": "company", "independence_group": "first-party", "subject_type": "PHONE",
         "object_type": "COMPANY"},
        {"source_class": "PASSIVE_WEB", "source_url": "https://directory.test/a",
         "reputation_class": "DIRECTORY", "subject": "phone", "relation": "USES_PHONE",
         "object": "company", "independence_group": "copied-directory", "subject_type": "PHONE",
         "object_type": "COMPANY"},
        {"source_class": "PASSIVE_WEB", "source_url": "https://directory2.test/a",
         "reputation_class": "DIRECTORY", "subject": "phone", "relation": "USES_PHONE",
         "object": "company", "independence_group": "copied-directory", "subject_type": "PHONE",
         "object_type": "COMPANY"},
    ]
    score = diversity_score(evidence)
    result = CorroborationEngine().evaluate(evidence)[0]
    assert score.first_party_present is True
    assert result["evidence_count"] == 3
    assert result["independent_groups"] == 2
    assert result["corroborated"] is True


def test_stale_penalty_retains_but_penalizes_historical_evidence():
    assert stale_penalty(observed_at=NOW - timedelta(days=50), now=NOW) == 0
    assert stale_penalty(observed_at=NOW - timedelta(days=1000), now=NOW) == 0.35


def test_graph_projection_adapters_create_cross_type_paths_only_for_accepted_observations():
    record = SimpleNamespace(step=SimpleNamespace(collector_name="email_public_web", seed_reference=EMAIL))
    accepted = RawObservation(raw_status="EXACT_EMAIL_MATCH", value_reference="hash",
                              payload={"target_url": "https://example.test/contact", "domain": "example.test"})
    rejected = RawObservation(raw_status="UNKNOWN", value_reference="hash", payload={})
    values = GraphProjector._derive_observation(record, accepted)
    assert {(item[0].value, item[2].value) for item in values} == {("EMAIL", "WEBSITE"), ("EMAIL", "DOMAIN")}
    assert GraphProjector._derive_observation(record, rejected) == []


def test_default_pivot_policy_is_two_hops_and_marks_high_privacy_manual():
    budget = PivotBudget()
    assert budget.max_hops == 2
    assert budget.max_auto_pivots == 6
    assert budget.max_privacy_cost == 0.6
    assert ExecutionMode.AUTO.value == "AUTO"


def test_username_collision_and_ct_never_become_verified_by_source_layer():
    registry = build_default_source_registry()
    assert registry.get("certificate_transparency_candidate").enabled is False
    assert all(SourceRole.VERIFICATION not in item.roles
               for item in registry.for_entity(GraphEntityType.USERNAME))


def test_source_reputation_is_coverage_weight_not_truth():
    from osint_lab.sources import source_reputation
    first = source_reputation("first", ReliabilityClass.FIRST_PARTY)
    directory = source_reputation("dir", ReliabilityClass.DIRECTORY)
    assert first.base_weight > directory.base_weight
    assert "not a truth score" in first.reasons[0]


def test_source_rich_benchmark_improves_coverage_without_more_false_positives():
    expected = ({"id": "relation:a", "label": "TRUE"}, {"id": "relation:b", "label": "TRUE"})
    before = score_benchmark(
        predicted=({"id": "relation:a", "label": "TRUE", "verified": True,
                    "useful_entity": True, "independence_group": "first"},),
        expected=expected, pivot_count=1, useful_pivots=1, network_requests=2,
    )
    after = score_benchmark(
        predicted=(
            {"id": "relation:a", "label": "TRUE", "verified": True, "useful_entity": True,
             "independence_group": "first", "source_class": "FIRST_PARTY"},
            {"id": "relation:b", "label": "TRUE", "verified": True, "useful_entity": True,
             "independence_group": "technical", "source_class": "TECHNICAL_INFRASTRUCTURE"},
        ), expected=expected, pivot_count=2, useful_pivots=2, network_requests=4,
        provider_runs=2, provider_failures=0,
    )
    comparison = compare_source_expansion(before=before, after=after)
    assert before.false_positive_count == after.false_positive_count == 0
    assert before.verified_evidence_count == 1
    assert after.verified_evidence_count == 2
    assert comparison["success"] is True
