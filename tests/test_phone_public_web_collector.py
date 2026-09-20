from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from osint_lab.agents import (
    CollectorRegistry,
    PhoneMetadataCollector,
    PhonePublicProvider,
    PhonePublicWebCollector,
    build_default_registry,
    generate_phone_variants,
    metadata_for,
)
from osint_lab.agents.phone_public_http import (
    PhonePublicHttpResponse,
    PhonePublicHttpTimeout,
)
from osint_lab.agents.target_page_fetcher import FetchStatus, TargetPageFetchResult
from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.case_runner import CaseRunner
from osint_lab.case_storage import CaseStore
from osint_lab.evidence import EvidenceVault
from osint_lab.intelligence import Directness, EvidenceItem, EvidenceQualityEngine
from osint_lab.orchestrator.audit import AuditLog, verify_audit_log
from osint_lab.orchestrator.authorization_store import AuthorizationStore
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.reporting import ReportEngine
from osint_lab.schemas import FindingStatus


NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
PHONE = "+48123456789"


class FakeHttpClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, *, timeout, headers):
        self.calls.append({"url": url, "timeout": timeout, "headers": dict(headers)})
        value = self.response(url) if callable(self.response) else self.response
        if isinstance(value, BaseException):
            raise value
        return value


class FakeTargetFetcher:
    def __init__(self, body, *, status=FetchStatus.SUCCESS, error_code=None):
        self.body = body
        self.status = status
        self.error_code = error_code
        self.calls = []

    def fetch(self, url):
        self.calls.append(url)
        body = self.body.get(url, "") if isinstance(self.body, dict) else self.body
        body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest() if body else None
        return TargetPageFetchResult(
            requested_url=url,
            final_url=url,
            http_status=200 if self.status is FetchStatus.SUCCESS else None,
            content_type="text/html" if self.status is FetchStatus.SUCCESS else None,
            content_length=len(body.encode("utf-8")) if body else None,
            redirected=False,
            redirect_chain=(),
            fetched_at=NOW,
            body_sha256=body_hash,
            body_truncated=False,
            fetch_status=self.status,
            error_code=self.error_code,
            body=body if self.status is FetchStatus.SUCCESS else "",
        )


def provider(**changes):
    values = dict(
        provider_id="fixture_search",
        name="Fixture Search",
        search_url_template="https://search.test/?q={query}",
        method="GET",
        source_class=SourceClass.PASSIVE_WEB,
        exact_match_required=True,
        enabled=True,
        reviewed_at="2026-09-20",
        timeout=3.0,
        privacy_notes="Fixture provider receives a synthetic phone variant.",
        terms_limitations_note="Synthetic offline provider only.",
        result_parser="html_search_results_v1",
        notes="Reserved .test offline provider.",
        no_match_signals=("NO_RESULTS_FIXTURE",),
        challenge_signals=("captcha", "cloudflare", "too many requests", "enable javascript"),
        home_url="https://search.test/",
    )
    values.update(changes)
    return PhonePublicProvider(**values)


def response(status, body, *, final_url="https://search.test/?q=fixture", redirected=False):
    return PhonePublicHttpResponse(
        status_code=status,
        final_url=final_url,
        body=body,
        redirected=redirected,
    )


def matched_html(*, phone="+48 12 345 67 89", result_url="https://company.test/contact"):
    return f"""
    <html><body>
      <article class="result" data-result="1">
        <a class="result__a" href="{result_url}">Fixture Company contact</a>
        <p class="result__snippet">Kontakt: {phone}; contact Fixture.User@example.test; @fixture_handle</p>
        <time datetime="2025-09-20T00:00:00+00:00"></time>
        <script type="application/ld+json">
          {{"@type":"Organization","name":"Fixture Company","address":{{"addressLocality":"Fixture City"}}}}
        </script>
      </article>
    </body></html>
    """


def target_html(*, phone="+48 12 345 67 89"):
    return f"""
    <html><head><title>Fixture Company contact</title></head><body>
      <p>Kontakt: {phone}; Fixture.User@example.test; @fixture_handle</p>
      <a href="/contact.pdf">Contact document</a>
      <time datetime="2025-09-20T00:00:00+00:00"></time>
      <script type="application/ld+json">
        {{"@type":"Organization","name":"Fixture Company",
        "address":{{"addressLocality":"Fixture City"}}}}
      </script>
    </body></html>
    """


def manifest(*, passive=True, case_id="case-phone-public-001"):
    allowed = {SourceClass.LOCAL}
    if passive:
        allowed.add(SourceClass.PASSIVE_WEB)
    return CaseManifest(
        case_id=case_id,
        case_name="Synthetic phone public fixture",
        created_at=NOW - timedelta(days=1),
        authorized_by="fixture-reviewer",
        purpose="Offline public phone occurrence test",
        legal_basis_or_consent_note="Synthetic number and reserved .test sources only.",
        seed_entities=(SeedEntity(entity_type="PHONE", value=PHONE),),
        allowed_source_classes=frozenset(allowed),
        forbidden_source_classes=frozenset({SourceClass.THIRD_PARTY_API, SourceClass.TOR, SourceClass.DIRECT_TARGET}),
        allowed_agent_types=frozenset({"PHONE"}),
        retention_days=7,
        status=CaseStatus.ACTIVE,
    )


def setup_orchestrator(tmp_path, collector):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    audit = AuditLog(repo_root=repo, root=tmp_path / "private-audit")
    vault = EvidenceVault(repo_root=repo, root=tmp_path / "private-vault")
    registry = CollectorRegistry()
    registry.register(collector, metadata_for(collector, network_required=True, provenance="fixture:http"))
    orchestrator = Orchestrator(
        audit_log=audit,
        authorization_store=AuthorizationStore(repo_root=repo, root=tmp_path / "private-auth"),
        collector_registry=registry,
        evidence_vault=vault,
        clock=lambda: NOW,
    )
    return orchestrator, audit, vault, registry


def execute(orchestrator, collector, *, case=None):
    return orchestrator.execute(
        manifest=case or manifest(),
        collector=collector,
        seed_reference=PHONE,
        purpose="Synthetic public phone test",
        requested_by="fixture-runner",
    )


def run_public_case(tmp_path, collector, *, case_id):
    repo = tmp_path / "repo"
    repo.mkdir()
    case_root = tmp_path / "cases"
    store = CaseStore(repo_root=repo, root=case_root)
    vault = EvidenceVault(repo_root=repo, root=case_root)
    audit = AuditLog(repo_root=repo, root=tmp_path / "audit")
    registry = CollectorRegistry()
    registry.register(collector, metadata_for(collector, network_required=True, provenance="fixture:http"))
    runner = CaseRunner(
        orchestrator=Orchestrator(
            audit_log=audit,
            authorization_store=AuthorizationStore(repo_root=repo, root=tmp_path / "auth"),
            collector_registry=registry,
            evidence_vault=vault,
            clock=lambda: NOW,
        ),
        registry=registry,
        collectors={"phone_public_web": collector},
        case_store=store,
        report_engine=ReportEngine(evidence_vault=vault, case_root=case_root, clock=lambda: NOW),
        audit_log=audit,
        clock=lambda: NOW,
        id_factory=lambda: case_id,
    )
    case = manifest(case_id=case_id)
    store.create(case)
    return runner.run(case)


def test_phone_variants_are_canonical_bounded_and_deduplicated():
    variants = generate_phone_variants(PHONE)
    assert {item.canonical_e164 for item in variants} == {PHONE}
    assert [item.variant for item in variants] == [
        "+48123456789",
        "123456789",
        "12 345 67 89",
        "12-345-67-89",
        "+48 12 345 67 89",
        "48 12 345 67 89",
    ]
    assert len({item.variant for item in variants}) == len(variants)


def test_exact_snippet_match_is_accepted_and_duplicates_are_removed(tmp_path):
    client = FakeHttpClient(response(200, matched_html()))
    target = FakeTargetFetcher(target_html())
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=client, target_fetcher=target, clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)
    assert len(client.calls) == len(generate_phone_variants(PHONE))
    assert len(target.calls) == 1
    assert len(result.observations) == 1
    payload = result.observations[0].payload
    assert payload["status"] == "MATCH"
    assert payload["match_level"] == "PHONE_CONTEXT_MATCH"
    assert payload["exact_match"] is True
    assert payload["matched_variant"] == "+48 12 345 67 89"
    assert payload["match_location"] == "snippet"
    assert payload["target_verified"] is True
    assert payload["target_body_sha256"]
    assert payload["target_domain"] == "company.test"
    assert payload["discovery_provider"] == "fixture_search"
    assert payload["discovery_query_variant"]
    assert payload["discovery_result_url"] == "https://company.test/contact"
    assert payload["target_signal_type"] == "VISIBLE_PHONE_CONTEXT"
    assert payload["context_snippet"]
    assert result.finding_candidates[0].normalized_status is FindingStatus.POSSIBLE


def test_same_target_from_two_search_providers_is_fetched_once(tmp_path):
    providers = (
        provider(provider_id="search_one", name="Search One", search_url_template="https://one.search.test/?q={query}"),
        provider(provider_id="search_two", name="Search Two", search_url_template="https://two.search.test/?q={query}"),
    )
    target = FakeTargetFetcher(target_html())

    def search_response(url):
        result_url = (
            "https://company.test/contact?utm_source=one&id=42#phone"
            if "one.search.test" in url
            else "https://company.test/contact?id=42&fbclid=fixture"
        )
        return response(200, matched_html(result_url=result_url), final_url=url)

    collector = PhonePublicWebCollector(
        providers=providers,
        http_client=FakeHttpClient(search_response),
        target_fetcher=target,
        clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)
    assert len(target.calls) == 1
    assert len(result.observations) == 1
    channels = result.observations[0].payload["discovery_channels"]
    assert {item["provider_id"] for item in channels} == {"search_one", "search_two"}
    assert result.observations[0].payload["target_canonical_url"] == "https://company.test/contact?id=42"


@pytest.mark.parametrize(("same_content", "expected_groups"), ((False, 2), (True, 1)))
def test_target_sources_drive_independence_and_duplicate_content_clustering(tmp_path, same_content, expected_groups):
    first_url = "https://one-target.test/contact"
    second_url = "https://two-target.test/contact"
    providers = (
        provider(provider_id="search_one", name="Search One", search_url_template="https://one.search.test/?q={query}"),
        provider(provider_id="search_two", name="Search Two", search_url_template="https://two.search.test/?q={query}"),
    )

    def search_response(url):
        target_url = first_url if "one.search.test" in url else second_url
        return response(200, matched_html(result_url=target_url), final_url=url)

    first_body = target_html()
    second_body = first_body if same_content else target_html().replace("Fixture Company", "Independent Company")
    collector = PhonePublicWebCollector(
        providers=providers,
        http_client=FakeHttpClient(search_response),
        target_fetcher=FakeTargetFetcher({first_url: first_body, second_url: second_body}),
        clock=lambda: NOW,
    )
    result = run_public_case(tmp_path, collector, case_id=f"case-independence-{int(same_content)}")
    evidence = [
        item for item in result.intelligence_summary.evidence_quality
        if item.source_name == "phone_public_web" and item.match_level == "PHONE_CONTEXT_MATCH"
    ]
    assert len(evidence) == 2
    assert len({item.independence_group for item in evidence}) == expected_groups


def test_search_candidate_without_verified_target_creates_no_intelligence(tmp_path):
    collector = PhonePublicWebCollector(
        providers=(provider(),),
        http_client=FakeHttpClient(response(200, matched_html())),
        target_fetcher=FakeTargetFetcher("", status=FetchStatus.UNKNOWN, error_code="TIMEOUT"),
        clock=lambda: NOW,
    )
    result = run_public_case(tmp_path, collector, case_id="case-search-only")
    assert result.intelligence_summary.probable_correlations == ()
    assert result.intelligence_summary.open_hypotheses == ()
    assert all(item.proposed_collector != "domain_dns" for item in result.intelligence_summary.recommended_pivots)


def test_exact_body_match_is_accepted(tmp_path):
    html = '<html><body><article class="result"><a href="https://page.test/contact">Contact</a>' \
           '<div>Telephone +48 12 345 67 89</div></article></body></html>'
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, html)),
        target_fetcher=FakeTargetFetcher('<p>Telephone +48 12 345 67 89</p>'), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    payload = execute(orchestrator, collector).observations[0].payload
    assert payload["status"] == "MATCH"
    assert payload["match_location"] == "snippet"


def test_fuzzy_or_non_exact_result_is_unknown(tmp_path):
    html = matched_html(phone="+48 12 345 67 890")
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, html)),
        target_fetcher=FakeTargetFetcher('<p>Kontakt: +48 12 345 67 890</p>'), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    payload = execute(orchestrator, collector).observations[0].payload
    assert payload["status"] == "UNKNOWN"
    assert payload["exact_match"] is False
    assert payload["error_code"] == "NON_EXACT_CANDIDATE"


@pytest.mark.parametrize(
    ("result_url", "visible_text"),
    [
        pytest.param(
            "https://stock-images.test/image-photo/man-chainsaw-cutting-tree-123456789",
            "Stock photo result",
            id="shutterstock-style-image-id",
        ),
        ("https://shop.test/item/widget", "Product ID: 123456789"),
        ("https://news.test/story", "Article ID: 123456789"),
        ("https://example.test/resources/123456789", "Unrelated public result"),
    ],
)
def test_numeric_resource_identifiers_are_rejected(tmp_path, result_url, visible_text):
    html = (
        '<html><body><article class="result"><a class="result__a" '
        f'href="{result_url}">Fixture result</a><p>{visible_text}</p></article></body></html>'
    )
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, html)),
        target_fetcher=FakeTargetFetcher(f"<p>{visible_text}</p>"), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)
    payload = result.observations[0].payload
    assert payload["status"] == "UNKNOWN"
    assert payload["match_level"] == "REJECTED_NUMERIC_ID"
    assert payload["semantic_match"] is False
    assert payload["error_code"] == "REJECTED_NUMERIC_ID"
    assert result.finding_candidates[0].normalized_status is FindingStatus.UNKNOWN


def test_generic_visible_numeric_token_is_not_a_phone_match(tmp_path):
    html = ('<html><body><article class="result"><a href="https://example.test/value">Value</a>'
            '<p>Reference 123456789 appears in unrelated text.</p></article></body></html>')
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, html)),
        target_fetcher=FakeTargetFetcher('<p>Reference 123456789 appears in unrelated text.</p>'),
        clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    payload = execute(orchestrator, collector).observations[0].payload
    assert payload["status"] == "UNKNOWN"
    assert payload["match_level"] == "NUMERIC_MATCH_ONLY"
    assert payload["numeric_exact_match"] is True
    assert payload["exact_match"] is False


@pytest.mark.parametrize("label", ("Telefon", "Kontakt"))
def test_visible_phone_context_accepts_normalized_number(tmp_path, label):
    html = ('<html><body><article class="result"><a href="https://company.test/contact">Contact</a>'
            f'<p>{label}: 123 456 789</p></article></body></html>')
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, html)),
        target_fetcher=FakeTargetFetcher(f'<p>{label}: 123 456 789</p>'), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    payload = execute(orchestrator, collector).observations[0].payload
    assert payload["status"] == "MATCH"
    assert payload["match_level"] == "PHONE_CONTEXT_MATCH"
    assert payload["semantic_match"] is True


@pytest.mark.parametrize(
    ("structured_html", "expected_location"),
    [
        ('<a href="tel:+48123456789">Call</a>', "structured:tel_href"),
        ('<script type="application/ld+json">'
         '{"@type":"Organization","telephone":"+48123456789"}</script>',
         "structured:json_ld_telephone"),
    ],
)
def test_structured_telephone_fields_are_accepted(tmp_path, structured_html, expected_location):
    html = ('<html><body><article class="result"><a class="result__a" '
            'href="https://company.test/contact">Contact page</a>' + structured_html + '</article></body></html>')
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, html)),
        target_fetcher=FakeTargetFetcher(structured_html), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    payload = execute(orchestrator, collector).observations[0].payload
    assert payload["status"] == "MATCH"
    assert payload["match_level"] == "STRUCTURED_PHONE_MATCH"
    assert payload["match_location"] == expected_location


@pytest.mark.parametrize(
    ("http_response", "expected_code"),
    [
        (response(200, "<html>captcha</html>"), "CHALLENGE"),
        (response(403, "forbidden"), "HTTP_403"),
        (response(429, "rate limited"), "HTTP_429"),
        (response(200, "<html><body>generic page</body></html>"), "GENERIC_PAGE"),
        (response(503, "server unavailable"), "HTTP_SERVER_ERROR"),
        (response(200, "generic", final_url="https://search.test/", redirected=True), "REDIRECT_HOME"),
    ],
)
def test_provider_failures_are_unknown_not_no_match(tmp_path, http_response, expected_code):
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(http_response), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)
    assert result.observations[0].payload["status"] == "UNKNOWN"
    assert result.observations[0].payload["error_code"] == expected_code
    assert result.finding_candidates[0].normalized_status is FindingStatus.UNKNOWN


def test_timeout_is_unknown(tmp_path):
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(PhonePublicHttpTimeout("timeout")), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    payload = execute(orchestrator, collector).observations[0].payload
    assert payload["status"] == "UNKNOWN"
    assert payload["error_code"] == "TIMEOUT"


def test_explicit_provider_no_match_rule(tmp_path):
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, "NO_RESULTS_FIXTURE")), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)
    assert result.observations[0].payload["status"] == "NO_MATCH"
    assert result.finding_candidates[0].normalized_status is FindingStatus.NOT_FOUND


def test_entity_extraction_is_conservative_and_evidence_bound(tmp_path):
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, matched_html())),
        target_fetcher=FakeTargetFetcher(target_html()), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    observation = execute(orchestrator, collector).observations[0]
    entities = observation.payload["discovered_entities"]
    by_type = {item["entity_type"]: item for item in entities}
    assert by_type["EMAIL"]["value"] == "fixture.user@example.test"
    assert by_type["DOMAIN"]["value"] == "company.test"
    assert by_type["USERNAME"]["value"] == "fixture_handle"
    assert by_type["COMPANY"]["value"] == "Fixture Company"
    assert by_type["LOCATION"]["value"] == "Fixture City"
    assert by_type["DOCUMENT"]["value"] == "contact.pdf"
    assert all(item["evidence_ref"] == observation.evidence_ref for item in entities)
    serialized = json.dumps(entities).casefold()
    assert "owner found" not in serialized
    assert "subscriber identified" not in serialized


def test_old_source_date_is_preserved_with_warning(tmp_path):
    html = matched_html()
    old_target = target_html().replace("2025-09-20T00:00:00+00:00", "2020-01-01T00:00:00+00:00")
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, html)),
        target_fetcher=FakeTargetFetcher(old_target), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    payload = execute(orchestrator, collector).observations[0].payload
    assert payload["source_date"] == "2020-01-01T00:00:00+00:00"
    assert "older than 24 months" in payload["source_date_warning"]


def test_duplicate_content_and_same_domain_share_independence_group():
    items = (
        EvidenceItem(evidence_id="a", source_name="phone_public_web", source_class="PASSIVE_WEB",
                     collected_at=NOW, directness=Directness.DIRECT, canonical_url="https://one.test/a",
                     domain="one.test", content_hash="same"),
        EvidenceItem(evidence_id="b", source_name="phone_public_web", source_class="PASSIVE_WEB",
                     collected_at=NOW, directness=Directness.DIRECT, canonical_url="https://mirror.test/b",
                     domain="mirror.test", content_hash="same"),
        EvidenceItem(evidence_id="c", source_name="phone_public_web", source_class="PASSIVE_WEB",
                     collected_at=NOW, directness=Directness.DIRECT, canonical_url="https://one.test/c",
                     domain="one.test", content_hash="different"),
    )
    assessed, summary = EvidenceQualityEngine().assess(items, now=NOW)
    assert len({item.independence_group for item in assessed}) == 1
    assert summary.independent_group_count == 1


@pytest.mark.parametrize(
    ("match_level", "expected_score"),
    [
        ("REJECTED_NUMERIC_ID", 0.1),
        ("NUMERIC_MATCH", 0.25),
        ("PHONE_CONTEXT_MATCH", 0.75),
        ("STRUCTURED_PHONE_MATCH", 0.9),
    ],
)
def test_semantic_match_level_caps_evidence_quality_with_reason(match_level, expected_score):
    evidence = EvidenceItem(
        evidence_id=f"evidence-{match_level}",
        source_name="phone_public_web",
        source_class="PASSIVE_WEB",
        collected_at=NOW,
        directness=Directness.DIRECT,
        reproducible=True,
        match_level=match_level,
    )
    assessed, _ = EvidenceQualityEngine().assess((evidence,), now=NOW)
    assert assessed[0].quality_score == expected_score
    assert any(match_level in reason and "caps quality" in reason for reason in assessed[0].quality_reasons)


def test_directory_page_role_scores_below_first_party_contact_page():
    contact = EvidenceItem(
        evidence_id="contact", source_name="phone_public_web", source_class="PASSIVE_WEB",
        collected_at=NOW, directness=Directness.DIRECT, reproducible=True,
        match_level="PHONE_CONTEXT_MATCH", page_role="CONTACT_PAGE",
    )
    directory = EvidenceItem(
        evidence_id="directory", source_name="phone_public_web", source_class="PASSIVE_WEB",
        collected_at=NOW, directness=Directness.DIRECT, reproducible=True,
        match_level="PHONE_CONTEXT_MATCH", page_role="DIRECTORY",
    )
    assessed, _ = EvidenceQualityEngine().assess((contact, directory), now=NOW)
    assert assessed[0].quality_score == 0.75
    assert assessed[1].quality_score == 0.65
    assert any("DIRECTORY" in reason for reason in assessed[1].quality_reasons)


def test_policy_denial_prevents_http(tmp_path):
    client = FakeHttpClient(response(200, matched_html()))
    target = FakeTargetFetcher(target_html())
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=client, target_fetcher=target, clock=lambda: NOW,
    )
    orchestrator, audit, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector, case=manifest(passive=False))
    assert result.status.value == "DENIED"
    assert client.calls == []
    assert target.calls == []
    assert audit.read("case-phone-public-001")[-1]["event_type"] == "RUN_DENIED"


def test_allowed_run_stores_evidence_and_keeps_audit_and_receipt_private(tmp_path):
    client = FakeHttpClient(response(200, matched_html()))
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=client, target_fetcher=FakeTargetFetcher(target_html()),
        clock=lambda: NOW,
    )
    orchestrator, audit, vault, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)
    assert result.receipt is not None
    assert result.receipt.collector == "phone_public_web"
    assert result.receipt.source_class is SourceClass.PASSIVE_WEB
    assert result.receipt.audit_head_hash == verify_audit_log(audit, "case-phone-public-001").head_hash
    audit_bytes = (audit.root / "case-phone-public-001" / "audit.jsonl").read_bytes()
    assert PHONE.encode() not in audit_bytes
    assert hashlib.sha256(PHONE.encode()).hexdigest().encode() in audit_bytes
    raw_directory = next((vault.root / "case-phone-public-001" / "raw").glob("ev-*"))
    raw_bytes = next(raw_directory.glob("run-*.json")).read_bytes()
    assert PHONE.encode() in raw_bytes
    receipt_directory = next((vault.root / "case-phone-public-001" / "reports").glob("ev-*"))
    receipt_bytes = next(receipt_directory.glob("run-*-receipt.json")).read_bytes()
    assert PHONE.encode() not in receipt_bytes


def test_default_registry_contains_reviewed_phone_public_collector():
    registry = build_default_registry()
    collector = PhonePublicWebCollector()
    metadata = registry.validate(collector)
    assert metadata.source_class is SourceClass.PASSIVE_WEB
    assert metadata.network_required is True
    assert metadata.capabilities["providers"] == ["duckduckgo_html", "mojeek_html_candidate"]
    assert metadata.capabilities["enabled_providers"] == ["duckduckgo_html"]
    changed = PhonePublicWebCollector(providers=(replace(provider(), provider_id="other"),))
    with pytest.raises(PermissionError, match="metadata"):
        registry.validate(changed)


def test_case_runner_intelligence_pivots_and_report_are_integrated(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    case_root = tmp_path / "private-cases"
    store = CaseStore(repo_root=repo, root=case_root)
    vault = EvidenceVault(repo_root=repo, root=case_root)
    audit = AuditLog(repo_root=repo, root=tmp_path / "audit")
    public = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, matched_html())),
        target_fetcher=FakeTargetFetcher(target_html()), clock=lambda: NOW,
    )
    local = PhoneMetadataCollector()
    registry = CollectorRegistry()
    registry.register(local, metadata_for(local, network_required=False, provenance="phonenumbers:fixture"))
    registry.register(public, metadata_for(public, network_required=True, provenance="fixture:http"))
    orchestrator = Orchestrator(
        audit_log=audit,
        authorization_store=AuthorizationStore(repo_root=repo, root=tmp_path / "auth"),
        collector_registry=registry,
        evidence_vault=vault,
        clock=lambda: NOW,
    )
    runner = CaseRunner(
        orchestrator=orchestrator,
        registry=registry,
        collectors={"phone_metadata": local, "phone_public_web": public},
        case_store=store,
        report_engine=ReportEngine(evidence_vault=vault, case_root=case_root, clock=lambda: NOW),
        audit_log=audit,
        clock=lambda: NOW,
        id_factory=lambda: "phone-public-run",
    )
    case = manifest()
    store.create(case)
    result = runner.run(case)
    assert [item.step.collector_name for item in result.executions] == ["phone_metadata", "phone_public_web"]
    summary = result.intelligence_summary
    assert summary is not None
    assert any(item.relation_type == "MENTIONED_ON" for item in summary.probable_correlations)
    assert any(item.relation_type == "MENTIONS" for item in summary.probable_correlations)
    assert any(item.relation_type == "ASSOCIATED_WITH" for item in summary.probable_correlations)
    assert all(item.status.value != "CONFIRMED" for item in summary.probable_correlations)
    pivot_names = {item.proposed_collector for item in summary.recommended_pivots}
    assert {"email_local_metadata", "email_exposure", "domain_dns", "username_lookup"} <= pivot_names
    report = json.loads(Path(result.report_reference.json_path).read_text(encoding="utf-8"))
    phone_section = report["phone_public_intelligence"]
    assert report["schema_version"] == "1.4"
    assert phone_section["provider_count"] == 1
    assert phone_section["status_counts"]["MATCH"] == 1
    assert phone_section["discovered_entities"]
    assert phone_section["source_independence_groups"]
    assert phone_section["correlations"]
    assert phone_section["hypotheses"]
    assert any("stale" in item for item in phone_section["alternative_explanations"])
    assert phone_section["recommended_pivots"]
    assert phone_section["target_pages_checked"] == 1
    assert len(phone_section["target_pages_verified"]) == 1
    assert phone_section["target_pages_rejected"] == []
    assert phone_section["phone_signals"]
    html = Path(result.report_reference.html_path).read_text(encoding="utf-8")
    assert "PHONE PUBLIC INTELLIGENCE" in html
    assert "Public occurrence" in html
    assert "Possible association" in html
    assert "Not independently verified" in html
    assert "SEARCH DISCOVERY" in html
    assert "TARGET PAGES VERIFIED" in html
    assert "Owner found" not in html
    assert "Subscriber identified" not in html


def test_rejected_numeric_id_stays_low_quality_and_cannot_drive_intelligence(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    case_root = tmp_path / "private-cases"
    store = CaseStore(repo_root=repo, root=case_root)
    vault = EvidenceVault(repo_root=repo, root=case_root)
    audit = AuditLog(repo_root=repo, root=tmp_path / "audit")
    rejected_html = (
        '<html><body><article class="result"><a class="result__a" '
        'href="https://stock-images.test/image-photo/synthetic-fixture-123456789">'
        'Synthetic stock image</a><p>Royalty-free image result.</p></article></body></html>'
    )
    public = PhonePublicWebCollector(
        providers=(provider(),),
        http_client=FakeHttpClient(response(200, rejected_html)),
        target_fetcher=FakeTargetFetcher("<p>Royalty-free image result.</p>"),
        clock=lambda: NOW,
    )
    local = PhoneMetadataCollector()
    registry = CollectorRegistry()
    registry.register(local, metadata_for(local, network_required=False, provenance="phonenumbers:fixture"))
    registry.register(public, metadata_for(public, network_required=True, provenance="fixture:http"))
    runner = CaseRunner(
        orchestrator=Orchestrator(
            audit_log=audit,
            authorization_store=AuthorizationStore(repo_root=repo, root=tmp_path / "auth"),
            collector_registry=registry,
            evidence_vault=vault,
            clock=lambda: NOW,
        ),
        registry=registry,
        collectors={"phone_metadata": local, "phone_public_web": public},
        case_store=store,
        report_engine=ReportEngine(evidence_vault=vault, case_root=case_root, clock=lambda: NOW),
        audit_log=audit,
        clock=lambda: NOW,
        id_factory=lambda: "phone-public-rejected-run",
    )
    case = manifest(case_id="case-phone-public-rejected")
    store.create(case)
    result = runner.run(case)
    summary = result.intelligence_summary
    assert summary is not None
    assert summary.probable_correlations == ()
    assert summary.open_hypotheses == ()
    assert all(item.proposed_collector != "domain_dns" for item in summary.recommended_pivots)
    rejected_evidence = next(item for item in summary.evidence_quality if item.source_name == "phone_public_web")
    assert rejected_evidence.match_level == "REJECTED_NUMERIC_ID"
    assert rejected_evidence.quality_score <= 0.1
    assert any("caps quality" in reason for reason in rejected_evidence.quality_reasons)
    report = json.loads(Path(result.report_reference.json_path).read_text(encoding="utf-8"))
    rejected = report["phone_public_intelligence"]["false_positives_rejected"]
    assert len(rejected) == 1
    assert rejected[0]["match_location"] == "url"
    assert "resource/image identifier" in rejected[0]["reason"]
    assert report["phone_public_intelligence"]["public_urls"] == []
    html = Path(result.report_reference.html_path).read_text(encoding="utf-8")
    assert "FALSE POSITIVES REJECTED" in html
    assert "resource/image identifier" in html


def test_phone_public_collector_has_no_prohibited_automation_imports():
    root = Path(__file__).resolve().parents[1] / "osint_lab" / "agents"
    source = "\n".join(
        (root / name).read_text(encoding="utf-8")
        for name in (
            "phone_public_web.py", "phone_public_http.py", "phone_public_providers.py",
            "phone_public_parsers.py", "phone_public_extract.py", "phone_public_semantics.py",
            "phone_variants.py", "target_page_analysis.py", "target_page_fetcher.py",
        )
    ).casefold()
    for forbidden in (
        "import subprocess", "from subprocess", "import selenium", "import playwright",
        "truecaller", "phoneinfoga", "import stem", "socks5",
    ):
        assert forbidden not in source
