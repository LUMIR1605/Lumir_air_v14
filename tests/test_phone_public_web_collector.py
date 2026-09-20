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
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


def provider(**changes):
    values = dict(
        provider_id="fixture_search",
        name="Fixture Search",
        search_url_template="https://search.test/?q={query}",
        method="GET",
        source_class=SourceClass.PASSIVE_WEB,
        exact_match_required=True,
        enabled=True,
        timeout=3.0,
        privacy_notes="Fixture provider receives a synthetic phone variant.",
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


def matched_html(*, phone="+48 12 345 67 89", result_url="https://company.test/contact.pdf"):
    return f"""
    <html><body>
      <article class="result" data-result="1">
        <a class="result__a" href="{result_url}">Fixture Company contact</a>
        <p class="result__snippet">Public occurrence {phone}; contact Fixture.User@example.test; @fixture_handle</p>
        <time datetime="2025-09-20T00:00:00+00:00"></time>
        <script type="application/ld+json">
          {{"@type":"Organization","name":"Fixture Company","address":{{"addressLocality":"Fixture City"}}}}
        </script>
      </article>
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
    collector = PhonePublicWebCollector(providers=(provider(),), http_client=client, clock=lambda: NOW)
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector)
    assert len(client.calls) == len(generate_phone_variants(PHONE))
    assert len(result.observations) == 1
    payload = result.observations[0].payload
    assert payload["status"] == "MATCH"
    assert payload["exact_match"] is True
    assert payload["matched_variant"] == "+48 12 345 67 89"
    assert payload["match_location"] == "snippet"
    assert result.finding_candidates[0].normalized_status is FindingStatus.POSSIBLE


def test_exact_body_match_is_accepted(tmp_path):
    html = '<html><body><article class="result"><a href="https://page.test/contact">Contact</a>' \
           '<div>Telephone +48 12 345 67 89</div></article></body></html>'
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, html)), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    payload = execute(orchestrator, collector).observations[0].payload
    assert payload["status"] == "MATCH"
    assert payload["match_location"] == "body"


def test_fuzzy_or_non_exact_result_is_unknown(tmp_path):
    html = matched_html(phone="+48 12 345 67 890")
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, html)), clock=lambda: NOW,
    )
    orchestrator, _, _, _ = setup_orchestrator(tmp_path, collector)
    payload = execute(orchestrator, collector).observations[0].payload
    assert payload["status"] == "UNKNOWN"
    assert payload["exact_match"] is False
    assert payload["error_code"] == "NON_EXACT_CANDIDATE"


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
        providers=(provider(),), http_client=FakeHttpClient(response(200, matched_html())), clock=lambda: NOW,
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
    html = matched_html().replace("2025-09-20T00:00:00+00:00", "2020-01-01T00:00:00+00:00")
    collector = PhonePublicWebCollector(
        providers=(provider(),), http_client=FakeHttpClient(response(200, html)), clock=lambda: NOW,
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


def test_policy_denial_prevents_http(tmp_path):
    client = FakeHttpClient(response(200, matched_html()))
    collector = PhonePublicWebCollector(providers=(provider(),), http_client=client, clock=lambda: NOW)
    orchestrator, audit, _, _ = setup_orchestrator(tmp_path, collector)
    result = execute(orchestrator, collector, case=manifest(passive=False))
    assert result.status.value == "DENIED"
    assert client.calls == []
    assert audit.read("case-phone-public-001")[-1]["event_type"] == "RUN_DENIED"


def test_allowed_run_stores_evidence_and_keeps_audit_and_receipt_private(tmp_path):
    client = FakeHttpClient(response(200, matched_html()))
    collector = PhonePublicWebCollector(providers=(provider(),), http_client=client, clock=lambda: NOW)
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
    assert metadata.capabilities["providers"] == ["duckduckgo_html"]
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
        providers=(provider(),), http_client=FakeHttpClient(response(200, matched_html())), clock=lambda: NOW,
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
    assert report["schema_version"] == "1.3"
    assert phone_section["provider_count"] == 1
    assert phone_section["status_counts"]["MATCH"] == 1
    assert phone_section["discovered_entities"]
    assert phone_section["source_independence_groups"]
    assert phone_section["correlations"]
    assert phone_section["hypotheses"]
    assert any("stale" in item for item in phone_section["alternative_explanations"])
    assert phone_section["recommended_pivots"]
    html = Path(result.report_reference.html_path).read_text(encoding="utf-8")
    assert "PHONE PUBLIC INTELLIGENCE" in html
    assert "Public occurrence" in html
    assert "Possible association" in html
    assert "Not independently verified" in html
    assert "Owner found" not in html
    assert "Subscriber identified" not in html


def test_phone_public_collector_has_no_prohibited_automation_imports():
    root = Path(__file__).resolve().parents[1] / "osint_lab" / "agents"
    source = "\n".join(
        (root / name).read_text(encoding="utf-8")
        for name in (
            "phone_public_web.py", "phone_public_http.py", "phone_public_providers.py",
            "phone_public_parsers.py", "phone_public_extract.py", "phone_variants.py",
        )
    ).casefold()
    for forbidden in (
        "import subprocess", "from subprocess", "import selenium", "import playwright",
        "truecaller", "phoneinfoga", "import stem", "socks5",
    ):
        assert forbidden not in source
