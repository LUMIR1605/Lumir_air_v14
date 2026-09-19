import ast
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from osint_lab.agents import (
    CollectorRegistry,
    DomainDNSCollector,
    ExecutionStatus,
    build_default_registry,
)
from osint_lab.case_manifest import CaseManifest, CaseStatus, SeedEntity
from osint_lab.evidence import EvidenceVault
from osint_lab.orchestrator.audit import AuditLog, verify_audit_log
from osint_lab.orchestrator.authorization_store import AuthorizationStore
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus


NOW = datetime(2026, 9, 19, 16, 0, tzinfo=timezone.utc)
TEST_DOMAIN = "example.test"


class FakeName:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return self.value


class FakeAddress:
    def __init__(self, address):
        self.address = address

    def to_text(self):
        return self.address


class FakeMX:
    def __init__(self, preference, exchange):
        self.preference = preference
        self.exchange = FakeName(exchange)

    def to_text(self):
        return f"{self.preference} {self.exchange.to_text()}"


class FakeNS:
    def __init__(self, target):
        self.target = FakeName(target)

    def to_text(self):
        return self.target.to_text()


class FakeTXT:
    def __init__(self, *parts):
        self.strings = tuple(part.encode("utf-8") for part in parts)

    def to_text(self):
        return "".join(part.decode("utf-8") for part in self.strings)


class FakeAnswer(tuple):
    def __new__(cls, records, ttl=300):
        instance = super().__new__(cls, records)
        instance.rrset = SimpleNamespace(ttl=ttl)
        return instance


class FakeResolver:
    nameservers = ("192.0.2.53",)

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def resolve(self, query_name, query_type, **kwargs):
        self.calls.append((query_name, query_type, kwargs))
        response = self.responses.get((query_name, query_type), dns.resolver.NoAnswer())
        if isinstance(response, BaseException):
            raise response
        return response


def complete_responses(*, multiple_spf=False):
    spf = [FakeTXT("v=spf1 include:_spf.example.test -all")]
    if multiple_spf:
        spf.append(FakeTXT("v=spf1 ip4:192.0.2.0/24 ~all"))
    return {
        (TEST_DOMAIN, "A"): FakeAnswer([FakeAddress("192.0.2.10")], ttl=60),
        (TEST_DOMAIN, "AAAA"): FakeAnswer([FakeAddress("2001:db8::10")], ttl=60),
        (TEST_DOMAIN, "MX"): FakeAnswer([FakeMX(10, "mail.example.test.")]),
        (TEST_DOMAIN, "NS"): FakeAnswer([FakeNS("ns1.example.test.")]),
        (TEST_DOMAIN, "TXT"): FakeAnswer([
            FakeTXT("site-verification=fixture"),
            *spf,
        ]),
        (f"_dmarc.{TEST_DOMAIN}", "TXT"): FakeAnswer([
            FakeTXT(
                "v=DMARC1; p=reject; sp=quarantine; pct=50; "
                "rua=mailto:aggregate@example.test; ruf=mailto:forensic@example.test"
            ),
        ]),
    }


def domain_manifest(*, allow_passive=True):
    allowed = {SourceClass.LOCAL}
    if allow_passive:
        allowed.add(SourceClass.PASSIVE_WEB)
    return CaseManifest(
        case_id="case-domain-dns-001",
        case_name="Synthetic DNS fixture",
        created_at=NOW - timedelta(days=1),
        authorized_by="fixture-owner",
        purpose="Deterministic mocked DNS test",
        legal_basis_or_consent_note="Reserved .test domain only.",
        seed_entities=(SeedEntity(entity_type="DOMAIN", value=TEST_DOMAIN),),
        allowed_source_classes=frozenset(allowed),
        forbidden_source_classes=frozenset({
            SourceClass.THIRD_PARTY_API,
            SourceClass.TOR,
            SourceClass.DIRECT_TARGET,
        }),
        allowed_agent_types=frozenset({"DOMAIN"}),
        retention_days=7,
        status=CaseStatus.ACTIVE,
    )


def setup_orchestrator(tmp_path, resolver):
    repo = tmp_path / "repo"
    repo.mkdir()
    audit = AuditLog(repo_root=repo, root=tmp_path / "private-audit")
    vault = EvidenceVault(repo_root=repo, root=tmp_path / "private-vault")
    orchestrator = Orchestrator(
        audit_log=audit,
        authorization_store=AuthorizationStore(
            repo_root=repo,
            root=tmp_path / "private-authorizations",
        ),
        collector_registry=build_default_registry(),
        evidence_vault=vault,
        clock=lambda: NOW,
    )
    collector = DomainDNSCollector(resolver=resolver, resolver_label="mock://192.0.2.53")
    return orchestrator, collector, audit, vault


def execute(orchestrator, collector, *, manifest=None, domain=TEST_DOMAIN):
    return orchestrator.execute(
        manifest=manifest or domain_manifest(),
        collector=collector,
        seed_reference=domain,
        purpose="Deterministic mocked DNS test",
        requested_by="fixture-requester",
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.test", "example.test"),
        ("  EXAMPLE.TEST.  ", "example.test"),
        ("sub.example.test", "sub.example.test"),
        ("täst.example", "xn--tst-qla.example"),
    ],
)
def test_domain_input_normalization(value, expected):
    assert DomainDNSCollector._normalize_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://example.test",
        "example.test/path",
        "example.test:443",
        "*.example.test",
        "bad..example.test",
        "bad host.example",
        "localhost",
        "127.0.0.1",
        "-bad.example",
    ],
)
def test_invalid_hostname_is_rejected(value):
    with pytest.raises(ValueError):
        DomainDNSCollector._normalize_domain(value)


def test_supported_records_spf_and_dmarc_are_preserved(tmp_path):
    resolver = FakeResolver(complete_responses(multiple_spf=True))
    orchestrator, collector, _, _ = setup_orchestrator(tmp_path, resolver)
    result = execute(orchestrator, collector)
    observations = {item.payload["query_type"]: item for item in result.observations}

    assert result.status is ExecutionStatus.SUCCESS
    assert set(observations) == {"A", "AAAA", "MX", "NS", "TXT", "SPF", "DMARC"}
    assert observations["A"].payload["records"] == ["192.0.2.10"]
    assert observations["AAAA"].payload["records"] == ["2001:db8::10"]
    assert observations["MX"].payload["records"] == ["10 mail.example.test"]
    assert observations["NS"].payload["records"] == ["ns1.example.test"]
    assert observations["TXT"].payload["records"][0] == "site-verification=fixture"
    assert observations["A"].payload["ttl"] == 60
    assert observations["A"].payload["resolver"] == "mock://192.0.2.53"

    assert observations["SPF"].payload["status"] == "FOUND"
    assert observations["SPF"].payload["records"] == [
        "v=spf1 include:_spf.example.test -all",
        "v=spf1 ip4:192.0.2.0/24 ~all",
    ]
    dmarc = observations["DMARC"].payload["dmarc_records"][0]
    assert dmarc == {
        "raw": (
            "v=DMARC1; p=reject; sp=quarantine; pct=50; "
            "rua=mailto:aggregate@example.test; ruf=mailto:forensic@example.test"
        ),
        "p": "reject",
        "sp": "quarantine",
        "pct": "50",
        "rua": "mailto:aggregate@example.test",
        "ruf": "mailto:forensic@example.test",
    }
    assert json.loads(json.dumps(dict(observations["DMARC"].payload)))
    assert all(
        candidate.normalized_status is FindingStatus.POSSIBLE
        for candidate in result.finding_candidates
    )


@pytest.mark.parametrize(
    ("failure", "status", "error_code", "candidate_status"),
    [
        (dns.resolver.NXDOMAIN(), "NXDOMAIN", "NXDOMAIN", FindingStatus.UNKNOWN),
        (dns.resolver.NoAnswer(), "NOT_FOUND", "NO_ANSWER", FindingStatus.NOT_FOUND),
        (dns.exception.Timeout(), "UNKNOWN", "TIMEOUT", FindingStatus.UNKNOWN),
        (dns.resolver.NoNameservers(), "UNKNOWN", "NO_NAMESERVERS", FindingStatus.UNKNOWN),
        (RuntimeError("resolver unavailable"), "ERROR", "RUNTIMEERROR", FindingStatus.UNKNOWN),
    ],
)
def test_dns_failures_never_become_false_not_found(
    tmp_path,
    failure,
    status,
    error_code,
    candidate_status,
):
    resolver = FakeResolver({(TEST_DOMAIN, "A"): failure})
    orchestrator, collector, _, _ = setup_orchestrator(tmp_path, resolver)
    result = execute(orchestrator, collector)
    index = next(
        position
        for position, item in enumerate(result.observations)
        if item.payload["query_type"] == "A"
    )
    observation = result.observations[index]

    assert result.status is ExecutionStatus.SUCCESS
    assert observation.payload["status"] == status
    assert observation.payload["error_code"] == error_code
    assert result.finding_candidates[index].normalized_status is candidate_status
    if status != "NOT_FOUND":
        assert result.finding_candidates[index].normalized_status is not FindingStatus.NOT_FOUND


def test_domain_collector_metadata_registry_and_policy_gate(tmp_path):
    collector = DomainDNSCollector(resolver=FakeResolver(), resolver_label="mock")
    assert collector.source_class is SourceClass.PASSIVE_WEB
    assert collector.network_required is True
    assert collector.describe_capabilities()["network"] is True

    registry = build_default_registry()
    metadata = registry.validate(collector)
    assert metadata.network_required is True
    assert metadata.provenance.startswith("dnspython:")
    with pytest.raises(PermissionError, match="not registered"):
        CollectorRegistry().validate(collector)

    resolver = FakeResolver(complete_responses())
    orchestrator, collector, audit, _ = setup_orchestrator(tmp_path, resolver)
    denied = execute(
        orchestrator,
        collector,
        manifest=domain_manifest(allow_passive=False),
    )
    assert denied.status is ExecutionStatus.DENIED
    assert resolver.calls == []
    assert audit.read("case-domain-dns-001")[-1]["event_type"] == "RUN_DENIED"


def test_orchestrator_persists_dns_evidence_receipt_and_private_audit(tmp_path):
    resolver = FakeResolver(complete_responses())
    orchestrator, collector, audit, vault = setup_orchestrator(tmp_path, resolver)
    result = execute(orchestrator, collector)

    assert result.status is ExecutionStatus.SUCCESS
    assert result.receipt is not None
    assert result.receipt.collector == "domain_dns"
    assert result.receipt.source_class is SourceClass.PASSIVE_WEB
    assert result.receipt.audit_head_hash == verify_audit_log(
        audit,
        "case-domain-dns-001",
    ).head_hash
    events = audit.read("case-domain-dns-001")
    assert events[1]["decision"] == "ALLOW"
    assert events[2]["decision"] == "NOT_REQUIRED"
    audit_bytes = (audit.root / "case-domain-dns-001" / "audit.jsonl").read_bytes()
    assert TEST_DOMAIN.encode() not in audit_bytes
    assert hashlib.sha256(TEST_DOMAIN.encode()).hexdigest().encode() in audit_bytes

    raw_directory = next((vault.root / "case-domain-dns-001" / "raw").glob("ev-*"))
    record = json.loads(next(raw_directory.glob("run-*.json")).read_text(encoding="utf-8"))
    payloads = {item["payload"]["query_type"]: item["payload"] for item in record["raw_observations"]}
    assert payloads["A"]["records"] == ["192.0.2.10"]
    assert payloads["DMARC"]["dmarc_records"][0]["p"] == "reject"
    assert record["execution_metadata"]["source_class"] == "PASSIVE_WEB"

    receipt_directory = next((vault.root / "case-domain-dns-001" / "reports").glob("ev-*"))
    receipt_bytes = next(receipt_directory.glob("run-*-receipt.json")).read_bytes()
    assert b"192.0.2.10" not in receipt_bytes
    assert b"v=DMARC1" not in receipt_bytes
    assert result.receipt.evidence_refs[0] == json.loads(
        (raw_directory / "metadata.json").read_text(encoding="utf-8")
    )["evidence_id"]

    serialized = json.dumps(record)
    for forbidden_claim in ("OWNER", "IDENTITY_MATCH", "PERSON_TO_DOMAIN"):
        assert forbidden_claim not in serialized
    assert all(
        candidate.normalized_status is not FindingStatus.CONFIRMED
        for candidate in result.finding_candidates
    )


def test_domain_collector_has_no_http_or_subprocess_imports():
    source_path = Path(__file__).resolve().parents[1] / "osint_lab" / "agents" / "domain_dns.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports.isdisjoint({"requests", "urllib", "subprocess"})
