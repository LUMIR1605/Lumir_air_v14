"""Public domain RDAP adapter using the official IANA bootstrap registry."""

from datetime import datetime, timezone
import ipaddress
import json
import re
from typing import Callable, Mapping
from urllib.parse import quote

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus

from .base import Collector, FindingCandidate, RawObservation
from .target_page_fetcher import FetchStatus, TargetPageFetcher


_LABEL = re.compile(r"^[a-z0-9-]+$")


class DomainRdapCollector(Collector):
    agent_name = "domain_rdap"
    agent_type = "DOMAIN"
    version = "1.0.0"
    source_class = SourceClass.PASSIVE_WEB
    network_required = True
    bootstrap_url = "https://data.iana.org/rdap/dns.json"

    def __init__(self, *, fetcher=None, clock: Callable[[], datetime] | None = None) -> None:
        super().__init__()
        self._fetcher = fetcher or TargetPageFetcher(
            supported_content_types=frozenset({"application/json", "application/rdap+json"}),
            max_response_bytes=1_048_576,
        )
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def validate_input(self, seed_reference: str) -> None:
        self._domain(seed_reference)

    def _run(self, context: ExecutionContext, seed_reference: str) -> tuple[RawObservation, ...]:
        domain = self._domain(seed_reference)
        bootstrap = self._fetcher.fetch(self.bootstrap_url)
        if bootstrap.fetch_status is not FetchStatus.SUCCESS:
            return (self._unknown(domain, "BOOTSTRAP_" + (bootstrap.error_code or bootstrap.fetch_status.value)),)
        try:
            endpoint = self._endpoint(json.loads(bootstrap.body), domain.rsplit(".", 1)[-1])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return (self._unknown(domain, "BOOTSTRAP_PARSER_FAILURE"),)
        result = self._fetcher.fetch(endpoint.rstrip("/") + "/domain/" + quote(domain, safe=".-"))
        if result.fetch_status is not FetchStatus.SUCCESS:
            return (self._unknown(domain, result.error_code or result.fetch_status.value),)
        try:
            payload = json.loads(result.body)
            parsed = self.parse_response(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            return (self._unknown(domain, "RDAP_PARSER_FAILURE"),)
        parsed.update({
            "source_id": "registry_rdap", "source_role": "ENRICHMENT",
            "source_reputation": "OFFICIAL_PUBLIC_REGISTRY", "queried_domain": domain,
            "rdap_endpoint": endpoint, "response_sha256": result.body_sha256,
            "collected_at": self._clock().isoformat(), "failure_status": "SUCCESS",
        })
        return (RawObservation(
            raw_status="FOUND", value_reference=f"domain:{domain}",
            notes="Public RDAP registration metadata; redaction is UNKNOWN and no ownership is inferred.",
            payload=parsed,
        ),)

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        return FindingCandidate(
            raw_status=f"RDAP_{observation.raw_status}",
            normalized_status=FindingStatus.POSSIBLE if observation.raw_status == "FOUND" else FindingStatus.UNKNOWN,
            value_reference=observation.value_reference, evidence_ref=observation.evidence_ref,
            notes="RDAP metadata is technical registration evidence, not identity confirmation.",
        )

    def describe_capabilities(self) -> Mapping[str, object]:
        return {"network": True, "method": "GET", "iana_bootstrap": True, "rdap": True,
                "authentication": False, "owner_inference": False, "ssrf_protection": True}

    @staticmethod
    def _endpoint(payload: Mapping[str, object], tld: str) -> str:
        for service in payload.get("services", []):
            if not isinstance(service, list) or len(service) != 2:
                continue
            names, urls = service
            if isinstance(names, list) and tld.casefold() in {str(item).casefold() for item in names} \
                    and isinstance(urls, list) and urls:
                endpoint = str(urls[0])
                if endpoint.startswith("https://"):
                    return endpoint
        raise ValueError("no HTTPS RDAP endpoint for TLD")

    @staticmethod
    def parse_response(payload: Mapping[str, object]) -> dict[str, object]:
        if not isinstance(payload, Mapping):
            raise ValueError("RDAP response must be an object")
        events = []
        for item in payload.get("events", []):
            if isinstance(item, Mapping) and isinstance(item.get("eventAction"), str):
                events.append({"action": item.get("eventAction"), "date": item.get("eventDate")})
        nameservers = [str(item.get("ldhName")).casefold() for item in payload.get("nameservers", [])
                       if isinstance(item, Mapping) and item.get("ldhName")]
        entities = []
        redacted = False
        for item in payload.get("entities", []):
            if not isinstance(item, Mapping):
                continue
            roles = [str(value) for value in item.get("roles", [])]
            handle = item.get("handle")
            public_name = None
            vcard = item.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                for field in vcard[1]:
                    if isinstance(field, list) and len(field) >= 4 and field[0] in {"fn", "org"}:
                        public_name = field[3] if isinstance(field[3], str) else None
            if not public_name and any("redact" in str(value).casefold() for value in item.values()):
                redacted = True
            entities.append({"handle": handle, "roles": roles, "public_name": public_name})
        notices = [{"title": item.get("title"), "description": item.get("description")}
                   for item in payload.get("notices", []) if isinstance(item, Mapping)]
        links = [str(item.get("href")) for item in payload.get("links", [])
                 if isinstance(item, Mapping) and str(item.get("href", "")).startswith("https://")]
        registrar = next((item.get("public_name") for item in entities
                          if "registrar" in item.get("roles", []) and item.get("public_name")), None)
        return {
            "registrar": registrar, "events": events, "nameservers": nameservers,
            "statuses": [str(item) for item in payload.get("status", [])], "entities": entities,
            "registrant_disclosure": "UNKNOWN" if redacted or not entities else "PUBLIC_FIELDS_ONLY",
            "notices": notices, "links": links,
        }

    @staticmethod
    def _unknown(domain: str, reason: str) -> RawObservation:
        return RawObservation(raw_status="UNKNOWN", value_reference=f"domain:{domain}",
                              notes="RDAP lookup was inconclusive.",
                              payload={"source_id": "registry_rdap", "failure_status": "UNKNOWN",
                                       "error_reason": reason})

    @staticmethod
    def _domain(value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("domain input must be non-empty")
        raw = value.strip().rstrip(".")
        if any(marker in raw for marker in ("://", "/", "\\", ":", "*")) or any(ch.isspace() for ch in raw):
            raise ValueError("domain input must be a hostname")
        try:
            domain = raw.encode("idna").decode("ascii").casefold()
        except UnicodeError as error:
            raise ValueError("domain input is not valid IDNA") from error
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            raise ValueError("domain input must not be an IP address")
        labels = domain.split(".")
        if len(labels) < 2 or len(domain) > 253 or any(
            not 1 <= len(label) <= 63 or _LABEL.fullmatch(label) is None
            or label.startswith("-") or label.endswith("-") for label in labels
        ):
            raise ValueError("domain input contains an invalid hostname label")
        return domain
