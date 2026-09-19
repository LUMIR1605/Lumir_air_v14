"""Controlled PASSIVE_WEB DNS record collector using dnspython."""

import ipaddress
import re
from typing import Mapping

import dns.exception
import dns.resolver

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus

from .base import Collector, FindingCandidate, RawObservation


_LABEL = re.compile(r"^[a-z0-9-]+$")
_DIRECT_QUERY_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


class DomainDNSCollector(Collector):
    """Collect current DNS records without HTTP, subprocesses, or inference."""

    agent_name = "domain_dns"
    agent_type = "DOMAIN"
    version = "1.0.0"
    source_class = SourceClass.PASSIVE_WEB
    network_required = True

    def __init__(self, *, resolver=None, resolver_label: str | None = None) -> None:
        super().__init__()
        if resolver is None:
            resolver = dns.resolver.Resolver(configure=True)
            resolver.timeout = 2.0
            resolver.lifetime = 5.0
        if not hasattr(resolver, "resolve"):
            raise ValueError("resolver must provide resolve()")
        self._resolver = resolver
        self._resolver_label = resolver_label or self._describe_resolver(resolver)

    def validate_input(self, seed_reference: str) -> None:
        self._normalize_domain(seed_reference)

    def _run(
        self,
        context: ExecutionContext,
        seed_reference: str,
    ) -> tuple[RawObservation, ...]:
        domain = self._normalize_domain(seed_reference)
        outcomes = {
            query_type: self._resolve(domain, query_type)
            for query_type in _DIRECT_QUERY_TYPES
        }
        observations = [
            self._observation(domain, query_type, domain, outcomes[query_type])
            for query_type in _DIRECT_QUERY_TYPES
        ]
        observations.append(self._spf_observation(domain, outcomes["TXT"]))
        observations.append(self._dmarc_observation(domain))
        return tuple(observations)

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        if not isinstance(observation, RawObservation):
            raise ValueError("RawObservation required")
        status = observation.payload.get("status")
        if status == "FOUND":
            normalized_status = FindingStatus.POSSIBLE
        elif status == "NOT_FOUND":
            normalized_status = FindingStatus.NOT_FOUND
        else:
            normalized_status = FindingStatus.UNKNOWN
        query_type = str(observation.payload.get("query_type", "UNKNOWN"))
        return FindingCandidate(
            raw_status=f"DOMAIN_{query_type}_RECORD_{status}",
            normalized_status=normalized_status,
            value_reference=observation.value_reference,
            evidence_ref=observation.evidence_ref,
            notes="Technical DNS record fact only; no ownership or identity inference.",
        )

    def describe_capabilities(self) -> Mapping[str, object]:
        return {
            "network": True,
            "record_types": ["A", "AAAA", "MX", "NS", "TXT", "SPF", "DMARC"],
            "http": False,
            "subprocess": False,
            "ownership_inference": False,
        }

    def _resolve(self, query_name: str, query_type: str) -> dict[str, object]:
        try:
            answer = self._resolver.resolve(
                query_name,
                query_type,
                search=False,
                raise_on_no_answer=True,
            )
            records = [self._record_text(item, query_type) for item in answer]
            if not records:
                return self._outcome("NOT_FOUND", records=[])
            ttl = getattr(getattr(answer, "rrset", None), "ttl", None)
            return self._outcome("FOUND", records=records, ttl=ttl)
        except dns.resolver.NXDOMAIN:
            return self._outcome(
                "NXDOMAIN",
                error_code="NXDOMAIN",
                error_reason="The queried DNS name does not exist.",
            )
        except dns.resolver.NoAnswer:
            return self._outcome(
                "NOT_FOUND",
                error_code="NO_ANSWER",
                error_reason="The DNS response contained no answer for this record type.",
            )
        except dns.exception.Timeout:
            return self._outcome(
                "UNKNOWN",
                error_code="TIMEOUT",
                error_reason="The DNS query timed out.",
            )
        except dns.resolver.NoNameservers:
            return self._outcome(
                "UNKNOWN",
                error_code="NO_NAMESERVERS",
                error_reason="No configured nameserver returned a usable answer.",
            )
        except dns.exception.DNSException as error:
            return self._outcome(
                "ERROR",
                error_code=type(error).__name__.upper(),
                error_reason="The resolver raised a DNS protocol error.",
            )
        except Exception as error:
            return self._outcome(
                "ERROR",
                error_code=type(error).__name__.upper(),
                error_reason="The resolver raised an unexpected technical error.",
            )

    def _spf_observation(
        self,
        domain: str,
        txt_outcome: Mapping[str, object],
    ) -> RawObservation:
        outcome = dict(txt_outcome)
        if outcome["status"] == "FOUND":
            records = [
                record
                for record in outcome["records"]
                if isinstance(record, str) and record.casefold().startswith("v=spf1")
            ]
            outcome.update({
                "status": "FOUND" if records else "NOT_FOUND",
                "records": records,
                "error_code": None if records else "NO_SPF_RECORD",
                "error_reason": None if records else "TXT answer contained no SPF record.",
            })
        return self._observation(domain, "SPF", domain, outcome)

    def _dmarc_observation(self, domain: str) -> RawObservation:
        query_name = f"_dmarc.{domain}"
        outcome = self._resolve(query_name, "TXT")
        dmarc_records: list[dict[str, object]] = []
        if outcome["status"] == "FOUND":
            for record in outcome["records"]:
                if isinstance(record, str) and record.casefold().startswith("v=dmarc1"):
                    tags = self._tag_values(record)
                    dmarc_records.append({
                        "raw": record,
                        "p": tags.get("p"),
                        "sp": tags.get("sp"),
                        "pct": tags.get("pct"),
                        "rua": tags.get("rua"),
                        "ruf": tags.get("ruf"),
                    })
            outcome.update({
                "status": "FOUND" if dmarc_records else "NOT_FOUND",
                "records": [item["raw"] for item in dmarc_records],
                "error_code": None if dmarc_records else "NO_DMARC_RECORD",
                "error_reason": None if dmarc_records else "TXT answer contained no DMARC record.",
            })
        observation = self._observation(domain, "DMARC", query_name, outcome)
        payload = dict(observation.payload)
        payload["dmarc_records"] = dmarc_records
        return RawObservation(
            raw_status=observation.raw_status,
            value_reference=observation.value_reference,
            notes=observation.notes,
            payload=payload,
        )

    def _observation(
        self,
        domain: str,
        query_type: str,
        query_name: str,
        outcome: Mapping[str, object],
    ) -> RawObservation:
        payload = {
            "domain": domain,
            "query_name": query_name,
            "query_type": query_type,
            "status": outcome["status"],
            "records": list(outcome["records"]),
            "ttl": outcome["ttl"],
            "resolver": self._resolver_label,
            "error_code": outcome["error_code"],
            "error_reason": outcome["error_reason"],
        }
        return RawObservation(
            raw_status=str(outcome["status"]),
            value_reference=f"dns:{domain}:{query_type}",
            notes="Current DNS evidence only; no HTTP request or ownership inference.",
            payload=payload,
        )

    @staticmethod
    def _outcome(
        status: str,
        *,
        records: list[str] | None = None,
        ttl: int | None = None,
        error_code: str | None = None,
        error_reason: str | None = None,
    ) -> dict[str, object]:
        return {
            "status": status,
            "records": records or [],
            "ttl": ttl,
            "error_code": error_code,
            "error_reason": error_reason,
        }

    @staticmethod
    def _record_text(record, query_type: str) -> str:
        if query_type in {"A", "AAAA"} and hasattr(record, "address"):
            return str(record.address)
        if query_type == "MX" and hasattr(record, "exchange"):
            exchange = record.exchange.to_text().rstrip(".")
            return f"{record.preference} {exchange}"
        if query_type == "NS" and hasattr(record, "target"):
            return record.target.to_text().rstrip(".")
        if query_type == "TXT" and hasattr(record, "strings"):
            return b"".join(record.strings).decode("utf-8", errors="replace")
        return record.to_text().rstrip(".")

    @staticmethod
    def _tag_values(record: str) -> dict[str, str]:
        values: dict[str, str] = {}
        for part in record.split(";"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip().casefold()
            if key:
                values[key] = value.strip()
        return values

    @staticmethod
    def _normalize_domain(seed_reference: str) -> str:
        if not isinstance(seed_reference, str) or not seed_reference.strip():
            raise ValueError("domain input must be non-empty")
        raw = seed_reference.strip()
        if any(marker in raw for marker in ("://", "/", "\\", ":", "*")):
            raise ValueError("domain input must not contain a URL, path, port, or wildcard")
        if any(character.isspace() for character in raw):
            raise ValueError("domain input must not contain internal whitespace")
        if raw.endswith("."):
            raw = raw[:-1]
        if not raw or raw.endswith("."):
            raise ValueError("domain input has an invalid trailing dot")
        try:
            domain = raw.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("domain input is not valid IDNA") from error
        if len(domain) > 253 or "." not in domain:
            raise ValueError("domain input must be a multi-label hostname")
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            raise ValueError("domain input must not be an IP address")
        for label in domain.split("."):
            if (
                not 1 <= len(label) <= 63
                or _LABEL.fullmatch(label) is None
                or label.startswith("-")
                or label.endswith("-")
            ):
                raise ValueError("domain input contains an invalid hostname label")
        return domain

    @staticmethod
    def _describe_resolver(resolver) -> str:
        nameservers = getattr(resolver, "nameservers", ())
        rendered = ",".join(str(item) for item in nameservers)
        return f"configured:{rendered}" if rendered else "configured:system"
