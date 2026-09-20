"""Collector adapters and guarded entity-to-enricher routing."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
from typing import Callable, Mapping

from osint_lab.agents import Collector
from osint_lab.case_manifest import CaseManifest
from osint_lab.orchestrator.service import Orchestrator
from osint_lab.policies import SourceClass
from osint_lab.policies.gate import PolicyDecision, PolicyGate
from osint_lab.sources.runtime import PrivateSourceCache, RateLimiter, RequestBudget

from .models import CaseEvent, CaseEventType, EntityNode, GraphEntityType, GraphStatus, PivotBudget
from .normalization import EntityNormalizer
from .store import GraphStore, deterministic_entity_id


class CostClass(str, Enum):
    LOCAL_LOW = "LOCAL_LOW"
    NETWORK_LOW = "NETWORK_LOW"
    NETWORK_MEDIUM = "NETWORK_MEDIUM"


@dataclass(frozen=True, kw_only=True)
class EnricherDefinition:
    enricher_id: str
    supported_entity_types: tuple[GraphEntityType, ...]
    output_entity_types: tuple[GraphEntityType, ...]
    source_class: SourceClass
    network_required: bool
    cost_class: CostClass
    privacy_cost: float
    expected_information_gain: float
    version: str
    enabled: bool
    prerequisites: tuple[str, ...] = ()
    source_id: str | None = None

    def __post_init__(self) -> None:
        if not self.enricher_id or not self.version:
            raise ValueError("enricher_id and version are required")
        if not self.supported_entity_types:
            raise ValueError("supported_entity_types are required")
        for value in (self.privacy_cost, self.expected_information_gain):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
                raise ValueError("enricher scores must be between 0 and 1")
        if self.network_required != (self.source_class is not SourceClass.LOCAL):
            raise ValueError("network_required must match source class")

    def to_dict(self) -> dict[str, object]:
        return {"enricher_id": self.enricher_id,
                "supported_entity_types": [item.value for item in self.supported_entity_types],
                "output_entity_types": [item.value for item in self.output_entity_types],
                "source_class": self.source_class.value, "network_required": self.network_required,
                "cost_class": self.cost_class.value, "privacy_cost": self.privacy_cost,
                "expected_information_gain": self.expected_information_gain, "version": self.version,
                "enabled": self.enabled, "prerequisites": list(self.prerequisites),
                "source_id": self.source_id}


class EnricherRegistry:
    def __init__(self) -> None:
        self._definitions: dict[str, EnricherDefinition] = {}

    def register(self, definition: EnricherDefinition) -> None:
        if not isinstance(definition, EnricherDefinition):
            raise ValueError("EnricherDefinition required")
        if definition.enricher_id in self._definitions:
            raise ValueError("duplicate enricher_id")
        self._definitions[definition.enricher_id] = definition

    def get(self, enricher_id: str) -> EnricherDefinition:
        try:
            return self._definitions[enricher_id]
        except KeyError:
            raise KeyError("unknown enricher") from None

    def for_entity(self, entity_type: GraphEntityType) -> tuple[EnricherDefinition, ...]:
        return tuple(sorted(
            (item for item in self._definitions.values()
             if item.enabled and entity_type in item.supported_entity_types),
            key=lambda item: item.enricher_id,
        ))

    @property
    def definitions(self) -> tuple[EnricherDefinition, ...]:
        return tuple(self._definitions[key] for key in sorted(self._definitions))


def build_default_enricher_registry() -> EnricherRegistry:
    registry = EnricherRegistry()
    values = (
        ("phone_metadata", (GraphEntityType.PHONE,), (GraphEntityType.PHONE,), SourceClass.LOCAL,
         CostClass.LOCAL_LOW, 0.05, 0.35, "1.0.0", None),
        ("phone_public_web", (GraphEntityType.PHONE,),
         (GraphEntityType.WEBSITE, GraphEntityType.EMAIL, GraphEntityType.DOMAIN, GraphEntityType.COMPANY),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_MEDIUM, 0.55, 0.8, "1.1.0", "duckduckgo_html"),
        ("email_local_metadata", (GraphEntityType.EMAIL,), (GraphEntityType.DOMAIN,), SourceClass.LOCAL,
         CostClass.LOCAL_LOW, 0.05, 0.55, "1.0.0", None),
        ("email_exposure", (GraphEntityType.EMAIL,), (GraphEntityType.EMAIL, GraphEntityType.WEBSITE),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_MEDIUM, 0.6, 0.65, "1.0.0", "gravatar_public_profile"),
        ("email_public_web", (GraphEntityType.EMAIL,),
         (GraphEntityType.EMAIL, GraphEntityType.WEBSITE, GraphEntityType.DOMAIN, GraphEntityType.COMPANY),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_MEDIUM, 0.7, 0.8, "1.0.0", "first_party_web"),
        ("username_lookup", (GraphEntityType.USERNAME,), (GraphEntityType.SOCIAL_PROFILE,),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_MEDIUM, 0.5, 0.65, "1.0.0", "github_public_profile"),
        ("domain_dns", (GraphEntityType.DOMAIN,), (GraphEntityType.IP, GraphEntityType.DOMAIN),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_LOW, 0.25, 0.7, "1.0.0", "public_dns"),
        ("domain_rdap", (GraphEntityType.DOMAIN,), (GraphEntityType.DOMAIN, GraphEntityType.COMPANY),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_LOW, 0.3, 0.75, "1.0.0", "registry_rdap"),
        ("website_metadata", (GraphEntityType.DOMAIN, GraphEntityType.WEBSITE),
         (GraphEntityType.WEBSITE, GraphEntityType.DOMAIN, GraphEntityType.EMAIL,
          GraphEntityType.PHONE, GraphEntityType.COMPANY),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_LOW, 0.35, 0.82, "1.0.0", "first_party_web"),
        ("company_public_web", (GraphEntityType.COMPANY, GraphEntityType.ORGANIZATION),
         (GraphEntityType.COMPANY, GraphEntityType.WEBSITE, GraphEntityType.DOMAIN,
          GraphEntityType.EMAIL, GraphEntityType.PHONE),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_MEDIUM, 0.58, 0.78, "1.0.0", "first_party_web"),
        ("document_intelligence", (GraphEntityType.DOCUMENT, GraphEntityType.WEBSITE),
         (GraphEntityType.DOCUMENT, GraphEntityType.EMAIL, GraphEntityType.PHONE,
          GraphEntityType.DOMAIN, GraphEntityType.COMPANY),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_LOW, 0.4, 0.75, "1.0.0", "first_party_document"),
        ("public_archive", (GraphEntityType.DOMAIN, GraphEntityType.WEBSITE),
         (GraphEntityType.WEBSITE, GraphEntityType.DOCUMENT), SourceClass.PASSIVE_WEB,
         CostClass.NETWORK_LOW, 0.3, 0.5, "1.0.0", "common_crawl_index"),
    )
    for enricher_id, supported, outputs, source, cost, privacy, gain, version, source_id in values:
        registry.register(EnricherDefinition(
            enricher_id=enricher_id, supported_entity_types=supported, output_entity_types=outputs,
            source_class=source, network_required=source is not SourceClass.LOCAL, cost_class=cost,
            privacy_cost=privacy, expected_information_gain=gain, version=version, enabled=True,
            source_id=source_id,
        ))
    return registry


class EnrichmentBus:
    """Routes entities and delegates every execution to the existing Orchestrator."""

    _NETWORK_REQUEST_RESERVATION = {
        "phone_public_web": 10,
        "email_exposure": 4,
        "username_lookup": 8,
        "domain_dns": 8,
        "email_public_web": 6,
        "domain_rdap": 2,
        "website_metadata": 1,
        "company_public_web": 5,
        "document_intelligence": 1,
        "public_archive": 2,
    }
    _REQUEST_HOSTS = {
        "phone_public_web": "https://html.duckduckgo.com/",
        "email_exposure": "https://api.gravatar.com/",
        "email_public_web": "https://html.duckduckgo.com/",
        "username_lookup": "https://github.com/",
        "domain_dns": "https://dns.invalid/",
        "domain_rdap": "https://data.iana.org/",
        "company_public_web": "https://html.duckduckgo.com/",
        "public_archive": "https://index.commoncrawl.org/",
    }

    def __init__(
        self,
        *,
        registry: EnricherRegistry,
        orchestrator: Orchestrator,
        collectors: Mapping[str, Collector],
        clock: Callable[[], datetime],
        budget: PivotBudget | None = None,
        source_registry=None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        if not isinstance(registry, EnricherRegistry) or not isinstance(orchestrator, Orchestrator):
            raise ValueError("registry and Orchestrator are required")
        self.registry = registry
        self._orchestrator = orchestrator
        self._collectors = dict(collectors)
        self._clock = clock
        self.budget = budget or PivotBudget()
        self.source_registry = source_registry
        self.rate_limiter = rate_limiter or RateLimiter(RequestBudget(
            max_case_requests=self.budget.max_network_requests,
            max_provider_requests=self.budget.max_network_requests,
            max_host_requests=self.budget.max_network_requests,
        ))
        self._network_requests: dict[str, int] = {}
        self._enrichments: dict[tuple[str, str], int] = {}
        self._validate_mappings()

    def _validate_mappings(self) -> None:
        registered_sources = (
            {item.source_id: item for item in self.source_registry.definitions}
            if self.source_registry is not None else {}
        )
        for definition in self.registry.definitions:
            collector = self._collectors.get(definition.enricher_id)
            if collector is not None and (
                collector.agent_name != definition.enricher_id
                or collector.version != definition.version
                or collector.source_class is not definition.source_class
                or collector.network_required != definition.network_required
            ):
                raise ValueError(f"collector/enricher metadata mismatch: {definition.enricher_id}")
            if not definition.enabled or definition.source_id is None or self.source_registry is None:
                continue
            source = registered_sources.get(definition.source_id)
            if source is None:
                raise ValueError(f"SOURCE_MAPPING_ERROR: {definition.enricher_id}")
            if source.source_class is not definition.source_class:
                raise ValueError(f"source class mismatch: {definition.enricher_id}")

    def eligible(self, *, manifest: CaseManifest, entity: EntityNode) -> tuple[EnricherDefinition, ...]:
        values = []
        for definition in self.registry.for_entity(entity.entity_type):
            collector = self._collectors.get(definition.enricher_id)
            if collector is None:
                continue
            policy = PolicyGate.decide(
                manifest, agent_type=collector.agent_type, source_class=definition.source_class,
            )
            if policy.decision is not PolicyDecision.DENY:
                values.append(definition)
        return tuple(values)

    def execute(
        self,
        *,
        manifest: CaseManifest,
        entity: EntityNode,
        enricher_id: str,
        graph_store: GraphStore,
        hop: int,
        authorization_id: str | None = None,
        automatic: bool = True,
    ):
        definition = self.registry.get(enricher_id)
        if entity.entity_type not in definition.supported_entity_types or not definition.enabled:
            raise ValueError("entity is not supported by enricher")
        if self.source_registry is not None and definition.source_id is not None:
            source = self.source_registry.get(definition.source_id)
            if not source.enabled:
                raise PermissionError("source review registry disabled this source")
            if automatic and (not source.terms_reviewed or not source.automation_allowed):
                raise PermissionError("source is not reviewed for automatic execution")
        collector = self._collectors.get(enricher_id)
        if collector is None:
            raise ValueError("collector adapter is unavailable")
        policy = PolicyGate.decide(manifest, agent_type=collector.agent_type, source_class=definition.source_class)
        if policy.decision is PolicyDecision.DENY:
            raise PermissionError("PolicyGate blocked enrichment")
        if hop > self.budget.max_hops:
            raise RuntimeError("pivot max hops exhausted")
        if automatic and definition.privacy_cost > self.budget.max_privacy_cost:
            raise PermissionError("pivot requires manual execution because privacy cost exceeds threshold")
        counts = graph_store.snapshot()
        if len(counts["nodes"]) >= self.budget.max_entities or len(counts["edges"]) >= self.budget.max_relations:
            raise RuntimeError("graph entity/relation budget exhausted")
        key = (manifest.case_id, entity.entity_id)
        current = self._enrichments.get(key, 0)
        if current >= self.budget.max_enrichments_per_entity:
            raise RuntimeError("per-entity enrichment budget exhausted")
        if definition.network_required:
            network = self._network_requests.get(manifest.case_id, 0)
            reserved_requests = self._NETWORK_REQUEST_RESERVATION.get(enricher_id, 1)
            if network + reserved_requests > self.budget.max_network_requests:
                raise RuntimeError("network request budget exhausted")
            request_url = self._REQUEST_HOSTS.get(enricher_id)
            if request_url is None:
                if entity.entity_type is GraphEntityType.WEBSITE:
                    request_url = entity.canonical_value
                elif entity.entity_type is GraphEntityType.DOMAIN:
                    request_url = "https://" + entity.canonical_value + "/"
                else:
                    request_url = f"https://{enricher_id}.source.invalid/"
            self.rate_limiter.reserve(
                case_id=manifest.case_id, provider_id=definition.source_id or enricher_id,
                url=request_url, count=reserved_requests,
            )
        fingerprint = self.execution_fingerprint(manifest.case_id, entity, enricher_id)
        if graph_store.has_pivot(fingerprint):
            raise RuntimeError("duplicate enrichment suppressed")
        result = self._orchestrator.execute(
            manifest=manifest, collector=collector, seed_reference=entity.canonical_value,
            purpose=f"EnrichmentBus graph pivot hop {hop}: {enricher_id}", requested_by="enrichment-bus",
            authorization_id=authorization_id,
        )
        if result.status.value != "DENIED":
            cache = PrivateSourceCache(
                repo_root=graph_store.repo_root,
                case_root=graph_store.case_root / manifest.case_id,
            )
            cache.put(
                provider_id=definition.source_id or enricher_id,
                provider_version=definition.version,
                request_identity=f"{enricher_id}|{entity.canonical_value}",
                timestamp=self._clock(),
                payload={
                    "execution_id": result.execution_id,
                    "result_status": result.status.value,
                    "observations": [
                        {"raw_status": item.raw_status, "value_reference": item.value_reference,
                         "evidence_ref": item.evidence_ref, "payload": dict(item.payload)}
                        for item in result.observations
                    ],
                    "stale_warning": "Cache timestamp must be evaluated before reuse as current evidence.",
                },
            )
            if not graph_store.record_pivot(
                fingerprint=fingerprint, entity_id=entity.entity_id, enricher_id=enricher_id,
                status="PIVOT_EXECUTED", hop=hop, timestamp=self._clock(),
            ):
                raise RuntimeError("duplicate enrichment suppressed")
            graph_store.add_batch(events=(CaseEvent(
                event_id="evt-" + hashlib.sha256(f"auto|{fingerprint}".encode()).hexdigest()[:24],
                case_id=manifest.case_id, event_type=CaseEventType.AUTO_PIVOT_RECORDED,
                timestamp=self._clock(), subject_id=fingerprint,
                evidence_refs=(), attributes={"enricher": enricher_id, "hop": hop,
                                               "execution_mode": "AUTO" if automatic else "MANUAL_REQUIRED"},
            ),))
            self._enrichments[key] = current + 1
            if definition.network_required:
                self._network_requests[manifest.case_id] = (
                    self._network_requests.get(manifest.case_id, 0) + reserved_requests
                )
        return result

    def execute_seed(
        self,
        *,
        manifest: CaseManifest,
        entity_type: str,
        seed_reference: str,
        enricher_id: str,
        graph_store: GraphStore,
        hop: int = 0,
        authorization_id: str | None = None,
        automatic: bool = True,
    ):
        graph_type = GraphEntityType(entity_type.upper())
        normalized = EntityNormalizer().normalize(graph_type, seed_reference)
        timestamp = self._clock()
        seed_hash = hashlib.sha256(
            f"{manifest.case_id}|{graph_type.value}|{normalized.canonical_value}".encode()
        ).hexdigest()
        entity = EntityNode(
            entity_id=deterministic_entity_id(manifest.case_id, graph_type, normalized.canonical_value),
            case_id=manifest.case_id, entity_type=graph_type, canonical_value=normalized.canonical_value,
            display_value=normalized.display_value, aliases=(normalized.display_value,), first_seen=timestamp,
            last_seen=timestamp, created_at=timestamp, updated_at=timestamp,
            source_refs=(f"manifest:{manifest.case_id}",), evidence_refs=(f"seed:{seed_hash}",),
            confidence=1.0, status=GraphStatus.POSSIBLE, attributes={"seed": True, "hop": hop},
        )
        return self.execute(manifest=manifest, entity=entity, enricher_id=enricher_id,
                            graph_store=graph_store, hop=hop, authorization_id=authorization_id,
                            automatic=automatic)

    @staticmethod
    def execution_fingerprint(case_id: str, entity: EntityNode, enricher_id: str) -> str:
        token = f"{case_id}|{entity.entity_id}|{enricher_id}|{entity.canonical_value}"
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def source_mapping(self, enricher_id: str) -> tuple[str, str | None]:
        definition = self.registry.get(enricher_id)
        return definition.source_id or enricher_id, definition.source_id

    def request_reservation(self, enricher_id: str) -> int:
        definition = self.registry.get(enricher_id)
        return self._NETWORK_REQUEST_RESERVATION.get(enricher_id, 1) if definition.network_required else 0

    def network_requests_reserved(self, case_id: str) -> int:
        return self._network_requests.get(case_id, 0)
