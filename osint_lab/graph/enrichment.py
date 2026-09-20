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

from .models import EntityNode, GraphEntityType, GraphStatus, PivotBudget
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
                "enabled": self.enabled, "prerequisites": list(self.prerequisites)}


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
         CostClass.LOCAL_LOW, 0.05, 0.35, "1.0.0"),
        ("phone_public_web", (GraphEntityType.PHONE,),
         (GraphEntityType.WEBSITE, GraphEntityType.EMAIL, GraphEntityType.DOMAIN, GraphEntityType.COMPANY),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_MEDIUM, 0.55, 0.8, "1.1.0"),
        ("email_local_metadata", (GraphEntityType.EMAIL,), (GraphEntityType.DOMAIN,), SourceClass.LOCAL,
         CostClass.LOCAL_LOW, 0.05, 0.55, "1.0.0"),
        ("email_exposure", (GraphEntityType.EMAIL,), (GraphEntityType.EMAIL, GraphEntityType.WEBSITE),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_MEDIUM, 0.6, 0.65, "1.0.0"),
        ("username_lookup", (GraphEntityType.USERNAME,), (GraphEntityType.SOCIAL_PROFILE,),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_MEDIUM, 0.5, 0.65, "1.0.0"),
        ("domain_dns", (GraphEntityType.DOMAIN,), (GraphEntityType.IP, GraphEntityType.DOMAIN),
         SourceClass.PASSIVE_WEB, CostClass.NETWORK_LOW, 0.25, 0.7, "1.0.0"),
    )
    for enricher_id, supported, outputs, source, cost, privacy, gain, version in values:
        registry.register(EnricherDefinition(
            enricher_id=enricher_id, supported_entity_types=supported, output_entity_types=outputs,
            source_class=source, network_required=source is not SourceClass.LOCAL, cost_class=cost,
            privacy_cost=privacy, expected_information_gain=gain, version=version, enabled=True,
        ))
    return registry


class EnrichmentBus:
    """Routes entities and delegates every execution to the existing Orchestrator."""

    _NETWORK_REQUEST_RESERVATION = {
        "phone_public_web": 16,
        "email_exposure": 4,
        "username_lookup": 8,
        "domain_dns": 8,
    }

    def __init__(
        self,
        *,
        registry: EnricherRegistry,
        orchestrator: Orchestrator,
        collectors: Mapping[str, Collector],
        clock: Callable[[], datetime],
        budget: PivotBudget | None = None,
    ) -> None:
        if not isinstance(registry, EnricherRegistry) or not isinstance(orchestrator, Orchestrator):
            raise ValueError("registry and Orchestrator are required")
        self.registry = registry
        self._orchestrator = orchestrator
        self._collectors = dict(collectors)
        self._clock = clock
        self.budget = budget or PivotBudget()
        self._network_requests: dict[str, int] = {}
        self._enrichments: dict[tuple[str, str], int] = {}

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
    ):
        definition = self.registry.get(enricher_id)
        if entity.entity_type not in definition.supported_entity_types or not definition.enabled:
            raise ValueError("entity is not supported by enricher")
        collector = self._collectors.get(enricher_id)
        if collector is None:
            raise ValueError("collector adapter is unavailable")
        policy = PolicyGate.decide(manifest, agent_type=collector.agent_type, source_class=definition.source_class)
        if policy.decision is PolicyDecision.DENY:
            raise PermissionError("PolicyGate blocked enrichment")
        if hop > self.budget.max_hops:
            raise RuntimeError("pivot max hops exhausted")
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
        fingerprint = self.execution_fingerprint(manifest.case_id, entity, enricher_id)
        if graph_store.has_pivot(fingerprint):
            raise RuntimeError("duplicate enrichment suppressed")
        result = self._orchestrator.execute(
            manifest=manifest, collector=collector, seed_reference=entity.canonical_value,
            purpose=f"EnrichmentBus graph pivot hop {hop}: {enricher_id}", requested_by="enrichment-bus",
            authorization_id=authorization_id,
        )
        if result.status.value != "DENIED":
            if not graph_store.record_pivot(
                fingerprint=fingerprint, entity_id=entity.entity_id, enricher_id=enricher_id,
                status="PIVOT_EXECUTED", hop=hop, timestamp=self._clock(),
            ):
                raise RuntimeError("duplicate enrichment suppressed")
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
                            graph_store=graph_store, hop=hop, authorization_id=authorization_id)

    @staticmethod
    def execution_fingerprint(case_id: str, entity: EntityNode, enricher_id: str) -> str:
        token = f"{case_id}|{entity.entity_id}|{enricher_id}|{entity.canonical_value}"
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
