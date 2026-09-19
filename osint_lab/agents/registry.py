"""Central collector registry with declaration and implementation checks."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from osint_lab.policies import SourceClass

from .base import Collector


def implementation_identifier(collector: Collector) -> str:
    collector_type = type(collector)
    return f"{collector_type.__module__}:{collector_type.__qualname__}"


@dataclass(frozen=True, kw_only=True)
class CollectorMetadata:
    agent_name: str
    agent_type: str
    version: str
    source_class: SourceClass
    capabilities: Mapping[str, object]
    network_required: bool
    provenance: str
    implementation_identifier: str

    def __post_init__(self) -> None:
        for name in ("agent_name", "agent_type", "version", "provenance", "implementation_identifier"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if not isinstance(self.source_class, SourceClass):
            raise ValueError("source_class must be a SourceClass")
        if not isinstance(self.capabilities, Mapping):
            raise ValueError("capabilities must be a mapping")
        copied = dict(self.capabilities)
        if any(not isinstance(key, str) or not key.strip() for key in copied):
            raise ValueError("capability names must be non-empty strings")
        if not isinstance(self.network_required, bool):
            raise ValueError("network_required must be a bool")
        if copied.get("network") is not self.network_required:
            raise ValueError("network_required must match the network capability")
        object.__setattr__(self, "capabilities", MappingProxyType(copied))


@dataclass(frozen=True)
class _Registration:
    collector_type: type[Collector]
    metadata: CollectorMetadata


class CollectorRegistry:
    """Allow execution only for exactly registered collector implementations."""

    def __init__(self) -> None:
        self._registrations: dict[str, _Registration] = {}

    def register(self, collector: Collector, metadata: CollectorMetadata) -> None:
        if not isinstance(collector, Collector):
            raise ValueError("Collector required")
        if not isinstance(metadata, CollectorMetadata):
            raise ValueError("CollectorMetadata required")
        if metadata.agent_name in self._registrations:
            raise ValueError("duplicate collector agent_name")
        self._validate_declaration(collector, metadata)
        self._registrations[metadata.agent_name] = _Registration(type(collector), metadata)

    def validate(self, collector: Collector) -> CollectorMetadata:
        if not isinstance(collector, Collector):
            raise ValueError("Collector required")
        registration = self._registrations.get(collector.agent_name)
        if registration is None:
            raise PermissionError("collector is not registered")
        if type(collector) is not registration.collector_type:
            raise PermissionError("registered collector implementation was substituted")
        try:
            self._validate_declaration(collector, registration.metadata)
        except ValueError as error:
            raise PermissionError("collector metadata no longer matches registry") from error
        return registration.metadata

    @staticmethod
    def _validate_declaration(collector: Collector, metadata: CollectorMetadata) -> None:
        declared = {
            "agent_name": collector.agent_name,
            "agent_type": collector.agent_type,
            "version": collector.version,
            "source_class": collector.source_class,
            "capabilities": dict(collector.describe_capabilities()),
            "implementation_identifier": implementation_identifier(collector),
        }
        expected = {
            "agent_name": metadata.agent_name,
            "agent_type": metadata.agent_type,
            "version": metadata.version,
            "source_class": metadata.source_class,
            "capabilities": dict(metadata.capabilities),
            "implementation_identifier": metadata.implementation_identifier,
        }
        if declared != expected:
            raise ValueError("collector declaration does not match registry metadata")


def metadata_for(
    collector: Collector,
    *,
    network_required: bool,
    provenance: str,
) -> CollectorMetadata:
    if not isinstance(collector, Collector):
        raise ValueError("Collector required")
    return CollectorMetadata(
        agent_name=collector.agent_name,
        agent_type=collector.agent_type,
        version=collector.version,
        source_class=collector.source_class,
        capabilities=collector.describe_capabilities(),
        network_required=network_required,
        provenance=provenance,
        implementation_identifier=implementation_identifier(collector),
    )
