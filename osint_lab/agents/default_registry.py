"""Controlled construction of the production collector registry."""

import dns
import phonenumbers

from .domain_dns import DomainDNSCollector
from .phone_metadata import PhoneMetadataCollector
from .registry import CollectorRegistry, metadata_for


def build_default_registry() -> CollectorRegistry:
    """Build a fresh registry containing reviewed production collectors."""

    registry = CollectorRegistry()
    collectors = (
        (PhoneMetadataCollector(), False, f"phonenumbers:{phonenumbers.__version__}"),
        (DomainDNSCollector(), True, f"dnspython:{dns.__version__}"),
    )
    for collector, network_required, provenance in collectors:
        registry.register(
            collector,
            metadata_for(
                collector,
                network_required=network_required,
                provenance=provenance,
            ),
        )
    return registry
