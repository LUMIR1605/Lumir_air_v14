"""Controlled construction of the production collector registry."""

import phonenumbers

from .phone_metadata import PhoneMetadataCollector
from .registry import CollectorRegistry, metadata_for


def build_default_registry() -> CollectorRegistry:
    """Build a fresh registry containing reviewed production collectors."""

    registry = CollectorRegistry()
    collector = PhoneMetadataCollector()
    registry.register(
        collector,
        metadata_for(
            collector,
            network_required=False,
            provenance=f"phonenumbers:{phonenumbers.__version__}",
        ),
    )
    return registry
