"""Controlled construction of the production collector registry."""

import dns
import phonenumbers
import requests

from .domain_dns import DomainDNSCollector
from .email_exposure import EmailExposureCollector, EmailLocalMetadataCollector
from .phone_metadata import PhoneMetadataCollector
from .phone_public_web import PhonePublicWebCollector
from .registry import CollectorRegistry, metadata_for
from .username_lookup import UsernameCollector


def build_default_registry() -> CollectorRegistry:
    """Build a fresh registry containing reviewed production collectors."""

    registry = CollectorRegistry()
    collectors = (
        (PhoneMetadataCollector(), False, f"phonenumbers:{phonenumbers.__version__}"),
        (PhonePublicWebCollector(), True, f"requests:{requests.__version__}"),
        (DomainDNSCollector(), True, f"dnspython:{dns.__version__}"),
        (UsernameCollector(), True, f"requests:{requests.__version__}"),
        (EmailLocalMetadataCollector(), False, "python-stdlib:idna"),
        (EmailExposureCollector(), True, f"requests:{requests.__version__}"),
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
