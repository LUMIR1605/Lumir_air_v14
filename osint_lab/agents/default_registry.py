"""Controlled construction of the production collector registry."""

import dns
import phonenumbers
import requests
from osint_lab.sources import build_default_discovery_engine

from .domain_dns import DomainDNSCollector
from .email_exposure import EmailExposureCollector, EmailLocalMetadataCollector
from .phone_metadata import PhoneMetadataCollector
from .phone_public_web import PhonePublicWebCollector
from .registry import CollectorRegistry, metadata_for
from .username_lookup import UsernameCollector
from .company_public_web import CompanyPublicWebCollector
from .document_intelligence import DocumentIntelligenceCollector
from .domain_rdap import DomainRdapCollector
from .email_public_web import EmailPublicWebCollector
from .public_archive import PublicArchiveCollector
from .website_metadata import WebsiteMetadataCollector


def build_default_registry() -> CollectorRegistry:
    """Build a fresh registry containing reviewed production collectors."""

    registry = CollectorRegistry()
    collectors = (
        (PhoneMetadataCollector(), False, f"phonenumbers:{phonenumbers.__version__}"),
        (PhonePublicWebCollector(discovery_engine=build_default_discovery_engine()),
         True, f"requests:{requests.__version__};brave-search-api;duckduckgo-html"),
        (DomainDNSCollector(), True, f"dnspython:{dns.__version__}"),
        (UsernameCollector(discovery_engine=build_default_discovery_engine()),
         True, f"requests:{requests.__version__};multi-provider-discovery"),
        (EmailLocalMetadataCollector(), False, "python-stdlib:idna"),
        (EmailExposureCollector(), True, f"requests:{requests.__version__}"),
        (EmailPublicWebCollector(discovery_engine=build_default_discovery_engine()),
         True, f"requests:{requests.__version__};multi-provider-discovery"),
        (DomainRdapCollector(), True, f"requests:{requests.__version__}"),
        (WebsiteMetadataCollector(), True, f"requests:{requests.__version__}"),
        (CompanyPublicWebCollector(discovery_engine=build_default_discovery_engine()),
         True, f"requests:{requests.__version__};multi-provider-discovery"),
        (DocumentIntelligenceCollector(), True, f"requests:{requests.__version__};pypdf"),
        (PublicArchiveCollector(), True, f"requests:{requests.__version__}"),
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
