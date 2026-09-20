"""Versioned registry of reviewed public sources."""

import hashlib
import json

from osint_lab.graph.models import GraphEntityType as E
from osint_lab.policies import SourceClass

from .models import (
    ImplementationStatus as I,
    ReliabilityClass as Q,
    SourceCategory as C,
    SourceDefinition,
    SourceRole as R,
    make_source_definition,
)


SOURCE_REGISTRY_VERSION = "2026-09-20-v1"


class SourceRegistry:
    def __init__(self, *, version: str = SOURCE_REGISTRY_VERSION) -> None:
        if not version:
            raise ValueError("registry version is required")
        self.version = version
        self._values: dict[str, SourceDefinition] = {}

    def register(self, definition: SourceDefinition) -> None:
        if not isinstance(definition, SourceDefinition):
            raise ValueError("SourceDefinition required")
        if definition.source_id in self._values:
            raise ValueError("duplicate source_id")
        self._values[definition.source_id] = definition

    def get(self, source_id: str) -> SourceDefinition:
        try:
            return self._values[source_id]
        except KeyError:
            raise KeyError("unknown source") from None

    def for_entity(self, entity_type: E, *, enabled_only: bool = False) -> tuple[SourceDefinition, ...]:
        values = (item for item in self._values.values() if entity_type in item.supported_entity_types)
        if enabled_only:
            values = (item for item in values if item.enabled)
        return tuple(sorted(values, key=lambda item: item.source_id))

    @property
    def definitions(self) -> tuple[SourceDefinition, ...]:
        return tuple(self._values[key] for key in sorted(self._values))

    @property
    def config_hash(self) -> str:
        payload = [item.to_dict() for item in self.definitions]
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _definition(source_id, name, category, roles, supported, outputs, source_class, access_method,
                base_url, reliability, gain, *, enabled=True, automation=True, reviewed=True,
                auth=False, key=False, paid=False, status=I.IMPLEMENTED, parser="1.0.0",
                terms_url="https://example.invalid/review-required", privacy="Provider receives the query and source IP.",
                rate="Bounded locally; provider responses may impose stricter limits."):
    return make_source_definition(
        source_id=source_id, name=name, category=category, roles=roles,
        supported_entity_types=supported, output_entity_types=outputs, source_class=source_class,
        access_method=access_method, base_url=base_url, authentication_required=auth,
        api_key_required=key, paid=paid, automation_allowed=automation, terms_reviewed=reviewed,
        terms_review_url=terms_url, privacy_notes=privacy, reliability_class=reliability,
        expected_information_gain=gain, rate_limit_notes=rate, enabled=enabled,
        reviewed_at="2026-09-20", implementation_status=status, parser_version=parser,
    )


def build_default_source_registry() -> SourceRegistry:
    registry = SourceRegistry()
    definitions = (
        _definition("first_party_web", "First-party public web", C.FIRST_PARTY_WEB,
                    (R.EVIDENCE, R.VERIFICATION), (E.PHONE, E.EMAIL, E.DOMAIN, E.WEBSITE, E.COMPANY),
                    (E.PHONE, E.EMAIL, E.DOMAIN, E.WEBSITE, E.COMPANY, E.DOCUMENT),
                    SourceClass.PASSIVE_WEB, "HTTPS GET", "https://{authorized-public-host}/", Q.FIRST_PARTY, 0.9,
                    terms_url="https://www.rfc-editor.org/rfc/rfc9110.html",
                    privacy="The requested public host receives the target URL, source IP and user agent."),
        _definition("public_dns", "Public DNS", C.PUBLIC_DNS, (R.ENRICHMENT, R.VERIFICATION),
                    (E.DOMAIN,), (E.DOMAIN, E.IP), SourceClass.PASSIVE_WEB, "DNS",
                    "dns://system-resolver", Q.TECHNICAL_INFRASTRUCTURE, 0.75,
                    terms_url="https://www.rfc-editor.org/rfc/rfc1035.html",
                    privacy="Configured DNS resolvers receive the queried domain."),
        _definition("iana_rdap_bootstrap", "IANA RDAP bootstrap", C.PUBLIC_DOMAIN_DATA,
                    (R.DISCOVERY,), (E.DOMAIN,), (E.DOMAIN,), SourceClass.PASSIVE_WEB, "HTTPS JSON",
                    "https://data.iana.org/rdap/dns.json", Q.OFFICIAL_PUBLIC_REGISTRY, 0.4,
                    terms_url="https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml",
                    privacy="IANA receives a bootstrap registry request; the target domain is not sent."),
        _definition("registry_rdap", "Authoritative registry RDAP", C.PUBLIC_DOMAIN_DATA,
                    (R.ENRICHMENT, R.VERIFICATION), (E.DOMAIN,), (E.DOMAIN, E.COMPANY),
                    SourceClass.PASSIVE_WEB, "RDAP HTTPS JSON", "iana-bootstrap://domain",
                    Q.OFFICIAL_PUBLIC_REGISTRY, 0.85,
                    terms_url="https://www.icann.org/rdap/",
                    privacy="The authoritative RDAP service receives the queried domain and source IP.",
                    rate="At most one bootstrap and one RDAP lookup per uncached domain."),
        _definition("github_public_profile", "GitHub public profile", C.PUBLIC_CODE_HOSTING,
                    (R.ENRICHMENT,), (E.USERNAME,), (E.SOCIAL_PROFILE, E.WEBSITE),
                    SourceClass.PASSIVE_WEB, "Public HTTPS GET", "https://github.com/",
                    Q.PUBLIC_PLATFORM, 0.65, terms_url="https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api",
                    rate="Unauthenticated public API limit documented as 60 requests/hour per IP."),
        _definition("gitlab_public_profile", "GitLab.com public profile", C.PUBLIC_CODE_HOSTING,
                    (R.ENRICHMENT,), (E.USERNAME,), (E.SOCIAL_PROFILE, E.WEBSITE),
                    SourceClass.PASSIVE_WEB, "Public HTTPS GET", "https://gitlab.com/",
                    Q.PUBLIC_PLATFORM, 0.62, terms_url="https://docs.gitlab.com/user/gitlab_com/rate_limits/",
                    rate="Unauthenticated GitLab.com traffic is locally capped below published limits."),
        _definition("gravatar_public_profile", "Gravatar public profile", C.PUBLIC_PROFILE,
                    (R.ENRICHMENT,), (E.EMAIL,), (E.SOCIAL_PROFILE, E.WEBSITE),
                    SourceClass.PASSIVE_WEB, "Public HTTPS API", "https://api.gravatar.com/v3/profiles/",
                    Q.PUBLIC_PLATFORM, 0.55, terms_url="https://docs.gravatar.com/rest-api/",
                    privacy="Gravatar receives the SHA-256 email identifier and source IP.",
                    rate="Unauthenticated profile requests documented as 100/hour."),
        _definition("duckduckgo_html", "DuckDuckGo HTML discovery", C.SEARCH_ENGINE,
                    (R.DISCOVERY,), (E.PHONE, E.EMAIL, E.COMPANY, E.DOMAIN),
                    (E.WEBSITE, E.DOCUMENT), SourceClass.PASSIVE_WEB, "Public HTML GET",
                    "https://html.duckduckgo.com/html/", Q.AGGREGATOR, 0.55,
                    terms_url="https://duckduckgo.com/terms", rate="Low-volume serial discovery; challenge means UNKNOWN."),
        _definition("common_crawl_index", "Common Crawl URL index", C.PUBLIC_ARCHIVE,
                    (R.DISCOVERY, R.ENRICHMENT), (E.DOMAIN, E.WEBSITE), (E.WEBSITE, E.DOCUMENT),
                    SourceClass.PASSIVE_WEB, "Public CDX index", "https://index.commoncrawl.org/",
                    Q.ARCHIVE, 0.55, terms_url="https://index.commoncrawl.org/",
                    privacy="Common Crawl receives the URL/domain query and source IP.",
                    rate="Exact/host queries only, limit 5, serial; do not overload the public index."),
        _definition("first_party_document", "First-party public document", C.PUBLIC_DOCUMENT_INDEX,
                    (R.EVIDENCE, R.ENRICHMENT), (E.DOCUMENT, E.WEBSITE),
                    (E.PHONE, E.EMAIL, E.DOMAIN, E.COMPANY, E.DOCUMENT),
                    SourceClass.PASSIVE_WEB, "Bounded HTTPS GET", "https://{authorized-public-host}/document",
                    Q.FIRST_PARTY, 0.78, terms_url="https://www.rfc-editor.org/rfc/rfc9110.html",
                    privacy="The document host receives the target URL, source IP and user agent."),
        _definition("certificate_transparency_candidate", "Certificate Transparency candidate", C.PUBLIC_DOMAIN_DATA,
                    (R.DISCOVERY, R.ENRICHMENT), (E.DOMAIN,), (E.DOMAIN,), SourceClass.PASSIVE_WEB,
                    "Unreviewed public interface", "https://crt.sh/", Q.TECHNICAL_INFRASTRUCTURE, 0.6,
                    enabled=False, automation=False, reviewed=False, status=I.DISABLED_TERMS,
                    terms_url="https://crt.sh/", privacy="Disabled; no query is sent."),
        _definition("public_company_registry_candidate", "Public company registry candidate",
                    C.PUBLIC_COMPANY_DATA, (R.EVIDENCE, R.VERIFICATION), (E.COMPANY,),
                    (E.COMPANY, E.DOMAIN, E.PHONE, E.EMAIL), SourceClass.PASSIVE_WEB,
                    "Jurisdiction-specific", "https://example.invalid/company-registry", Q.OFFICIAL_PUBLIC_REGISTRY, 0.85,
                    enabled=False, automation=False, reviewed=False, status=I.PLANNED,
                    privacy="Disabled until a jurisdiction, terms and automation interface are explicitly reviewed."),
        _definition("wayback_cdx_candidate", "Wayback CDX candidate", C.PUBLIC_ARCHIVE,
                    (R.DISCOVERY, R.ENRICHMENT), (E.DOMAIN, E.WEBSITE), (E.WEBSITE, E.DOCUMENT),
                    SourceClass.PASSIVE_WEB, "CDX index", "https://web.archive.org/cdx/search/cdx",
                    Q.ARCHIVE, 0.55, enabled=False, automation=False, reviewed=False,
                    status=I.DISABLED_UNSTABLE, terms_url="https://archive.org/about/terms.php",
                    privacy="Disabled pending explicit automation/availability review."),
        _definition("public_directory_candidate", "Public directory candidate", C.PUBLIC_DIRECTORY,
                    (R.DISCOVERY,), (E.PHONE, E.EMAIL, E.COMPANY), (E.WEBSITE, E.COMPANY),
                    SourceClass.PASSIVE_WEB, "Provider-specific", "https://example.invalid/public-directory",
                    Q.DIRECTORY, 0.4, enabled=False, automation=False, reviewed=False, status=I.PLANNED,
                    privacy="Disabled; no directory has passed source-specific review."),
    )
    for definition in definitions:
        registry.register(definition)
    return registry
