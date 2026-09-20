"""Conservative exact entity normalization; fuzzy values are never merged."""

from dataclasses import dataclass
import re
from urllib.parse import urlsplit

import phonenumbers

from osint_lab.agents.email_exposure import normalize_email
from osint_lab.agents.target_page_fetcher import canonicalize_url

from .models import GraphEntityType


@dataclass(frozen=True)
class NormalizedEntity:
    canonical_value: str
    display_value: str
    comparison_value: str


class EntityNormalizer:
    def normalize(self, entity_type: GraphEntityType, value: str) -> NormalizedEntity:
        if not isinstance(entity_type, GraphEntityType):
            raise ValueError("GraphEntityType required")
        if not isinstance(value, str) or not value.strip():
            raise ValueError("entity value must be non-empty")
        display = value.strip()
        if entity_type is GraphEntityType.PHONE:
            parsed = phonenumbers.parse(display, "PL")
            if not phonenumbers.is_possible_number(parsed):
                raise ValueError("phone is not possible")
            canonical = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            return NormalizedEntity(canonical, display, canonical)
        if entity_type is GraphEntityType.EMAIL:
            _, local_part, domain = normalize_email(display)
            canonical = f"{local_part.casefold()}@{domain.casefold()}"
            return NormalizedEntity(canonical, display, canonical)
        if entity_type is GraphEntityType.DOMAIN:
            host = display.rstrip(".").casefold().encode("idna").decode("ascii")
            if not host or "." not in host or any(not label for label in host.split(".")):
                raise ValueError("invalid domain")
            return NormalizedEntity(host, display, host)
        if entity_type in {GraphEntityType.WEBSITE, GraphEntityType.SOCIAL_PROFILE, GraphEntityType.DOCUMENT}:
            value_with_scheme = display if urlsplit(display).scheme else f"https://{display}"
            canonical = canonicalize_url(value_with_scheme)
            return NormalizedEntity(canonical, display, canonical.casefold())
        if entity_type is GraphEntityType.USERNAME:
            comparison = display.removeprefix("@").casefold()
            if not comparison:
                raise ValueError("username is empty")
            return NormalizedEntity(comparison, display, comparison)
        if entity_type in {GraphEntityType.COMPANY, GraphEntityType.ORGANIZATION, GraphEntityType.NAME}:
            light = re.sub(r"\s+", " ", display).strip()
            return NormalizedEntity(light, display, light.casefold())
        canonical = re.sub(r"\s+", " ", display).strip()
        return NormalizedEntity(canonical, display, canonical.casefold())
