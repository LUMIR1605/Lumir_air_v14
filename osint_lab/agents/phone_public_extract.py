"""Conservative extraction from an exact public phone occurrence."""

import json
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from .phone_public_models import DiscoveredEntity, DiscoveredEntityType
from .phone_public_parsers import ParsedPhonePublicResult


_EMAIL = re.compile(r"(?<![\w.+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63})(?![\w.-])", re.IGNORECASE)
_HANDLE = re.compile(r"(?<![\w@.])@([A-Za-z0-9_][A-Za-z0-9_.-]{1,63})")
_DOCUMENT_SUFFIXES = {".pdf", ".doc", ".docx", ".odt", ".xls", ".xlsx", ".csv", ".txt"}


def extract_discovered_entities(
    result: ParsedPhonePublicResult,
    *,
    evidence_ref: str,
) -> tuple[DiscoveredEntity, ...]:
    values: list[DiscoveredEntity] = []
    domain = (urlsplit(result.result_url).hostname or "").casefold()
    values.append(_entity(
        DiscoveredEntityType.WEBSITE,
        result.result_url,
        result.result_url,
        evidence_ref,
        "result_url",
        1.0,
        "Public result URL containing an exact phone occurrence.",
    ))
    if domain:
        values.append(_entity(
            DiscoveredEntityType.DOMAIN,
            domain,
            result.result_url,
            evidence_ref,
            "result_url_hostname",
            1.0,
            "Domain of the public occurrence; no ownership inference.",
        ))
    for email in sorted({item.casefold() for item in _EMAIL.findall(result.visible_text)}):
        values.append(_entity(
            DiscoveredEntityType.EMAIL, email, result.result_url, evidence_ref,
            "visible_text_email", 0.95, "Visible email on the matched public material.",
        ))
    text_without_emails = _EMAIL.sub(" ", result.visible_text)
    for handle in sorted({item for item in _HANDLE.findall(text_without_emails)}):
        values.append(_entity(
            DiscoveredEntityType.USERNAME, handle, result.result_url, evidence_ref,
            "visible_text_handle", 0.85, "Visible handle; identity is not established.",
        ))
    values.extend(_structured_organization_entities(result, evidence_ref))
    suffix = PurePosixPath(urlsplit(result.result_url).path).suffix.casefold()
    if suffix in _DOCUMENT_SUFFIXES:
        filename = PurePosixPath(urlsplit(result.result_url).path).name
        values.append(_entity(
            DiscoveredEntityType.DOCUMENT, filename, result.result_url, evidence_ref,
            f"result_url_extension:{suffix}", 0.95, "Public document filename and type.",
        ))
    deduped: dict[tuple[str, str], DiscoveredEntity] = {}
    for item in values:
        deduped.setdefault((item.entity_type.value, item.value.casefold()), item)
    return tuple(deduped.values())


def _structured_organization_entities(
    result: ParsedPhonePublicResult,
    evidence_ref: str,
) -> list[DiscoveredEntity]:
    soup = BeautifulSoup(result.page_html, "html.parser")
    output: list[DiscoveredEntity] = []
    for script in soup.select('script[type="application/ld+json"]'):
        try:
            payload = json.loads(script.string or "")
        except (TypeError, json.JSONDecodeError):
            continue
        nodes = payload if isinstance(payload, list) else [payload]
        for node in nodes:
            if not isinstance(node, dict) or node.get("@type") not in {"Organization", "LocalBusiness"}:
                continue
            name = node.get("name")
            if isinstance(name, str) and name.strip():
                output.append(_entity(
                    DiscoveredEntityType.COMPANY, name.strip(), result.result_url, evidence_ref,
                    "json_ld_organization_name", 0.9,
                    "Explicit structured organization name; not a phone ownership claim.",
                ))
            address = node.get("address")
            if isinstance(address, dict):
                location = address.get("addressLocality")
                if isinstance(location, str) and location.strip():
                    output.append(_entity(
                        DiscoveredEntityType.LOCATION, location.strip(), result.result_url, evidence_ref,
                        "json_ld_address_locality", 0.85,
                        "Explicit structured location text; not a person's current location.",
                    ))
    return output


def _entity(
    entity_type: DiscoveredEntityType,
    value: str,
    source_url: str,
    evidence_ref: str,
    method: str,
    confidence: float,
    notes: str,
) -> DiscoveredEntity:
    return DiscoveredEntity(
        entity_type=entity_type,
        value=value,
        source_url=source_url,
        evidence_ref=evidence_ref,
        extraction_method=method,
        confidence=confidence,
        notes=notes,
    )
