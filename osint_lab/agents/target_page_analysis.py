"""Deterministic target-page role and content fingerprint analysis."""

from enum import Enum
import hashlib
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from .phone_public_parsers import ParsedPhonePublicResult


class PageRole(str, Enum):
    CONTACT_PAGE = "CONTACT_PAGE"
    COMPANY_PAGE = "COMPANY_PAGE"
    DIRECTORY = "DIRECTORY"
    ADVERTISEMENT = "ADVERTISEMENT"
    MARKETPLACE = "MARKETPLACE"
    SOCIAL_PROFILE = "SOCIAL_PROFILE"
    DOCUMENT_PAGE = "DOCUMENT_PAGE"
    ARTICLE = "ARTICLE"
    UNKNOWN = "UNKNOWN"


_SOCIAL_HOSTS = {
    "facebook.com", "www.facebook.com", "instagram.com", "www.instagram.com",
    "linkedin.com", "www.linkedin.com", "x.com", "twitter.com",
}
_DOCUMENT_SUFFIXES = {".pdf", ".doc", ".docx", ".odt", ".xls", ".xlsx", ".csv", ".txt"}


def classify_page_role(result: ParsedPhonePublicResult) -> PageRole:
    parsed = urlsplit(result.result_url)
    host = (parsed.hostname or "").casefold()
    path = parsed.path.casefold()
    title = (result.page_title or "").casefold()
    text = result.visible_text[:4000].casefold()
    soup = BeautifulSoup(result.page_html, "html.parser")
    schema_types = {
        str(node.get("itemtype", "")).casefold() for node in soup.select("[itemtype]")
    }
    suffix = PurePosixPath(parsed.path).suffix.casefold()
    if suffix in _DOCUMENT_SUFFIXES:
        return PageRole.DOCUMENT_PAGE
    if host in _SOCIAL_HOSTS or any(host.endswith(f".{item}") for item in _SOCIAL_HOSTS):
        return PageRole.SOCIAL_PROFILE
    if re.search(r"(?:^|/)(?:contact|kontakt|contact-us|o-nas/kontakt)(?:/|$)", path):
        return PageRole.CONTACT_PAGE
    if any(value in title for value in ("contact", "kontakt")):
        return PageRole.CONTACT_PAGE
    if any(value in path or value in title for value in ("classified", "ogloszen", "advert", "listing")):
        return PageRole.ADVERTISEMENT
    if any(value in path or value in title for value in ("marketplace", "produkt", "product", "shop", "sklep")):
        return PageRole.MARKETPLACE
    if any(value in path or value in title for value in ("directory", "katalog", "phonebook", "firmy")):
        return PageRole.DIRECTORY
    if soup.find("article") is not None or any("article" in item for item in schema_types):
        return PageRole.ARTICLE
    if any(
        marker in result.page_html.casefold()
        for marker in ('"@type":"organization"', '"@type": "organization"', '"@type":"localbusiness"')
    ) or "company" in text[:500]:
        return PageRole.COMPANY_PAGE
    return PageRole.UNKNOWN


def normalized_visible_text_hash(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value).strip().casefold()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
