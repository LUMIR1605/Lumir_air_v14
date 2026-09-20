"""Strict parsers shared by reviewed public source adapters."""

from html.parser import HTMLParser
import json
import re
from urllib.parse import parse_qs, unquote, urljoin, urlsplit


EMAIL_PATTERN = re.compile(r"(?<![\w.+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63})(?![\w.-])", re.I)
PHONE_PATTERN = re.compile(r"(?<!\d)(?:\+?48[\s().-]*)?(?:\d[\s().-]*){9}(?!\d)")
DOMAIN_PATTERN = re.compile(r"(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w-])", re.I)
DATE_PATTERN = re.compile(r"\b(?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])\b")


class PublicHtmlParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self.mailto: list[str] = []
        self.meta: dict[str, str] = {}
        self.canonical: str | None = None
        self.language: str | None = None
        self.json_ld: list[dict[str, object]] = []
        self._in_title = False
        self._json_ld = False
        self._script_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        values = {str(key).casefold(): str(value) for key, value in attrs if value is not None}
        tag = tag.casefold()
        if tag == "html":
            self.language = values.get("lang") or self.language
        if tag == "title":
            self._in_title = True
        if tag == "meta":
            key = (values.get("name") or values.get("property") or "").casefold()
            if key and values.get("content"):
                self.meta[key] = values["content"]
        if tag == "link" and values.get("rel", "").casefold() == "canonical" and values.get("href"):
            self.canonical = urljoin(self.base_url, values["href"])
        if tag == "a" and values.get("href"):
            href = values["href"]
            if href.casefold().startswith("mailto:"):
                self.mailto.append(unquote(href[7:].split("?", 1)[0]))
            elif href.casefold().startswith(("http://", "https://", "/")):
                self.links.append(urljoin(self.base_url, href))
        if tag == "script" and values.get("type", "").casefold() == "application/ld+json":
            self._json_ld = True
            self._script_parts = []

    def handle_endtag(self, tag):
        tag = tag.casefold()
        if tag == "title":
            self._in_title = False
        if tag == "script" and self._json_ld:
            self._json_ld = False
            try:
                payload = json.loads("".join(self._script_parts))
            except (TypeError, json.JSONDecodeError):
                return
            values = payload if isinstance(payload, list) else [payload]
            self.json_ld.extend(item for item in values if isinstance(item, dict))

    def handle_data(self, data):
        text = data.strip()
        if self._json_ld:
            self._script_parts.append(data)
        elif text:
            self.text_parts.append(text)
            if self._in_title:
                self.title_parts.append(text)

    @property
    def title(self) -> str | None:
        return " ".join(self.title_parts).strip() or None

    @property
    def visible_text(self) -> str:
        return " ".join(self.text_parts)

    def organizations(self) -> tuple[dict[str, object], ...]:
        values = []
        for node in self.json_ld:
            types = node.get("@type", ())
            type_values = {types} if isinstance(types, str) else set(types) if isinstance(types, list) else set()
            if type_values & {"Organization", "Corporation", "LocalBusiness"}:
                values.append({key: node.get(key) for key in ("name", "url", "email", "telephone")})
        return tuple(values)


class SearchResultParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.casefold() != "a":
            return
        values = {str(key).casefold(): str(value) for key, value in attrs if value is not None}
        classes = set(values.get("class", "").split())
        href = values.get("href", "")
        if "result__a" not in classes or not href:
            return
        if href.startswith("//"):
            query = parse_qs(urlsplit("https:" + href).query)
            href = query.get("uddg", [href])[0]
        if urlsplit(href).scheme in {"http", "https"}:
            self.urls.append(href)


def parse_html(body: str, base_url: str) -> PublicHtmlParser:
    parser = PublicHtmlParser(base_url)
    parser.feed(body)
    return parser


def parse_search_urls(body: str, limit: int) -> tuple[str, ...]:
    parser = SearchResultParser()
    parser.feed(body)
    return tuple(dict.fromkeys(parser.urls))[:limit]
