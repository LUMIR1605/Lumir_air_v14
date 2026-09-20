"""Provider-independent parsers selected by reviewed provider metadata."""

from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

from bs4 import BeautifulSoup


@dataclass(frozen=True, kw_only=True)
class ParsedPhonePublicResult:
    result_url: str
    page_title: str | None
    snippet: str
    visible_text: str
    source_date: str | None
    html_fragment: str
    page_html: str


def parse_phone_public_results(
    parser_id: str,
    *,
    body: str,
    final_url: str,
) -> tuple[ParsedPhonePublicResult, ...]:
    if parser_id == "html_search_results_v1":
        return _parse_search_results(body, final_url)
    if parser_id == "body_exact_phone_v1":
        return _parse_body_result(body, final_url)
    raise ValueError("unknown phone public result parser")


def _parse_search_results(body: str, final_url: str) -> tuple[ParsedPhonePublicResult, ...]:
    soup = BeautifulSoup(body, "html.parser")
    nodes = soup.select(".result, article[data-result]")
    values: list[ParsedPhonePublicResult] = []
    seen_nodes: set[int] = set()
    for node in nodes:
        if id(node) in seen_nodes:
            continue
        seen_nodes.add(id(node))
        anchor = node.select_one("a.result__a[href], a[href]")
        if anchor is None:
            continue
        result_url = _unwrap_result_url(urljoin(final_url, str(anchor.get("href", ""))))
        if urlsplit(result_url).scheme not in {"http", "https"}:
            continue
        snippet_node = node.select_one(".result__snippet, [data-snippet], p")
        snippet = snippet_node.get_text(" ", strip=True) if snippet_node else ""
        time_node = node.find("time")
        source_date = None
        if time_node is not None:
            source_date = str(time_node.get("datetime") or time_node.get_text(" ", strip=True)).strip() or None
        values.append(ParsedPhonePublicResult(
            result_url=result_url,
            page_title=anchor.get_text(" ", strip=True) or None,
            snippet=snippet,
            visible_text=node.get_text(" ", strip=True),
            source_date=source_date,
            html_fragment=str(node),
            page_html=str(node),
        ))
    return _dedupe(values)


def _parse_body_result(body: str, final_url: str) -> tuple[ParsedPhonePublicResult, ...]:
    soup = BeautifulSoup(body, "html.parser")
    for item in soup(["script", "style", "noscript", "template"]):
        item.extract()
    visible = soup.get_text(" ", strip=True)
    time_node = soup.find("time")
    source_date = None
    if time_node is not None:
        source_date = str(time_node.get("datetime") or time_node.get_text(" ", strip=True)).strip() or None
    return (ParsedPhonePublicResult(
        result_url=final_url,
        page_title=soup.title.get_text(" ", strip=True) if soup.title else None,
        snippet=visible[:500],
        visible_text=visible,
        source_date=source_date,
        html_fragment=body,
        page_html=body,
    ),)


def _dedupe(values: list[ParsedPhonePublicResult]) -> tuple[ParsedPhonePublicResult, ...]:
    seen: set[str] = set()
    output: list[ParsedPhonePublicResult] = []
    for item in values:
        normalized = item.result_url.casefold().rstrip("/")
        if normalized in seen:
            continue
        seen.add(normalized)
        output.append(item)
    return tuple(output)


def _unwrap_result_url(value: str) -> str:
    parsed = urlsplit(value)
    wrapped = parse_qs(parsed.query).get("uddg")
    if wrapped:
        candidate = unquote(wrapped[0])
        if urlsplit(candidate).scheme in {"http", "https"}:
            return candidate
    return value
