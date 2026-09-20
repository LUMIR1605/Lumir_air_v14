"""Semantic validation for public phone-number occurrences."""

from dataclasses import dataclass
from enum import Enum
import json
import re
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup

from .phone_public_parsers import ParsedPhonePublicResult
from .phone_variants import PhoneVariant


class PhoneMatchLevel(str, Enum):
    SEARCH_DISCOVERY_ONLY = "SEARCH_DISCOVERY_ONLY"
    NUMERIC_MATCH = "NUMERIC_MATCH"
    NUMERIC_MATCH_ONLY = "NUMERIC_MATCH_ONLY"
    PHONE_CONTEXT_MATCH = "PHONE_CONTEXT_MATCH"
    STRUCTURED_PHONE_MATCH = "STRUCTURED_PHONE_MATCH"
    REJECTED_NUMERIC_ID = "REJECTED_NUMERIC_ID"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, kw_only=True)
class SemanticPhoneMatch:
    level: PhoneMatchLevel
    matched_variant: PhoneVariant | None
    match_location: str | None
    reason: str
    context_before: str | None = None
    matched_text: str | None = None
    context_after: str | None = None
    signal_type: str | None = None
    signal_path: str | None = None
    normalized_phone: str | None = None
    raw_visible_value: str | None = None

    @property
    def accepted(self) -> bool:
        return self.level in {
            PhoneMatchLevel.PHONE_CONTEXT_MATCH,
            PhoneMatchLevel.STRUCTURED_PHONE_MATCH,
        }


_PHONE_CONTEXT = re.compile(
    r"(?i)(?<!\w)(?:tel(?:efon|ephone)?|phone|mobile|kom\.?|kontakt|contact|zadzwoń|call|numer\s+telefonu)(?!\w)"
)
_NEGATIVE_ID_CONTEXT = re.compile(
    r"(?i)(?<!\w)(?:image|photo|product|sku|post|article|media|asset|timestamp|tracking|pagination|page|listing|document)"
    r"(?:\s*[-_:/#]?\s*(?:id|number|nr))?(?!\w)|(?<!\w)(?:id|sku)\s*[:#=-]"
)
_PHONE_CANDIDATE = re.compile(r"(?<!\d)\+?\d(?:[\s().-]*\d){7,14}(?!\d)")
_VCARD_TEL = re.compile(r"(?im)(?:^|[>\n\r])\s*TEL(?:;[^:]*)?:\s*([^<\n\r]+)")
_REJECTED_URL_REASON = (
    "Digits matched the phone seed but occur as a resource/image identifier, not as a telephone reference."
)


class TargetPhoneValidator:
    """Validate that a fetched target uses the seed as a telephone reference."""

    def validate(
        self,
        result: ParsedPhonePublicResult,
        variants: tuple[PhoneVariant, ...],
    ) -> SemanticPhoneMatch:
        if not isinstance(result, ParsedPhonePublicResult):
            raise ValueError("ParsedPhonePublicResult required")
        if not variants or any(not isinstance(item, PhoneVariant) for item in variants):
            raise ValueError("phone variants required")
        return classify_phone_occurrence(result, variants)


def classify_phone_occurrence(
    result: ParsedPhonePublicResult,
    variants: tuple[PhoneVariant, ...],
) -> SemanticPhoneMatch:
    """Separate numeric equality from evidence that the value is used as a phone number."""

    accepted_digits = _accepted_digits(variants)
    structured = _structured_match(result.page_html, variants, accepted_digits)
    if structured is not None:
        return structured

    first_numeric: tuple[PhoneVariant, str, str, str, str] | None = None
    first_negative: tuple[PhoneVariant, str, str, str, str] | None = None
    for location, text in (("snippet", result.snippet), ("body", result.visible_text)):
        for matched, span, raw_value in _numeric_occurrences(text, variants, accepted_digits):
            before = text[max(0, span[0] - 48):span[0]]
            after = text[span[1]:min(len(text), span[1] + 48)]
            context = f"{before} {after}"
            if _NEGATIVE_ID_CONTEXT.search(context):
                first_negative = first_negative or (matched, location, before, raw_value, after)
                continue
            if _PHONE_CONTEXT.search(context):
                return SemanticPhoneMatch(
                    level=PhoneMatchLevel.PHONE_CONTEXT_MATCH,
                    matched_variant=matched,
                    match_location=location,
                    reason="The normalized phone value appears in visible text with explicit telephone context.",
                    context_before=before.strip(),
                    matched_text=raw_value,
                    context_after=after.strip(),
                    signal_type="VISIBLE_PHONE_CONTEXT",
                    signal_path=location,
                    normalized_phone=matched.canonical_e164,
                    raw_visible_value=raw_value,
                )
            first_numeric = first_numeric or (matched, location, before, raw_value, after)

    url_match = _url_numeric_match(result.result_url, variants, accepted_digits)
    if url_match is not None:
        return SemanticPhoneMatch(
            level=PhoneMatchLevel.REJECTED_NUMERIC_ID,
            matched_variant=url_match,
            match_location="url",
            reason=_REJECTED_URL_REASON,
            signal_type="URL_NUMERIC_IDENTIFIER",
            signal_path="url",
            normalized_phone=url_match.canonical_e164,
            raw_visible_value=url_match.variant,
        )
    if first_negative is not None:
        matched, location, before, raw_value, after = first_negative
        return SemanticPhoneMatch(
            level=PhoneMatchLevel.REJECTED_NUMERIC_ID,
            matched_variant=matched,
            match_location=location,
            reason="Digits matched the phone seed in numeric identifier context, not telephone context.",
            context_before=before.strip(),
            matched_text=raw_value,
            context_after=after.strip(),
            signal_type="VISIBLE_NUMERIC_IDENTIFIER",
            signal_path=location,
            normalized_phone=matched.canonical_e164,
            raw_visible_value=raw_value,
        )
    if first_numeric is not None:
        matched, location, before, raw_value, after = first_numeric
        return SemanticPhoneMatch(
            level=PhoneMatchLevel.NUMERIC_MATCH_ONLY,
            matched_variant=matched,
            match_location=location,
            reason="The same digits are visible, but no telephone context or structured telephone field confirms their meaning.",
            context_before=before.strip(),
            matched_text=raw_value,
            context_after=after.strip(),
            signal_type="VISIBLE_NUMERIC_ONLY",
            signal_path=location,
            normalized_phone=matched.canonical_e164,
            raw_visible_value=raw_value,
        )
    return SemanticPhoneMatch(
        level=PhoneMatchLevel.UNKNOWN,
        matched_variant=None,
        match_location=None,
        reason="No normalized phone occurrence was found in visible or structured telephone content.",
    )


def _structured_match(
    page_html: str,
    variants: tuple[PhoneVariant, ...],
    accepted_digits: set[str],
) -> SemanticPhoneMatch | None:
    soup = BeautifulSoup(page_html, "html.parser")
    for node in soup.select('[href^="tel:" i]'):
        value = str(node.get("href", ""))[4:].split("?", 1)[0]
        matched = _variant_for_value(value, variants, accepted_digits)
        if matched is not None:
            return _structured_result(
                matched, "TEL_LINK", "structured:tel_href", value,
                "A tel: link contains the normalized phone value.",
            )
    for node in soup.select(
        '[itemprop="telephone" i], [property="telephone" i], '
        'meta[name="phone" i], meta[name="telephone" i]'
    ):
        value = str(node.get("content") or node.get_text(" ", strip=True))
        matched = _variant_for_value(value, variants, accepted_digits)
        if matched is not None:
            return _structured_result(
                matched, "SCHEMA_TELEPHONE", "structured:schema_telephone", value,
                "A structured telephone property contains the normalized phone value.",
            )
    for script in soup.select('script[type="application/ld+json"]'):
        try:
            payload = json.loads(script.string or "")
        except (TypeError, json.JSONDecodeError):
            continue
        for value in _telephone_values(payload):
            matched = _variant_for_value(value, variants, accepted_digits)
            if matched is not None:
                return _structured_result(
                    matched, "JSON_LD_TELEPHONE", "structured:json_ld_telephone", value,
                    "A JSON-LD telephone field contains the normalized phone value.",
                )
    for value in _VCARD_TEL.findall(page_html):
        matched = _variant_for_value(value, variants, accepted_digits)
        if matched is not None:
            return _structured_result(
                matched, "VCARD_TEL", "structured:vcard_tel", value,
                "A vCard TEL field contains the phone value.",
            )
    return None


def _telephone_values(value: object):
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).casefold() == "telephone" and isinstance(item, (str, int)):
                yield str(item)
            else:
                yield from _telephone_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _telephone_values(item)


def _structured_result(
    matched: PhoneVariant,
    signal_type: str,
    location: str,
    raw_value: str,
    reason: str,
) -> SemanticPhoneMatch:
    return SemanticPhoneMatch(
        level=PhoneMatchLevel.STRUCTURED_PHONE_MATCH,
        matched_variant=matched,
        match_location=location,
        reason=reason,
        matched_text=raw_value,
        signal_type=signal_type,
        signal_path=location,
        normalized_phone=matched.canonical_e164,
        raw_visible_value=raw_value,
    )


def _accepted_digits(variants: tuple[PhoneVariant, ...]) -> set[str]:
    return {_normalize_digits(item.variant) for item in variants}


def _numeric_occurrences(
    text: str,
    variants: tuple[PhoneVariant, ...],
    accepted_digits: set[str],
):
    for match in _PHONE_CANDIDATE.finditer(text):
        variant = _variant_for_value(match.group(0), variants, accepted_digits)
        if variant is not None:
            yield variant, match.span(), match.group(0)


def _url_numeric_match(
    result_url: str,
    variants: tuple[PhoneVariant, ...],
    accepted_digits: set[str],
) -> PhoneVariant | None:
    parsed = urlsplit(result_url)
    searchable = unquote(" ".join((parsed.path, parsed.query, parsed.fragment)))
    return next((item for item, _, _ in _numeric_occurrences(searchable, variants, accepted_digits)), None)


def _variant_for_value(
    value: str,
    variants: tuple[PhoneVariant, ...],
    accepted_digits: set[str],
) -> PhoneVariant | None:
    digits = _normalize_digits(value)
    if digits not in accepted_digits:
        return None
    return min(
        variants,
        key=lambda item: (_normalize_digits(item.variant) != digits, abs(len(item.variant) - len(value))),
    )


def _normalize_digits(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return digits[2:] if digits.startswith("00") else digits
