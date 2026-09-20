"""Deterministic, bounded phone-number variants for public exact-match search."""

from dataclasses import dataclass
import re

import phonenumbers
from phonenumbers import PhoneNumberFormat


@dataclass(frozen=True, kw_only=True)
class PhoneVariant:
    canonical_e164: str
    variant: str
    variant_type: str

    def __post_init__(self) -> None:
        for name in ("canonical_e164", "variant", "variant_type"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if not self.canonical_e164.startswith("+") or not self.canonical_e164[1:].isdigit():
            raise ValueError("canonical_e164 must be an E.164-like value")

    def to_dict(self) -> dict[str, str]:
        return {
            "canonical_e164": self.canonical_e164,
            "variant": self.variant,
            "variant_type": self.variant_type,
        }


def parse_phone(seed_reference: str, *, default_region: str = "PL"):
    if not isinstance(seed_reference, str) or not seed_reference.strip():
        raise ValueError("phone input must be non-empty")
    raw = seed_reference.strip()
    if re.fullmatch(r"[+0-9\s()\-]+", raw) is None:
        raise ValueError("phone input contains unsupported characters")
    compact = re.sub(r"[\s()\-]", "", raw)
    if compact.count("+") > 1 or ("+" in compact and not compact.startswith("+")):
        raise ValueError("phone input has an invalid international prefix")
    digits = compact[1:] if compact.startswith("+") else compact
    if not digits.isdigit():
        raise ValueError("phone input must contain digits")
    if compact.startswith("+"):
        value, region = compact, None
    elif digits.startswith("48") and len(digits) > 9:
        value, region = f"+{digits}", None
    else:
        value, region = digits, default_region
    try:
        return phonenumbers.parse(value, region)
    except phonenumbers.NumberParseException as error:
        raise ValueError("phone input could not be parsed") from error


def generate_phone_variants(seed_reference: str, *, default_region: str = "PL") -> tuple[PhoneVariant, ...]:
    """Return useful presentation variants without combinatorial permutations."""

    number = parse_phone(seed_reference, default_region=default_region)
    canonical = phonenumbers.format_number(number, PhoneNumberFormat.E164)
    international = phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL)
    national_digits = re.sub(r"\D", "", national)
    country_code = str(number.country_code)
    candidates = (
        (canonical, "CANONICAL_E164"),
        (national_digits, "NATIONAL_DIGITS"),
        (national, "NATIONAL_SPACED"),
        (re.sub(r"\s+", "-", national), "NATIONAL_HYPHEN"),
        (international, "INTERNATIONAL_SPACED"),
        (f"{country_code} {national}", "COUNTRY_CODE_SPACED"),
    )
    seen: set[str] = set()
    variants: list[PhoneVariant] = []
    for value, variant_type in candidates:
        normalized = " ".join(value.split())
        if normalized in seen:
            continue
        seen.add(normalized)
        variants.append(PhoneVariant(
            canonical_e164=canonical,
            variant=normalized,
            variant_type=variant_type,
        ))
    return tuple(variants)
