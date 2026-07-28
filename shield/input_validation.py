"""Validation and normalization for self-service Lumir SHIELD scans."""

from __future__ import annotations

import re
from dataclasses import dataclass

import phonenumbers


EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}$")
SUPPORTED_TYPES = {"email", "phone", "username"}


class InputValidationError(ValueError):
    """A user-facing validation failure with a safe Polish explanation."""


@dataclass(frozen=True)
class NormalizedInput:
    scan_type: str
    value: str


def _email(value: str) -> str:
    if not EMAIL_PATTERN.fullmatch(value):
        raise InputValidationError("Podaj pełny adres e-mail, np. imie@domena.pl.")
    local, domain = value.rsplit("@", 1)
    try:
        normalized_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise InputValidationError("Domena w adresie e-mail ma nieprawidłowy format.") from error
    return f"{local}@{normalized_domain}"


def _phone(value: str) -> str:
    compact = re.sub(r"[\s().-]", "", value)
    if compact.startswith("00"):
        compact = "+" + compact[2:]
    try:
        parsed = phonenumbers.parse(compact, "PL")
    except phonenumbers.NumberParseException as error:
        raise InputValidationError("Podaj prawidłowy numer telefonu, np. +48 123 456 789.") from error
    if not phonenumbers.is_possible_number(parsed):
        raise InputValidationError("Ten numer telefonu ma nieprawidłową długość lub format.")
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)


def _username(value: str) -> str:
    normalized = value[1:] if value.startswith("@") else value
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise InputValidationError("Nick może mieć 1–39 znaków: litery, cyfry, kropkę, myślnik lub podkreślenie.")
    return normalized


def normalize(value: str, requested_type: str = "auto") -> NormalizedInput:
    """Return a safe canonical value for one of the three supported self-scans."""
    raw = value.strip()
    if not raw:
        raise InputValidationError("Wpisz adres e-mail, numer telefonu albo nick.")
    if any(ord(char) < 32 for char in raw):
        raise InputValidationError("Dane wejściowe zawierają niedozwolone znaki.")

    selected = requested_type.lower().strip()
    if selected not in SUPPORTED_TYPES | {"auto"}:
        raise InputValidationError("Wybierz: e-mail, telefon albo nick.")
    if selected == "auto":
        if "@" in raw and not raw.startswith("@"):
            selected = "email"
        elif raw.startswith("+") or re.fullmatch(r"[0-9\s().-]+", raw):
            selected = "phone"
        else:
            selected = "username"
    return NormalizedInput(scan_type=selected, value={"email": _email, "phone": _phone, "username": _username}[selected](raw))
