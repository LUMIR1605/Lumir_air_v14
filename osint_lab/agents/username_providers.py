"""Explicit provider definitions for conservative public username checks."""

from dataclasses import dataclass
import re


_COMMON_ERROR_SIGNALS = (
    "captcha",
    "cf-chl-",
    "cloudflare",
    "just a moment...",
    "too many requests",
    "rate limit",
)


@dataclass(frozen=True, kw_only=True)
class UsernameProvider:
    provider_id: str
    name: str
    profile_url_template: str
    method: str
    claimed_signals: tuple[str, ...]
    available_signals: tuple[str, ...]
    error_signals: tuple[str, ...]
    allowed_status_codes: tuple[int, ...]
    timeout: float
    enabled: bool
    notes: str
    username_pattern: str
    available_status_codes: tuple[int, ...] = ()
    home_url: str = ""

    def __post_init__(self) -> None:
        for name in (
            "provider_id", "name", "profile_url_template", "method", "notes", "username_pattern"
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if self.method != "GET":
            raise ValueError("username providers support public GET only")
        if "{username}" not in self.profile_url_template:
            raise ValueError("profile_url_template must contain {username}")
        for name in ("claimed_signals", "available_signals", "error_signals"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or any(not isinstance(item, str) or not item for item in values):
                raise ValueError(f"{name} must be a tuple of non-empty strings")
        for name in ("allowed_status_codes", "available_status_codes"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or any(
                isinstance(item, bool) or not isinstance(item, int) or not 100 <= item <= 599
                for item in values
            ):
                raise ValueError(f"{name} must contain valid HTTP status codes")
        if isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float)) or self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if not isinstance(self.enabled, bool):
            raise ValueError("enabled must be a bool")
        try:
            re.compile(self.username_pattern)
        except re.error as error:
            raise ValueError("username_pattern must be a valid regular expression") from error

    def accepts(self, username: str) -> bool:
        return re.fullmatch(self.username_pattern, username) is not None


DEFAULT_USERNAME_PROVIDERS = (
    UsernameProvider(
        provider_id="github",
        name="GitHub",
        profile_url_template="https://github.com/{username}",
        method="GET",
        claimed_signals=(
            'itemprop="additionalName"',
            'data-testid="profile-avatar"',
        ),
        available_signals=("Page not found · GitHub",),
        error_signals=_COMMON_ERROR_SIGNALS,
        allowed_status_codes=(200, 403, 404, 429, 503),
        available_status_codes=(404,),
        timeout=8.0,
        enabled=True,
        notes="HTTP 200 requires a profile-specific marker; verified 404 means unavailable.",
        username_pattern=r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
        home_url="https://github.com/",
    ),
    UsernameProvider(
        provider_id="gitlab",
        name="GitLab",
        profile_url_template="https://gitlab.com/{username}",
        method="GET",
        claimed_signals=(
            'data-page="profiles:show"',
            'class="user-profile"',
        ),
        available_signals=("The page could not be found or you don't have permission",),
        error_signals=_COMMON_ERROR_SIGNALS,
        allowed_status_codes=(200, 403, 404, 429, 503),
        available_status_codes=(404,),
        timeout=8.0,
        enabled=True,
        notes="HTTP 200 requires a profile-specific marker; verified 404 means unavailable.",
        username_pattern=r"[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63}",
        home_url="https://gitlab.com/",
    ),
)
