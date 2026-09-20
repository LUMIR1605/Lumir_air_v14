"""Reviewed provider declarations for public phone occurrence search."""

from dataclasses import dataclass

from osint_lab.policies import SourceClass


COMMON_CHALLENGE_SIGNALS = (
    "captcha",
    "cf-chl-",
    "cloudflare",
    "just a moment",
    "too many requests",
    "rate limit",
    "enable javascript",
    "javascript is required",
)


@dataclass(frozen=True, kw_only=True)
class PhonePublicProvider:
    provider_id: str
    name: str
    search_url_template: str
    method: str
    source_class: SourceClass
    exact_match_required: bool
    enabled: bool
    timeout: float
    privacy_notes: str
    result_parser: str
    notes: str
    no_match_signals: tuple[str, ...] = ()
    challenge_signals: tuple[str, ...] = COMMON_CHALLENGE_SIGNALS
    home_url: str = ""

    def __post_init__(self) -> None:
        for name in (
            "provider_id", "name", "search_url_template", "method", "privacy_notes",
            "result_parser", "notes",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if self.method != "GET":
            raise ValueError("phone public providers support public GET only")
        if "{query}" not in self.search_url_template:
            raise ValueError("search_url_template must contain {query}")
        if self.source_class is not SourceClass.PASSIVE_WEB:
            raise ValueError("phone public providers must use PASSIVE_WEB")
        if self.exact_match_required is not True:
            raise ValueError("phone public providers must require exact matches")
        if not isinstance(self.enabled, bool):
            raise ValueError("enabled must be a bool")
        if isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float)) or self.timeout <= 0:
            raise ValueError("timeout must be positive")
        for name in ("no_match_signals", "challenge_signals"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or any(not isinstance(item, str) or not item for item in values):
                raise ValueError(f"{name} must contain non-empty strings")


DEFAULT_PHONE_PUBLIC_PROVIDERS = (
    PhonePublicProvider(
        provider_id="duckduckgo_html",
        name="DuckDuckGo HTML",
        search_url_template="https://html.duckduckgo.com/html/?q={query}",
        method="GET",
        source_class=SourceClass.PASSIVE_WEB,
        exact_match_required=True,
        enabled=True,
        timeout=8.0,
        privacy_notes="The public search provider receives the selected phone presentation variant.",
        result_parser="html_search_results_v1",
        notes="Public HTML search only; challenges and generic pages remain UNKNOWN.",
        no_match_signals=("No results.", "No results found"),
        home_url="https://html.duckduckgo.com/html/",
    ),
)
