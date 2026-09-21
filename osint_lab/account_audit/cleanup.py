"""Reviewed, local foundation for official account-cleanup links."""

from dataclasses import dataclass
from datetime import date
from urllib.parse import urlsplit


@dataclass(frozen=True, kw_only=True)
class CleanupCatalogEntry:
    service_id: str
    homepage: str | None
    account_settings_url: str | None
    deletion_url: str | None
    privacy_url: str | None
    deletion_instructions_note: str | None
    reviewed_at: date

    def __post_init__(self) -> None:
        if not isinstance(self.service_id, str) or not self.service_id.strip():
            raise ValueError("service_id must be non-empty")
        for name in ("homepage", "account_settings_url", "deletion_url", "privacy_url"):
            value = getattr(self, name)
            if value is None:
                continue
            parsed = urlsplit(value)
            if parsed.scheme != "https" or not parsed.hostname:
                raise ValueError(f"{name} must be an official HTTPS URL or null")

    def to_dict(self) -> dict[str, object]:
        return {
            "service_id": self.service_id,
            "homepage": self.homepage,
            "account_settings_url": self.account_settings_url,
            "deletion_url": self.deletion_url,
            "privacy_url": self.privacy_url,
            "deletion_instructions_note": self.deletion_instructions_note,
            "reviewed_at": self.reviewed_at.isoformat(),
        }


class AccountCleanupCatalog:
    """Small reviewed catalog; unknown services deliberately remain null."""

    def __init__(self, entries: tuple[CleanupCatalogEntry, ...] | None = None) -> None:
        values = entries if entries is not None else _DEFAULT_ENTRIES
        self._entries = {item.service_id.casefold(): item for item in values}
        if len(self._entries) != len(values):
            raise ValueError("duplicate cleanup catalog service_id")

    def get(self, service_id: str) -> CleanupCatalogEntry:
        key = service_id.casefold()
        if key in self._entries:
            return self._entries[key]
        return CleanupCatalogEntry(
            service_id=service_id,
            homepage=None,
            account_settings_url=None,
            deletion_url=None,
            privacy_url=None,
            deletion_instructions_note=None,
            reviewed_at=date(2026, 9, 21),
        )


_DEFAULT_ENTRIES = (
    CleanupCatalogEntry(
        service_id="github",
        homepage="https://github.com/",
        account_settings_url="https://github.com/settings/admin",
        deletion_url="https://docs.github.com/en/account-and-profile/how-tos/account-management/deleting-your-personal-account",
        privacy_url="https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement",
        deletion_instructions_note="Use the official account settings and review the delete-account section manually.",
        reviewed_at=date(2026, 9, 21),
    ),
    CleanupCatalogEntry(
        service_id="spotify",
        homepage="https://www.spotify.com/",
        account_settings_url="https://www.spotify.com/account/",
        deletion_url="https://support.spotify.com/article/how-to-close-your-account/",
        privacy_url="https://www.spotify.com/legal/privacy-policy/",
        deletion_instructions_note="Follow Spotify's official close-account help page manually.",
        reviewed_at=date(2026, 9, 21),
    ),
)
