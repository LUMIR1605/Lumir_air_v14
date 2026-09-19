"""Conservative provider-specific public username collector."""

from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from typing import Mapping
from urllib.parse import quote, urlsplit

from osint_lab.orchestrator.context import ExecutionContext
from osint_lab.policies import SourceClass
from osint_lab.schemas import FindingStatus

from .base import Collector, FindingCandidate, RawObservation
from .username_http import (
    RequestsUsernameHttpClient,
    UsernameHttpConnectionError,
    UsernameHttpResponse,
    UsernameHttpTimeout,
)
from .username_providers import DEFAULT_USERNAME_PROVIDERS, UsernameProvider


class UsernameCollector(Collector):
    """Check public profile presence without claiming identity or ownership."""

    agent_name = "username_lookup"
    agent_type = "USERNAME"
    version = "1.0.0"
    source_class = SourceClass.PASSIVE_WEB
    network_required = True
    _USER_AGENT = "LumirOSINTLab-UsernameCollector/1.0"

    def __init__(
        self,
        *,
        providers: tuple[UsernameProvider, ...] = DEFAULT_USERNAME_PROVIDERS,
        http_client=None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__()
        if not isinstance(providers, tuple) or any(
            not isinstance(item, UsernameProvider) for item in providers
        ):
            raise ValueError("providers must contain UsernameProvider values")
        if len({item.provider_id for item in providers}) != len(providers):
            raise ValueError("provider_id values must be unique")
        self._providers = providers
        self._http_client = http_client or RequestsUsernameHttpClient()
        if not hasattr(self._http_client, "get"):
            raise ValueError("http_client must provide get()")
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def validate_input(self, seed_reference: str) -> None:
        self._normalize_username(seed_reference)

    def _run(
        self,
        context: ExecutionContext,
        seed_reference: str,
    ) -> tuple[RawObservation, ...]:
        username = self._normalize_username(seed_reference)
        return tuple(self._query_provider(provider, username) for provider in self._providers)

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        if not isinstance(observation, RawObservation):
            raise ValueError("RawObservation required")
        status = observation.payload.get("status")
        if status == "CLAIMED":
            normalized_status = FindingStatus.POSSIBLE
            fact = "USERNAME_PROFILE_CANDIDATE"
        elif status == "AVAILABLE":
            normalized_status = FindingStatus.NOT_FOUND
            fact = "USERNAME_AVAILABLE"
        else:
            normalized_status = FindingStatus.UNKNOWN
            fact = "USERNAME_UNKNOWN"
        return FindingCandidate(
            raw_status=fact,
            normalized_status=normalized_status,
            value_reference=observation.value_reference,
            evidence_ref=observation.evidence_ref,
            notes="Provider-specific public profile signal only; never identity confirmation.",
        )

    def describe_capabilities(self) -> Mapping[str, object]:
        provider_payload = [asdict(provider) for provider in self._providers]
        provider_hash = hashlib.sha256(
            json.dumps(provider_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return {
            "network": True,
            "method": "GET",
            "providers": [provider.provider_id for provider in self._providers],
            "provider_config_sha256": provider_hash,
            "provider_specific_signals": True,
            "browser_automation": False,
            "authentication": False,
            "captcha_bypass": False,
            "identity_confirmation": False,
        }

    def _query_provider(self, provider: UsernameProvider, username: str) -> RawObservation:
        profile_url = provider.profile_url_template.format(username=quote(username, safe=""))
        base = {
            "username": username,
            "provider_id": provider.provider_id,
            "provider_name": provider.name,
            "profile_url": profile_url,
            "request_method": provider.method,
            "collector_version": self.version,
            "collected_at": self._now().isoformat(),
        }
        if not provider.enabled:
            return self._observation(
                base,
                status="UNKNOWN",
                signals=["provider_disabled"],
                error_code="PROVIDER_DISABLED",
                error_reason="Provider is disabled by configuration.",
            )
        if not provider.accepts(username):
            return self._observation(
                base,
                status="UNKNOWN",
                signals=["username_invalid_for_provider"],
                error_code="PROVIDER_USERNAME_POLICY",
                error_reason="Username does not match this provider's public profile rules.",
            )
        try:
            response = self._http_client.get(
                profile_url,
                timeout=provider.timeout,
                headers={
                    "User-Agent": self._USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml",
                },
            )
        except UsernameHttpTimeout:
            return self._observation(
                base,
                status="UNKNOWN",
                signals=["timeout"],
                error_code="TIMEOUT",
                error_reason="Public profile request timed out.",
            )
        except UsernameHttpConnectionError:
            return self._observation(
                base,
                status="UNKNOWN",
                signals=["connection_error"],
                error_code="CONNECTION_ERROR",
                error_reason="Public profile request failed.",
            )
        except Exception as error:
            return self._observation(
                base,
                status="ERROR",
                signals=["client_error"],
                error_code=type(error).__name__.upper(),
                error_reason="HTTP client raised an unexpected technical error.",
            )
        if not isinstance(response, UsernameHttpResponse):
            return self._observation(
                base,
                status="ERROR",
                signals=["malformed_response"],
                error_code="MALFORMED_RESPONSE",
                error_reason="HTTP client returned an invalid response object.",
            )
        return self._classify(provider, base, response)

    def _classify(
        self,
        provider: UsernameProvider,
        base: dict[str, object],
        response: UsernameHttpResponse,
    ) -> RawObservation:
        body_casefold = response.body.casefold()
        error_matches = [
            f"error_signal_{index}"
            for index, marker in enumerate(provider.error_signals)
            if marker.casefold() in body_casefold
        ]
        response_data = {
            "http_status": response.status_code,
            "redirected": response.redirected,
            "final_url": response.final_url,
            "body_sha256": hashlib.sha256(response.body.encode("utf-8")).hexdigest(),
            "body_truncated": response.body_truncated,
        }
        if error_matches:
            return self._observation(
                {**base, **response_data},
                status="UNKNOWN",
                signals=error_matches,
                error_code="INTERSTITIAL_OR_CHALLENGE",
                error_reason="CAPTCHA, rate-limit, or challenge signal was detected.",
            )
        if response.status_code in {403, 429}:
            return self._observation(
                {**base, **response_data},
                status="UNKNOWN",
                signals=[f"http_{response.status_code}"],
                error_code=f"HTTP_{response.status_code}",
                error_reason="HTTP status is not evidence of username availability.",
            )
        if self._redirected_outside_profile(provider, str(base["profile_url"]), response):
            return self._observation(
                {**base, **response_data},
                status="UNKNOWN",
                signals=["redirect_outside_profile"],
                error_code="REDIRECT_OUTSIDE_PROFILE",
                error_reason="Redirect did not resolve to the requested profile path.",
            )
        if response.status_code >= 500:
            return self._observation(
                {**base, **response_data},
                status="UNKNOWN",
                signals=[f"http_{response.status_code}"],
                error_code="HTTP_SERVER_ERROR",
                error_reason="Server error is not evidence of username availability.",
            )
        if response.status_code not in provider.allowed_status_codes:
            return self._observation(
                {**base, **response_data},
                status="UNKNOWN",
                signals=[f"unexpected_http_{response.status_code}"],
                error_code="UNEXPECTED_HTTP_STATUS",
                error_reason="HTTP status is outside the reviewed provider rules.",
            )
        claimed_matches = [
            f"claimed_signal_{index}"
            for index, marker in enumerate(provider.claimed_signals)
            if marker.format(username=base["username"]).casefold() in body_casefold
        ]
        available_matches = [
            f"available_signal_{index}"
            for index, marker in enumerate(provider.available_signals)
            if marker.format(username=base["username"]).casefold() in body_casefold
        ]
        if claimed_matches and available_matches:
            return self._observation(
                {**base, **response_data},
                status="UNKNOWN",
                signals=claimed_matches + available_matches,
                error_code="CONFLICTING_SIGNALS",
                error_reason="Provider response contained conflicting detection signals.",
            )
        if response.status_code in provider.available_status_codes or available_matches:
            signals = available_matches or [f"available_http_{response.status_code}"]
            return self._observation(
                {**base, **response_data},
                status="AVAILABLE",
                signals=signals,
            )
        if 200 <= response.status_code < 300 and claimed_matches:
            return self._observation(
                {**base, **response_data},
                status="CLAIMED",
                signals=claimed_matches,
            )
        signal = "body_truncated_without_signal" if response.body_truncated else "no_provider_specific_signal"
        return self._observation(
            {**base, **response_data},
            status="UNKNOWN",
            signals=[signal],
            error_code="INSUFFICIENT_SIGNAL",
            error_reason="Provider-specific claimed or available evidence was not sufficient.",
        )

    @staticmethod
    def _redirected_outside_profile(
        provider: UsernameProvider,
        profile_url: str,
        response: UsernameHttpResponse,
    ) -> bool:
        if not response.redirected:
            return False
        expected = urlsplit(profile_url)
        final = urlsplit(response.final_url)
        expected_path = expected.path.rstrip("/").casefold()
        final_path = final.path.rstrip("/").casefold()
        return expected.netloc.casefold() != final.netloc.casefold() or expected_path != final_path

    @staticmethod
    def _observation(
        base: Mapping[str, object],
        *,
        status: str,
        signals: list[str],
        error_code: str | None = None,
        error_reason: str | None = None,
    ) -> RawObservation:
        payload = {
            **base,
            "http_status": base.get("http_status"),
            "status": status,
            "signals": signals,
            "redirected": bool(base.get("redirected", False)),
            "final_url": base.get("final_url"),
            "body_sha256": base.get("body_sha256"),
            "body_truncated": bool(base.get("body_truncated", False)),
            "error_code": error_code,
            "error_reason": error_reason,
        }
        return RawObservation(
            raw_status=status,
            value_reference=f"username:{base['provider_id']}:{base['username']}",
            notes="Public provider signal only; no identity or person linkage.",
            payload=payload,
        )

    @staticmethod
    def _normalize_username(seed_reference: str) -> str:
        if not isinstance(seed_reference, str) or not seed_reference.strip():
            raise ValueError("username input must be non-empty")
        username = seed_reference.strip()
        if len(username) > 64:
            raise ValueError("username input exceeds the global maximum length")
        if any(character.isspace() or ord(character) < 32 for character in username):
            raise ValueError("username input must not contain whitespace or control characters")
        if any(marker in username for marker in ("://", "/", "\\", "?", "#", "%", "@", ":")):
            raise ValueError("username input must not be a URL or path")
        if any(not (character.isascii() and (character.isalnum() or character in "._-")) for character in username):
            raise ValueError("username input contains unsupported global characters")
        return username

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collector clock must return a timezone-aware datetime")
        return value
