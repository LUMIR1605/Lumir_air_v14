"""Conservative local email metadata and passive public exposure collectors."""

from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Mapping
from urllib.parse import urlsplit

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


EMAIL_PROVIDER_LIST_VERSION = "2026-09-v1"
FREE_PROVIDER_DOMAINS = frozenset({
    "gmail.com",
    "outlook.com",
    "proton.me",
    "protonmail.com",
    "yahoo.com",
})
DISPOSABLE_PROVIDER_DOMAINS = frozenset({
    "guerrillamail.com",
    "mailinator.com",
})

_LOCAL_PART = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+")
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_FORBIDDEN_ENDPOINT_TERMS = (
    "captcha",
    "challenge",
    "forgot",
    "login",
    "mfa",
    "password",
    "recover",
    "register",
    "reset",
    "signin",
    "signup",
)
_COMMON_ERROR_SIGNALS = (
    "captcha",
    "cf-chl-",
    "cloudflare",
    "just a moment",
    "rate limit",
    "too many requests",
)


@dataclass(frozen=True, kw_only=True)
class EmailProvider:
    """Reviewed public endpoint rule; no login, signup, or recovery flows."""

    provider_id: str
    name: str
    method: str
    endpoint_template: str
    claimed_signals: tuple[str, ...]
    available_signals: tuple[str, ...]
    error_signals: tuple[str, ...]
    allowed_status_codes: tuple[int, ...]
    timeout: float
    enabled: bool
    privacy_notes: str
    notes: str
    available_status_codes: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        for name in ("provider_id", "name", "method", "endpoint_template", "privacy_notes", "notes"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if self.method != "GET":
            raise ValueError("email exposure providers support public GET only")
        if "{email_sha256}" not in self.endpoint_template:
            raise ValueError("endpoint_template must contain {email_sha256}")
        if "{email}" in self.endpoint_template:
            raise ValueError("raw email placeholders are not permitted")
        parsed = urlsplit(self.endpoint_template)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("endpoint_template must be an absolute HTTPS URL")
        endpoint_casefold = self.endpoint_template.casefold()
        if any(term in endpoint_casefold for term in _FORBIDDEN_ENDPOINT_TERMS):
            raise ValueError("login, signup, recovery, challenge, and reset endpoints are forbidden")
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


DEFAULT_EMAIL_PROVIDERS = (
    EmailProvider(
        provider_id="gravatar_public_profile",
        name="Gravatar public profile",
        method="GET",
        endpoint_template="https://api.gravatar.com/v3/profiles/{email_sha256}",
        claimed_signals=('"profile_url"', '"hash"'),
        available_signals=(),
        error_signals=_COMMON_ERROR_SIGNALS,
        allowed_status_codes=(200, 403, 404, 429, 500, 502, 503),
        available_status_codes=(404,),
        timeout=8.0,
        enabled=True,
        privacy_notes="Discloses the provider-normalized SHA-256 email identifier and source IP.",
        notes="Public unauthenticated profile endpoint; HTTP 200 still requires profile JSON markers.",
    ),
)


def normalize_email(seed_reference: str) -> tuple[str, str, str]:
    """Validate an ASCII local-part and normalize only the domain through IDNA."""

    if not isinstance(seed_reference, str) or not seed_reference.strip():
        raise ValueError("email input must be non-empty")
    email = seed_reference.strip()
    if len(email) > 254:
        raise ValueError("email input exceeds 254 characters")
    if email.count("@") != 1:
        raise ValueError("email input must contain exactly one @")
    local_part, domain = email.split("@", 1)
    if not local_part or not domain:
        raise ValueError("email local-part and domain must be non-empty")
    if len(local_part) > 64 or not local_part.isascii() or not _LOCAL_PART.fullmatch(local_part):
        raise ValueError("email local-part is unsupported or too long")
    if local_part.startswith(".") or local_part.endswith(".") or ".." in local_part:
        raise ValueError("email local-part has invalid dot placement")
    if domain.startswith(".") or domain.endswith(".") or ".." in domain:
        raise ValueError("email domain is invalid")
    try:
        domain_idna = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("email domain is not valid IDNA") from error
    if len(domain_idna) > 253 or "." not in domain_idna:
        raise ValueError("email domain must be a qualified domain name")
    labels = domain_idna.split(".")
    if any(len(label) > 63 or _DOMAIN_LABEL.fullmatch(label) is None for label in labels):
        raise ValueError("email domain contains an invalid label")
    return f"{local_part}@{domain_idna}", local_part, domain_idna


class EmailLocalMetadataCollector(Collector):
    """Derive syntax and explicit-list metadata without any network access."""

    agent_name = "email_local_metadata"
    agent_type = "EMAIL"
    version = "1.0.0"
    source_class = SourceClass.LOCAL
    network_required = False

    def validate_input(self, seed_reference: str) -> None:
        normalize_email(seed_reference)

    def _run(
        self,
        context: ExecutionContext,
        seed_reference: str,
    ) -> tuple[RawObservation, ...]:
        normalized, local_part, domain = normalize_email(seed_reference)
        provider_class, free_provider, disposable_provider = self._provider_metadata(domain)
        return (RawObservation(
            raw_status="VALID",
            value_reference=f"email:{normalized}",
            notes="Technical email syntax/domain metadata only; no ownership or identity claim.",
            payload={
                "normalized_email": normalized,
                "local_part": local_part,
                "domain": domain,
                "syntax_valid": True,
                "domain_idna": domain,
                "provider_class": provider_class,
                "free_provider": free_provider,
                "disposable_provider": disposable_provider,
                "provider_list_version": EMAIL_PROVIDER_LIST_VERSION,
                "domain_dns_dependency": {
                    "collector": "domain_dns",
                    "seed_reference": domain,
                    "source_class": SourceClass.PASSIVE_WEB.value,
                    "requires_separate_policy_evaluation": True,
                },
            },
        ),)

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        if not isinstance(observation, RawObservation):
            raise ValueError("RawObservation required")
        return FindingCandidate(
            raw_status="EMAIL_SYNTAX_VALID",
            normalized_status=FindingStatus.POSSIBLE,
            value_reference=observation.value_reference,
            evidence_ref=observation.evidence_ref,
            notes="Technical syntax result only; it does not confirm an account or owner.",
        )

    def describe_capabilities(self) -> Mapping[str, object]:
        return {
            "network": False,
            "email_syntax": True,
            "idna_domain": True,
            "provider_list_version": EMAIL_PROVIDER_LIST_VERSION,
            "provider_lists_complete": False,
            "domain_dns_collector_reference": "domain_dns",
            "identity_confirmation": False,
        }

    @staticmethod
    def _provider_metadata(domain: str) -> tuple[str | None, bool | None, bool | None]:
        if domain in DISPOSABLE_PROVIDER_DOMAINS:
            return "DISPOSABLE_CANDIDATE", None, True
        if domain in FREE_PROVIDER_DOMAINS:
            return "FREE_WEBMAIL", True, None
        return None, None, None


class EmailExposureCollector(Collector):
    """Check reviewed public email-hash endpoints without authentication flows."""

    agent_name = "email_exposure"
    agent_type = "EMAIL"
    version = "1.0.0"
    source_class = SourceClass.PASSIVE_WEB
    network_required = True
    _USER_AGENT = "LumirOSINTLab-EmailExposureCollector/1.0"

    def __init__(
        self,
        *,
        providers: tuple[EmailProvider, ...] = DEFAULT_EMAIL_PROVIDERS,
        http_client=None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__()
        if not isinstance(providers, tuple) or any(not isinstance(item, EmailProvider) for item in providers):
            raise ValueError("providers must contain EmailProvider values")
        if len({item.provider_id for item in providers}) != len(providers):
            raise ValueError("provider_id values must be unique")
        self._providers = providers
        self._http_client = http_client or RequestsUsernameHttpClient()
        if not hasattr(self._http_client, "get"):
            raise ValueError("http_client must provide get()")
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def validate_input(self, seed_reference: str) -> None:
        normalize_email(seed_reference)

    def _run(
        self,
        context: ExecutionContext,
        seed_reference: str,
    ) -> tuple[RawObservation, ...]:
        normalized, _, _ = normalize_email(seed_reference)
        return tuple(self._query_provider(provider, normalized) for provider in self._providers)

    def normalize(self, observation: RawObservation) -> FindingCandidate:
        if not isinstance(observation, RawObservation):
            raise ValueError("RawObservation required")
        status = observation.payload.get("status")
        if status == "CLAIMED":
            normalized_status = FindingStatus.POSSIBLE
            fact = "EMAIL_SERVICE_CANDIDATE"
        elif status == "AVAILABLE":
            normalized_status = FindingStatus.NOT_FOUND
            fact = "EMAIL_SERVICE_AVAILABLE"
        else:
            normalized_status = FindingStatus.UNKNOWN
            fact = "EMAIL_SERVICE_UNKNOWN"
        return FindingCandidate(
            raw_status=fact,
            normalized_status=normalized_status,
            value_reference=observation.value_reference,
            evidence_ref=observation.evidence_ref,
            notes="Public provider signal only; never email ownership or person confirmation.",
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
            "hashed_email_identifier_only": True,
            "provider_specific_signals": True,
            "browser_automation": False,
            "authentication": False,
            "captcha_bypass": False,
            "identity_confirmation": False,
        }

    def _query_provider(self, provider: EmailProvider, normalized_email: str) -> RawObservation:
        email_sha256 = hashlib.sha256(normalized_email.casefold().encode("utf-8")).hexdigest()
        endpoint_url = provider.endpoint_template.replace("{email_sha256}", email_sha256)
        base = {
            "email_reference": f"sha256:{email_sha256}",
            "provider_id": provider.provider_id,
            "provider_name": provider.name,
            "endpoint_url": endpoint_url,
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
        try:
            response = self._http_client.get(
                endpoint_url,
                timeout=provider.timeout,
                headers={"User-Agent": self._USER_AGENT, "Accept": "application/json,text/plain"},
            )
        except UsernameHttpTimeout:
            return self._observation(
                base,
                status="UNKNOWN",
                signals=["timeout"],
                error_code="TIMEOUT",
                error_reason="Public provider request timed out.",
            )
        except UsernameHttpConnectionError:
            return self._observation(
                base,
                status="UNKNOWN",
                signals=["connection_error"],
                error_code="CONNECTION_ERROR",
                error_reason="Public provider request failed.",
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
        provider: EmailProvider,
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
                error_reason="HTTP status is not evidence of email availability.",
            )
        if response.redirected:
            return self._observation(
                {**base, **response_data},
                status="UNKNOWN",
                signals=["redirected_response"],
                error_code="REDIRECTED_RESPONSE",
                error_reason="Redirects are not accepted as account exposure evidence.",
            )
        if response.status_code >= 500:
            return self._observation(
                {**base, **response_data},
                status="ERROR",
                signals=[f"http_{response.status_code}"],
                error_code="HTTP_SERVER_ERROR",
                error_reason="Server error is not evidence of email availability.",
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
            if marker.casefold() in body_casefold
        ]
        available_matches = [
            f"available_signal_{index}"
            for index, marker in enumerate(provider.available_signals)
            if marker.casefold() in body_casefold
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
            return self._observation(
                {**base, **response_data},
                status="AVAILABLE",
                signals=available_matches or [f"available_http_{response.status_code}"],
            )
        if 200 <= response.status_code < 300 and claimed_matches:
            return self._observation(
                {**base, **response_data},
                status="CLAIMED",
                signals=claimed_matches,
            )
        return self._observation(
            {**base, **response_data},
            status="UNKNOWN",
            signals=["body_truncated_without_signal" if response.body_truncated else "no_provider_specific_signal"],
            error_code="INSUFFICIENT_SIGNAL",
            error_reason="Provider-specific claimed or available evidence was not sufficient.",
        )

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
            value_reference=f"email-provider:{base['provider_id']}:{base['email_reference']}",
            notes="Public provider signal only; no ownership or person linkage.",
            payload=payload,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collector clock must return a timezone-aware datetime")
        return value
