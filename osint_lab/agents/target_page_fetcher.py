"""Bounded public target-page fetcher with SSRF and redirect controls."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import ipaddress
import socket
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests


class FetchStatus(str, Enum):
    SUCCESS = "SUCCESS"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


class TargetPageTimeout(RuntimeError):
    pass


class TargetPageConnectionError(RuntimeError):
    pass


@dataclass(frozen=True, kw_only=True)
class TargetPageHttpResponse:
    status_code: int
    final_url: str
    headers: Mapping[str, str]
    body: str
    body_bytes: int
    body_truncated: bool = False
    peer_ip: str | None = None
    raw_bytes: bytes = b""
    tls_certificate: Mapping[str, object] | None = None


class TargetPageTransport(Protocol):
    def get(
        self,
        url: str,
        *,
        timeout: tuple[float, float],
        headers: Mapping[str, str],
        max_bytes: int,
    ) -> TargetPageHttpResponse: ...


@dataclass(frozen=True, kw_only=True)
class TargetPageFetchResult:
    requested_url: str
    final_url: str | None
    http_status: int | None
    content_type: str | None
    content_length: int | None
    redirected: bool
    redirect_chain: tuple[dict[str, object], ...]
    fetched_at: datetime
    body_sha256: str | None
    body_truncated: bool
    fetch_status: FetchStatus
    error_code: str | None
    body: str = ""
    raw_bytes: bytes = b""
    response_headers: Mapping[str, str] | None = None
    tls_certificate: Mapping[str, object] | None = None

    def to_metadata(self) -> dict[str, object]:
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "http_status": self.http_status,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "redirected": self.redirected,
            "redirect_chain": list(self.redirect_chain),
            "fetched_at": self.fetched_at.isoformat(),
            "body_sha256": self.body_sha256,
            "body_truncated": self.body_truncated,
            "fetch_status": self.fetch_status.value,
            "error_code": self.error_code,
            "response_headers": dict(self.response_headers or {}),
            "tls_certificate": dict(self.tls_certificate or {}),
        }


class RequestsTargetPageTransport:
    """No-cookie transport; redirects are deliberately handled by TargetPageFetcher."""

    def get(
        self,
        url: str,
        *,
        timeout: tuple[float, float],
        headers: Mapping[str, str],
        max_bytes: int,
    ) -> TargetPageHttpResponse:
        session = requests.Session()
        session.trust_env = False
        response = None
        try:
            response = session.request(
                "GET",
                url,
                headers=dict(headers),
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            )
            response.raw.decode_content = True
            raw = response.raw.read(max_bytes + 1)
            truncated = len(raw) > max_bytes
            raw = raw[:max_bytes]
            peer_ip = _response_peer_ip(response)
            return TargetPageHttpResponse(
                status_code=response.status_code,
                final_url=response.url,
                headers={str(key).casefold(): str(value) for key, value in response.headers.items()},
                body=raw.decode(response.encoding or "utf-8", errors="replace"),
                body_bytes=len(raw),
                body_truncated=truncated,
                peer_ip=peer_ip,
                raw_bytes=raw,
                tls_certificate=_response_tls_certificate(response),
            )
        except requests.Timeout as error:
            raise TargetPageTimeout("target page timed out") from error
        except requests.RequestException as error:
            raise TargetPageConnectionError("target page request failed") from error
        finally:
            if response is not None:
                response.close()
            session.close()


class TargetPageFetcher:
    _SUPPORTED_CONTENT_TYPES = {"text/html", "application/xhtml+xml", "text/plain"}
    _REDIRECT_STATUSES = {301, 302, 303, 307, 308}
    _CHALLENGE_SIGNALS = (
        "captcha", "cf-chl-", "cloudflare", "just a moment", "enable javascript",
        "javascript is required", "verify you are human",
    )
    _BLOCKED_HOSTS = {
        "localhost", "localhost.localdomain", "metadata.google.internal",
        "metadata.aws.internal", "instance-data.ec2.internal",
    }

    def __init__(
        self,
        *,
        transport: TargetPageTransport | None = None,
        resolver: Callable[[str], tuple[str, ...]] | None = None,
        clock: Callable[[], datetime] | None = None,
        connect_timeout: float = 4.0,
        read_timeout: float = 8.0,
        max_redirects: int = 4,
        max_response_bytes: int = 524_288,
        user_agent: str = "LumirOSINTLab-TargetPageFetcher/1.0",
        supported_content_types: frozenset[str] | None = None,
    ) -> None:
        if connect_timeout <= 0 or read_timeout <= 0:
            raise ValueError("timeouts must be positive")
        if isinstance(max_redirects, bool) or not isinstance(max_redirects, int) or max_redirects < 0:
            raise ValueError("max_redirects must be a non-negative integer")
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be a positive integer")
        self._transport = transport or RequestsTargetPageTransport()
        self._resolver = resolver or _resolve_host
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._timeout = (float(connect_timeout), float(read_timeout))
        self._max_redirects = max_redirects
        self._max_response_bytes = max_response_bytes
        self._user_agent = user_agent
        self._supported_content_types = supported_content_types or frozenset(self._SUPPORTED_CONTENT_TYPES)
        if not self._supported_content_types or any(
            not isinstance(item, str) or not item.strip() for item in self._supported_content_types
        ):
            raise ValueError("supported_content_types must contain non-empty strings")

    def fetch(self, requested_url: str) -> TargetPageFetchResult:
        started = self._now()
        try:
            current_url = canonicalize_url(requested_url)
            self._validated_addresses(current_url)
        except (ValueError, PermissionError) as error:
            return self._result(
                requested_url=requested_url,
                fetched_at=started,
                status=FetchStatus.BLOCKED,
                error_code=_error_code(error),
            )

        chain: list[dict[str, object]] = []
        for redirect_count in range(self._max_redirects + 1):
            try:
                before_addresses = self._validated_addresses(current_url)
                response = self._transport.get(
                    current_url,
                    timeout=self._timeout,
                    headers={
                        "User-Agent": self._user_agent,
                        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8",
                    },
                    max_bytes=self._max_response_bytes,
                )
                if response.peer_ip is None:
                    raise PermissionError("PEER_IP_UNAVAILABLE")
                _validate_ip(response.peer_ip)
                peer_ip = str(ipaddress.ip_address(response.peer_ip))
                if peer_ip not in before_addresses:
                    raise PermissionError("DNS_REBINDING")
                after_addresses = self._validated_addresses(current_url)
                if not before_addresses or not after_addresses:
                    raise PermissionError("DNS_EMPTY")
                if peer_ip not in after_addresses:
                    raise PermissionError("DNS_REBINDING")
            except TargetPageTimeout:
                return self._result(
                    requested_url=requested_url, final_url=current_url, fetched_at=started,
                    redirected=bool(chain), chain=chain, status=FetchStatus.UNKNOWN, error_code="TIMEOUT",
                )
            except TargetPageConnectionError:
                return self._result(
                    requested_url=requested_url, final_url=current_url, fetched_at=started,
                    redirected=bool(chain), chain=chain, status=FetchStatus.UNKNOWN,
                    error_code="CONNECTION_ERROR",
                )
            except (ValueError, PermissionError) as error:
                return self._result(
                    requested_url=requested_url, final_url=current_url, fetched_at=started,
                    redirected=bool(chain), chain=chain, status=FetchStatus.BLOCKED,
                    error_code=_error_code(error),
                )
            except Exception:
                return self._result(
                    requested_url=requested_url, final_url=current_url, fetched_at=started,
                    redirected=bool(chain), chain=chain, status=FetchStatus.ERROR,
                    error_code="TRANSPORT_ERROR",
                )

            status_code = response.status_code
            if status_code in self._REDIRECT_STATUSES:
                location = response.headers.get("location")
                if not location:
                    return self._from_response(
                        requested_url, current_url, response, started, chain,
                        FetchStatus.UNKNOWN, "REDIRECT_WITHOUT_LOCATION",
                    )
                if redirect_count >= self._max_redirects:
                    return self._from_response(
                        requested_url, current_url, response, started, chain,
                        FetchStatus.BLOCKED, "TOO_MANY_REDIRECTS",
                    )
                try:
                    next_url = canonicalize_url(urljoin(current_url, location))
                    self._validated_addresses(next_url)
                except (ValueError, PermissionError) as error:
                    chain.append({"status": status_code, "from_url": current_url, "to_url": location})
                    return self._from_response(
                        requested_url, current_url, response, started, chain,
                        FetchStatus.BLOCKED, _error_code(error),
                    )
                chain.append({"status": status_code, "from_url": current_url, "to_url": next_url})
                current_url = next_url
                continue

            if status_code in {403, 429}:
                return self._from_response(
                    requested_url, current_url, response, started, chain,
                    FetchStatus.UNKNOWN, f"HTTP_{status_code}",
                )
            if status_code >= 500:
                return self._from_response(
                    requested_url, current_url, response, started, chain,
                    FetchStatus.UNKNOWN, "HTTP_SERVER_ERROR",
                )
            if not 200 <= status_code < 300:
                return self._from_response(
                    requested_url, current_url, response, started, chain,
                    FetchStatus.UNKNOWN, "UNEXPECTED_HTTP_STATUS",
                )
            if chain and _is_homepage(current_url) and not _is_homepage(requested_url):
                return self._from_response(
                    requested_url, current_url, response, started, chain,
                    FetchStatus.UNKNOWN, "REDIRECT_HOME",
                )
            if chain and _is_interactive_gate(current_url):
                return self._from_response(
                    requested_url, current_url, response, started, chain,
                    FetchStatus.UNKNOWN, "INTERACTION_REQUIRED",
                )
            content_type = _content_type(response.headers)
            if content_type not in self._supported_content_types:
                return self._from_response(
                    requested_url, current_url, response, started, chain,
                    FetchStatus.UNKNOWN, "UNSUPPORTED_CONTENT_TYPE",
                )
            declared_length = _content_length(response.headers)
            if response.body_truncated or (
                declared_length is not None and declared_length > self._max_response_bytes
            ):
                return self._from_response(
                    requested_url, current_url, response, started, chain,
                    FetchStatus.BLOCKED, "RESPONSE_TOO_LARGE",
                )
            if any(signal in response.body.casefold() for signal in self._CHALLENGE_SIGNALS):
                return self._from_response(
                    requested_url, current_url, response, started, chain,
                    FetchStatus.UNKNOWN, "CHALLENGE",
                )
            return self._from_response(
                requested_url, current_url, response, started, chain,
                FetchStatus.SUCCESS, None,
            )

        return self._result(
            requested_url=requested_url, final_url=current_url, fetched_at=started,
            redirected=bool(chain), chain=chain, status=FetchStatus.BLOCKED,
            error_code="TOO_MANY_REDIRECTS",
        )

    def _validated_addresses(self, url: str) -> tuple[str, ...]:
        parsed = urlsplit(url)
        if parsed.scheme.casefold() not in {"http", "https"}:
            raise PermissionError("UNSUPPORTED_SCHEME")
        host = (parsed.hostname or "").casefold().rstrip(".")
        if not host:
            raise ValueError("MISSING_HOST")
        if host in self._BLOCKED_HOSTS or host.endswith(".localhost"):
            raise PermissionError("BLOCKED_HOST")
        if host.endswith(".onion"):
            raise PermissionError("ONION_BLOCKED")
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            addresses = tuple(dict.fromkeys(self._resolver(host)))
        else:
            addresses = (str(literal),)
        if not addresses:
            raise PermissionError("DNS_EMPTY")
        for address in addresses:
            _validate_ip(address)
        return addresses

    def _from_response(
        self,
        requested_url: str,
        final_url: str,
        response: TargetPageHttpResponse,
        fetched_at: datetime,
        chain: list[dict[str, object]],
        status: FetchStatus,
        error_code: str | None,
    ) -> TargetPageFetchResult:
        content_bytes = response.raw_bytes or response.body.encode("utf-8")
        body_hash = hashlib.sha256(content_bytes).hexdigest() if content_bytes else None
        return TargetPageFetchResult(
            requested_url=requested_url,
            final_url=final_url,
            http_status=response.status_code,
            content_type=_content_type(response.headers),
            content_length=_content_length(response.headers) or response.body_bytes,
            redirected=bool(chain),
            redirect_chain=tuple(chain),
            fetched_at=fetched_at,
            body_sha256=body_hash,
            body_truncated=response.body_truncated,
            fetch_status=status,
            error_code=error_code,
            body=response.body if status is FetchStatus.SUCCESS else "",
            raw_bytes=response.raw_bytes if status is FetchStatus.SUCCESS else b"",
            response_headers={key: value for key, value in response.headers.items()
                              if key.casefold() in {"content-type", "content-language", "server", "last-modified"}},
            tls_certificate=response.tls_certificate,
        )

    @staticmethod
    def _result(
        *,
        requested_url: str,
        fetched_at: datetime,
        status: FetchStatus,
        error_code: str | None,
        final_url: str | None = None,
        redirected: bool = False,
        chain: list[dict[str, object]] | None = None,
    ) -> TargetPageFetchResult:
        return TargetPageFetchResult(
            requested_url=requested_url,
            final_url=final_url,
            http_status=None,
            content_type=None,
            content_length=None,
            redirected=redirected,
            redirect_chain=tuple(chain or ()),
            fetched_at=fetched_at,
            body_sha256=None,
            body_truncated=False,
            fetch_status=status,
            error_code=error_code,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("fetcher clock must return a timezone-aware datetime")
        return value


def canonicalize_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("URL_EMPTY")
    parsed = urlsplit(value.strip())
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"}:
        raise PermissionError("UNSUPPORTED_SCHEME")
    host = (parsed.hostname or "").casefold().rstrip(".")
    if not host:
        raise ValueError("MISSING_HOST")
    port = parsed.port
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{netloc}:{port}"
    query = [
        (key, item) for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        if not key.casefold().startswith("utm_") and key.casefold() not in {"fbclid", "gclid"}
    ]
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, urlencode(query, doseq=True), ""))


def _resolve_host(host: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(
        item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    ))


def _validate_ip(value: str) -> None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise PermissionError("INVALID_IP") from error
    if not address.is_global:
        raise PermissionError("NON_PUBLIC_IP")


def _content_type(headers: Mapping[str, str]) -> str | None:
    value = headers.get("content-type") or headers.get("Content-Type")
    return value.split(";", 1)[0].strip().casefold() if value else None


def _content_length(headers: Mapping[str, str]) -> int | None:
    value = headers.get("content-length") or headers.get("Content-Length")
    if value is None:
        return None
    try:
        return max(0, int(value))
    except ValueError:
        return None


def _is_homepage(value: str) -> bool:
    parsed = urlsplit(value)
    return parsed.path in {"", "/"} and not parsed.query


def _is_interactive_gate(value: str) -> bool:
    path = urlsplit(value).path.casefold()
    return any(marker in path for marker in ("/login", "/signin", "/sign-in", "/auth", "/account"))


def _error_code(error: Exception) -> str:
    text = str(error).strip()
    return text if text and text.replace("_", "").isalnum() else type(error).__name__.upper()


def _response_peer_ip(response) -> str | None:
    candidates = (
        lambda: response.raw._connection.sock,
        lambda: response.raw._fp.fp.raw._sock,
    )
    for candidate in candidates:
        try:
            return str(candidate().getpeername()[0])
        except (AttributeError, OSError, TypeError):
            continue
    return None


def _response_tls_certificate(response) -> dict[str, object] | None:
    candidates = (
        lambda: response.raw._connection.sock,
        lambda: response.raw._fp.fp.raw._sock,
    )
    for candidate in candidates:
        try:
            certificate = candidate().getpeercert()
        except (AttributeError, OSError, TypeError, ValueError):
            continue
        if not isinstance(certificate, dict):
            continue
        subject = []
        for group in certificate.get("subject", ()):
            for key, value in group:
                subject.append(f"{key}={value}")
        sans = [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"]
        return {
            "subject": ", ".join(subject) or None,
            "subject_alt_names": sans,
            "not_after": certificate.get("notAfter"),
        }
    return None
