"""Minimal public-GET HTTP abstraction for username providers."""

from dataclasses import dataclass
import http.cookiejar
from typing import Mapping, Protocol

import requests


class UsernameHttpTimeout(RuntimeError):
    pass


class UsernameHttpConnectionError(RuntimeError):
    pass


@dataclass(frozen=True, kw_only=True)
class UsernameHttpResponse:
    status_code: int
    final_url: str
    body: str
    redirected: bool
    body_truncated: bool = False


class UsernameHttpClient(Protocol):
    def get(
        self,
        url: str,
        *,
        timeout: float,
        headers: Mapping[str, str],
    ) -> UsernameHttpResponse: ...


class _RejectCookies(http.cookiejar.DefaultCookiePolicy):
    def set_ok(self, cookie, request) -> bool:
        return False

    def return_ok(self, cookie, request) -> bool:
        return False


class RequestsUsernameHttpClient:
    """Perform one public GET with no auth, persistent cookies, proxy, or browser."""

    def __init__(self, *, max_body_bytes: int = 131_072) -> None:
        if isinstance(max_body_bytes, bool) or not isinstance(max_body_bytes, int) or max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be a positive integer")
        self._max_body_bytes = max_body_bytes

    def get(
        self,
        url: str,
        *,
        timeout: float,
        headers: Mapping[str, str],
    ) -> UsernameHttpResponse:
        session = requests.Session()
        session.trust_env = False
        session.cookies.set_policy(_RejectCookies())
        response = None
        try:
            response = session.request(
                "GET",
                url,
                headers=dict(headers),
                timeout=timeout,
                allow_redirects=True,
                stream=True,
            )
            response.raw.decode_content = True
            raw = response.raw.read(self._max_body_bytes + 1)
            truncated = len(raw) > self._max_body_bytes
            raw = raw[:self._max_body_bytes]
            encoding = response.encoding or "utf-8"
            body = raw.decode(encoding, errors="replace")
            return UsernameHttpResponse(
                status_code=response.status_code,
                final_url=response.url,
                body=body,
                redirected=bool(response.history),
                body_truncated=truncated,
            )
        except requests.Timeout as error:
            raise UsernameHttpTimeout("public GET timed out") from error
        except requests.RequestException as error:
            raise UsernameHttpConnectionError("public GET failed") from error
        finally:
            if response is not None:
                response.close()
            session.close()
