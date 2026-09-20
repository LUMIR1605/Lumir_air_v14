"""Minimal no-auth public GET client for phone occurrence providers."""

from dataclasses import dataclass
import http.cookiejar
from typing import Mapping, Protocol

import requests


class PhonePublicHttpTimeout(RuntimeError):
    pass


class PhonePublicHttpConnectionError(RuntimeError):
    pass


@dataclass(frozen=True, kw_only=True)
class PhonePublicHttpResponse:
    status_code: int
    final_url: str
    body: str
    redirected: bool
    body_truncated: bool = False


class PhonePublicHttpClient(Protocol):
    def get(self, url: str, *, timeout: float, headers: Mapping[str, str]) -> PhonePublicHttpResponse: ...


class _RejectCookies(http.cookiejar.DefaultCookiePolicy):
    def set_ok(self, cookie, request) -> bool:
        return False

    def return_ok(self, cookie, request) -> bool:
        return False


class RequestsPhonePublicHttpClient:
    def __init__(self, *, max_body_bytes: int = 262_144) -> None:
        if isinstance(max_body_bytes, bool) or not isinstance(max_body_bytes, int) or max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be a positive integer")
        self._max_body_bytes = max_body_bytes

    def get(self, url: str, *, timeout: float, headers: Mapping[str, str]) -> PhonePublicHttpResponse:
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
            body = raw.decode(response.encoding or "utf-8", errors="replace")
            return PhonePublicHttpResponse(
                status_code=response.status_code,
                final_url=response.url,
                body=body,
                redirected=bool(response.history),
                body_truncated=truncated,
            )
        except requests.Timeout as error:
            raise PhonePublicHttpTimeout("public phone search timed out") from error
        except requests.RequestException as error:
            raise PhonePublicHttpConnectionError("public phone search failed") from error
        finally:
            if response is not None:
                response.close()
            session.close()
