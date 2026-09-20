from datetime import datetime, timezone

import pytest

from osint_lab.agents.target_page_fetcher import (
    FetchStatus,
    TargetPageFetcher,
    TargetPageHttpResponse,
    TargetPageTimeout,
    canonicalize_url,
)


NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
PUBLIC_IP = "93.184.216.34"


class FakeTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, *, timeout, headers, max_bytes):
        self.calls.append({"url": url, "timeout": timeout, "headers": dict(headers), "max_bytes": max_bytes})
        value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def http_response(
    status=200,
    body="<html><body>Public</body></html>",
    *,
    headers=None,
    truncated=False,
    peer_ip=PUBLIC_IP,
):
    encoded = body.encode("utf-8")
    return TargetPageHttpResponse(
        status_code=status,
        final_url="https://public.test/contact",
        headers=headers or {"content-type": "text/html", "content-length": str(len(encoded))},
        body=body,
        body_bytes=len(encoded),
        body_truncated=truncated,
        peer_ip=peer_ip,
    )


def fetcher(transport, *, resolver=None, max_redirects=4, max_response_bytes=1024):
    return TargetPageFetcher(
        transport=transport,
        resolver=resolver or (lambda host: (PUBLIC_IP,)),
        clock=lambda: NOW,
        max_redirects=max_redirects,
        max_response_bytes=max_response_bytes,
    )


def test_public_https_target_is_accepted():
    transport = FakeTransport(http_response())
    result = fetcher(transport).fetch("https://public.test/contact")
    assert result.fetch_status is FetchStatus.SUCCESS
    assert result.final_url == "https://public.test/contact"
    assert result.content_type == "text/html"
    assert result.body_sha256
    assert result.body


@pytest.mark.parametrize(
    "url",
    (
        "http://localhost/",
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://[fd00::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[fe80::1]/",
        "file:///etc/passwd",
        "ftp://public.test/file",
        "data:text/plain,fixture",
        "javascript:alert(1)",
        "http://hiddenservice.onion/",
    ),
)
def test_unsafe_target_is_blocked_before_transport(url):
    transport = FakeTransport(http_response())
    result = fetcher(transport).fetch(url)
    assert result.fetch_status is FetchStatus.BLOCKED
    assert transport.calls == []


def test_redirect_to_private_address_is_blocked():
    transport = FakeTransport(http_response(302, "", headers={"location": "http://127.0.0.1/private"}))
    result = fetcher(transport).fetch("https://public.test/start")
    assert result.fetch_status is FetchStatus.BLOCKED
    assert result.error_code == "NON_PUBLIC_IP"
    assert len(result.redirect_chain) == 1
    assert len(transport.calls) == 1


def test_dns_rebinding_to_private_address_is_blocked_after_request():
    answers = iter(((PUBLIC_IP,), (PUBLIC_IP,), ("127.0.0.1",)))
    transport = FakeTransport(http_response())
    result = fetcher(transport, resolver=lambda host: next(answers)).fetch("https://public.test/contact")
    assert result.fetch_status is FetchStatus.BLOCKED
    assert result.error_code == "NON_PUBLIC_IP"


def test_dns_rebinding_to_unexpected_public_peer_is_blocked():
    transport = FakeTransport(http_response(peer_ip="1.1.1.1"))
    result = fetcher(transport).fetch("https://public.test/contact")
    assert result.fetch_status is FetchStatus.BLOCKED
    assert result.error_code == "DNS_REBINDING"


def test_missing_peer_ip_fails_closed():
    transport = FakeTransport(http_response(peer_ip=None))
    result = fetcher(transport).fetch("https://public.test/contact")
    assert result.fetch_status is FetchStatus.BLOCKED
    assert result.error_code == "PEER_IP_UNAVAILABLE"


def test_excessive_redirects_are_blocked():
    transport = FakeTransport(
        http_response(302, "", headers={"location": "/two"}),
        http_response(302, "", headers={"location": "/three"}),
    )
    result = fetcher(transport, max_redirects=1).fetch("https://public.test/one")
    assert result.fetch_status is FetchStatus.BLOCKED
    assert result.error_code == "TOO_MANY_REDIRECTS"
    assert len(result.redirect_chain) == 1


def test_redirect_to_login_is_not_evidence():
    transport = FakeTransport(
        http_response(302, "", headers={"location": "/login"}),
        http_response(200, "<html>Sign in</html>"),
    )
    result = fetcher(transport).fetch("https://public.test/contact")
    assert result.fetch_status is FetchStatus.UNKNOWN
    assert result.error_code == "INTERACTION_REQUIRED"


def test_oversized_response_is_bounded_and_blocked():
    transport = FakeTransport(http_response(body="x" * 1024, truncated=True))
    result = fetcher(transport, max_response_bytes=64).fetch("https://public.test/large")
    assert result.fetch_status is FetchStatus.BLOCKED
    assert result.error_code == "RESPONSE_TOO_LARGE"
    assert result.body == ""


def test_unsupported_content_type_is_skipped():
    transport = FakeTransport(http_response(headers={"content-type": "application/pdf"}))
    result = fetcher(transport).fetch("https://public.test/file.pdf")
    assert result.fetch_status is FetchStatus.UNKNOWN
    assert result.error_code == "UNSUPPORTED_CONTENT_TYPE"


def test_timeout_is_unknown():
    result = fetcher(FakeTransport(TargetPageTimeout("timeout"))).fetch("https://public.test/slow")
    assert result.fetch_status is FetchStatus.UNKNOWN
    assert result.error_code == "TIMEOUT"


@pytest.mark.parametrize(
    ("status", "expected_code"),
    ((403, "HTTP_403"), (429, "HTTP_429"), (503, "HTTP_SERVER_ERROR")),
)
def test_http_failures_are_unknown(status, expected_code):
    result = fetcher(FakeTransport(http_response(status, "failure"))).fetch("https://public.test/failure")
    assert result.fetch_status is FetchStatus.UNKNOWN
    assert result.error_code == expected_code


def test_canonical_url_removes_fragment_and_tracking_but_preserves_content_query():
    value = canonicalize_url(
        "HTTPS://Example.COM:443/contact?utm_source=x&id=42&fbclid=y&lang=pl#section"
    )
    assert value == "https://example.com/contact?id=42&lang=pl"
