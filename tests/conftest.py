"""Shared pytest fixtures.

!! None of these tests touch the network. !!

Every HTTP interaction goes through a fake client that returns canned payloads,
and every DNS query is served by an in-memory stub resolver.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import pytest

from subdomainx.models import Host
from subdomainx.utils.http import HTTPResponse


# ---------------------------------------------------------------------------
# fake HTTP layer
# ---------------------------------------------------------------------------


def make_response(
    text: str = "",
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None,
    error: Optional[str] = None,
    url: str = "https://example.test/",
) -> HTTPResponse:
    """Build an :class:`HTTPResponse` for tests."""
    return HTTPResponse(
        url=url,
        status_code=status_code,
        text=text,
        headers=headers or {},
        elapsed_ms=1.0,
        error=error,
        attempts=1,
    )


@dataclass
class Route:
    """A canned response for requests whose URL matches ``pattern``."""

    pattern: str
    response: HTTPResponse
    is_regex: bool = False


class FakeHTTPClient:
    """Drop-in replacement for :class:`subdomainx.utils.http.HTTPClient`."""

    def __init__(
        self,
        routes: Optional[List[Tuple[str, HTTPResponse]]] = None,
        default: Optional[HTTPResponse] = None,
    ) -> None:
        self.routes: List[Route] = []
        for pattern, response in routes or []:
            self.routes.append(Route(pattern, response))
        self.default = default or make_response("", status_code=404, error="HTTP 404")
        self.calls: List[str] = []
        self.session = None
        self.timeout = 5.0

    def add(self, pattern: str, response: HTTPResponse) -> "FakeHTTPClient":
        self.routes.append(Route(pattern, response))
        return self

    def _match(self, url: str) -> HTTPResponse:
        for route in self.routes:
            if route.is_regex:
                if re.search(route.pattern, url):
                    return route.response
            elif route.pattern in url:
                return route.response
        return self.default

    def get(self, url: str, params: Optional[Dict[str, Any]] = None, **kwargs: Any) -> HTTPResponse:
        full = url
        if params:
            full = f"{url}{'&' if '?' in url else '?'}{urlencode(params, doseq=True)}"
        return self.request("GET", full)

    def post(self, url: str, data=None, json_body=None, headers=None, **kwargs: Any) -> HTTPResponse:
        return self.request("POST", url)

    def request(self, method: str, url: str, params=None, **kwargs: Any) -> HTTPResponse:
        full = url
        if params:
            full = f"{url}{'&' if '?' in url else '?'}{urlencode(params, doseq=True)}"
        self.calls.append(f"{method} {full}")
        response = self._match(full)
        return response

    def probe(self, url: str, **kwargs: Any) -> HTTPResponse:
        self.calls.append(f"PROBE {url}")
        return self._match(url)

    def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# fake DNS layer
# ---------------------------------------------------------------------------


class FakeRecord:
    """Mimics a dnspython rdata object."""

    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class FakeAnswer:
    """Mimics a dnspython answer object."""

    def __init__(self, records: List[str]) -> None:
        self._records = [FakeRecord(r) for r in records]

    def __iter__(self):
        return iter(self._records)


@dataclass
class FakeDNSServer:
    """In-memory DNS stub: ``{hostname: {rtype: [values]}}``."""

    zone: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    wildcard: Optional[List[str]] = None
    nxdomain: bool = True

    def add(self, host: str, rtype: str, values: List[str]) -> "FakeDNSServer":
        self.zone.setdefault(host.lower(), {}).setdefault(rtype, []).extend(values)
        return self

    def resolve(self, host: str, rtype: str, **kwargs: Any):  # noqa: ANN401
        import dns.resolver

        host = host.lower().rstrip(".")
        records = (self.zone.get(host) or {}).get(rtype)
        if records:
            return FakeAnswer(records)
        if self.wildcard and rtype in ("A", "AAAA", "CNAME") and host.split(".")[0]:
            # Simulate a wildcard: any non-existent label resolves.
            if host not in self.zone:
                return FakeAnswer(self.wildcard)
        if self.nxdomain:
            raise dns.resolver.NXDOMAIN(f"no record for {host}")
        raise dns.resolver.NoAnswer()


@pytest.fixture()
def fake_dns():
    """Return a fresh :class:`FakeDNSServer` factory."""
    return FakeDNSServer()


@pytest.fixture()
def patch_dns(monkeypatch):
    """Patch ``dns.resolver.Resolver.resolve`` with the provided fake server."""

    def _patch(server: FakeDNSServer):
        monkeypatch.setattr(
            "dns.resolver.Resolver.resolve",
            lambda self, qname, rdtype, **kwargs: server.resolve(str(qname), str(rdtype), **kwargs),
            raising=True,
        )
        return server

    return _patch


# ---------------------------------------------------------------------------
# sample payloads
# ---------------------------------------------------------------------------

CRT_SH_PAYLOAD = [
    {
        "issuer_ca_id": 1,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "api.example.com",
        "name_value": "api.example.com\nwww.example.com\n*.dev.example.com",
        "id": 123,
        "entry_timestamp": "2024-01-12T10:00:00",
        "not_before": "2023-12-01T00:00:00",
        "not_after": "2024-03-01T00:00:00",
    },
    {
        "issuer_ca_id": 1,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "mail.example.com",
        "name_value": "mail.example.com",
        "id": 124,
        "entry_timestamp": "2023-05-02T10:00:00",
        "not_before": "2023-04-01T00:00:00",
        "not_after": "2023-07-01T00:00:00",
    },
]

CERTSPOTTER_PAYLOAD = [
    {
        "id": "abc",
        "dns_names": ["api.example.com", "admin.example.com"],
        "not_before": "2024-02-01T00:00:00Z",
        "not_after": "2024-05-01T00:00:00Z",
    }
]

URLSCAN_PAYLOAD = {
    "results": [
        {"page": {"domain": "portal.example.com"}, "task": {"time": "2024-04-08T12:00:00.000Z"}},
        {"page": {"domain": "api.example.com"}, "task": {"time": "2024-04-09T12:00:00.000Z"}},
        {"page": {"domain": "api.example.com"}, "task": {"time": "2024-04-10T12:00:00.000Z"}},
    ],
    "total": 3,
}

HACKERTARGET_BODY = "\n".join(
    [
        "api.example.com,93.184.216.34",
        "www.example.com,93.184.216.34",
        "dev.example.com,93.184.216.35",
    ]
)

RAPIDDNS_BODY = """
<html><body><table class="table">
<tr><th>Host</th><th>Type</th></tr>
<tr><td><a href="https://cdn.example.com">cdn.example.com</a></td><td>A</td></tr>
<tr><td><a href="https://old.example.com">old.example.com</a></td><td>A</td></tr>
<tr><td><a href="https://evil.com">evil.com</a></td><td>A</td></tr>
</table></body></html>
"""

WAYBACK_PAYLOAD = [
    ["original", "timestamp", "statuscode"],
    ["https://old-api.example.com/", "20230211120000", "200"],
    ["https://www.example.com/", "20250803120000", "200"],
]

COMMONCRAWL_BODY = "\n".join(
    [
        '{"url": "https://blog.example.com/post", "mime": "text/html"}',
        '{"url": "https://shop.example.com/", "mime": "text/html"}',
        "not-json",
    ]
)

OTX_PAYLOAD = {
    "passive_dns": [
        {"hostname": "vpn.example.com", "first": "2022-01-01T00:00:00", "last": "2023-01-01T00:00:00"},
        {"hostname": "api.example.com", "first": "2021-01-01T00:00:00", "last": "2024-01-01T00:00:00"},
    ]
}

BUFFEROVER_PAYLOAD = {
    "FDNS_A": ["93.184.216.34,api.example.com", "93.184.216.35,db.example.com"],
    "RDNS": ["93.184.216.36,backup.example.com"],
}

HTML_BODY = """
<!doctype html>
<html><head>
<title>   Customer   Portal  </title>
<meta name="generator" content="WordPress 6.4">
<script src="/_next/static/chunks/main.js"></script>
</head>
<body><div id="root" data-reactroot>Hello</div></body></html>
"""


@pytest.fixture()
def sample_hosts() -> List[Host]:
    """A small set of hosts used by reporting / scoring tests."""
    return [
        Host(host="api.example.com", domain="example.com", registrable_domain="example.com"),
        Host(host="admin.example.com", domain="example.com", registrable_domain="example.com"),
        Host(host="old.example.com", domain="example.com", registrable_domain="example.com"),
    ]
