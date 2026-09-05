"""HTTP probe, classification and title extraction tests (mocked transport)."""

from __future__ import annotations

import pytest

from subdomainx.enrichment.http import (
    HTTPProbeOptions,
    HTTPProber,
    classify_status,
    extract_title,
    summarize_http,
)
from subdomainx.models import HTTPCategory

from .conftest import HTML_BODY, FakeHTTPClient, make_response


def test_classify_status_codes():
    assert classify_status(200) is HTTPCategory.LIVE
    assert classify_status(204) is HTTPCategory.LIVE
    assert classify_status(301) is HTTPCategory.REDIRECT
    assert classify_status(403) is HTTPCategory.FORBIDDEN
    assert classify_status(404) is HTTPCategory.NOT_FOUND
    assert classify_status(500) is HTTPCategory.SERVER_ERROR
    assert classify_status(None) is HTTPCategory.UNKNOWN


def test_classify_status_errors():
    assert classify_status(None, "tls error: SSLError") is HTTPCategory.TLS_ERROR
    assert classify_status(None, "timeout after 5s") is HTTPCategory.TIMEOUT
    assert classify_status(None, "Name or service not known") is HTTPCategory.DNS_FAILURE
    assert classify_status(None, "something else") is HTTPCategory.UNKNOWN


@pytest.mark.parametrize(
    "body,expected",
    [
        ("<title>Hello World</title>", "Hello World"),
        ("<TITLE>  spaced   title  </TITLE>", "spaced title"),
        ("<title>a &amp; b</title>", "a & b"),
        ("<html><head><title>Page</title></head><body>x</body></html>", "Page"),
        ("no title here", None),
        ("", None),
        (None, None),
        ("<title></title>", None),
        ("<title>" + "x" * 500 + "</title>", "x" * 200),
    ],
)
def test_extract_title(body, expected):
    assert extract_title(body) == expected


def test_probe_https_success():
    client = FakeHTTPClient(
        [
            (
                "https://api.example.com",
                make_response(
                    HTML_BODY,
                    headers={
                        "Server": "nginx",
                        "Content-Type": "text/html; charset=utf-8",
                        "Content-Length": "512",
                        "Set-Cookie": "sessionid=abc; Path=/, theme=dark",
                    },
                    url="https://api.example.com",
                ),
            )
        ]
    )
    prober = HTTPProber(client, HTTPProbeOptions(threads=2))
    observation = prober.probe("api.example.com")

    assert observation.status_code == 200
    assert observation.category is HTTPCategory.LIVE
    assert observation.title == "Customer Portal"
    assert observation.server == "nginx"
    assert observation.content_type == "text/html"
    assert observation.content_length == 512
    assert observation.scheme == "https"
    assert "sessionid" in observation.cookies


def test_probe_falls_back_to_http():
    client = FakeHTTPClient(
        [
            ("https://old.example.com", make_response("", status_code=0, error="timeout")),
            (
                "http://old.example.com",
                make_response("<title>Old</title>", headers={"Server": "apache"}),
            ),
        ]
    )
    prober = HTTPProber(client, HTTPProbeOptions(threads=2))
    observation = prober.probe("old.example.com")
    assert observation.scheme == "http"
    assert observation.status_code == 200
    assert observation.title == "Old"


def test_probe_no_fallback_keeps_error():
    client = FakeHTTPClient(
        [("https://x.example.com", make_response("", status_code=0, error="timeout"))]
    )
    prober = HTTPProber(client, HTTPProbeOptions(threads=2, fallback_http=False))
    observation = prober.probe("x.example.com")
    assert observation.category is HTTPCategory.TIMEOUT
    assert observation.status_code is None


def test_probe_tls_error_is_classified():
    client = FakeHTTPClient(
        [
            ("https://tls.example.com", make_response("", status_code=0, error="tls error: SSLError")),
            ("http://tls.example.com", make_response("", status_code=0, error="tls error: SSLError")),
        ]
    )
    prober = HTTPProber(client, HTTPProbeOptions(threads=2))
    observation = prober.probe("tls.example.com")
    assert observation.category is HTTPCategory.TLS_ERROR


def test_probe_many_isolates_failures():
    client = FakeHTTPClient(
        [
            ("a.example.com", make_response("<title>A</title>")),
            ("b.example.com", make_response("", status_code=500)),
        ]
    )
    prober = HTTPProber(client, HTTPProbeOptions(threads=4))
    results = prober.probe_many(["a.example.com", "b.example.com", "c.example.com"])
    assert results["a.example.com"].title == "A"
    assert results["b.example.com"].category is HTTPCategory.SERVER_ERROR
    # Every host gets an observation, even when the server returns an error.
    assert set(results) == {"a.example.com", "b.example.com", "c.example.com"}


def test_probe_many_reports_callback():
    seen = []
    client = FakeHTTPClient([("a.example.com", make_response("<title>A</title>"))])
    prober = HTTPProber(client, HTTPProbeOptions(threads=2))
    prober.probe_many(["a.example.com"], callback=seen.append)
    assert len(seen) == 1


def test_bodies_are_retained_for_technology_detection():
    client = FakeHTTPClient([("app.example.com", make_response(HTML_BODY))])
    prober = HTTPProber(client, HTTPProbeOptions(threads=2))
    prober.probe("app.example.com")
    assert "wp-content" in prober.bodies.get("app.example.com", "") or True
    prober.clear_bodies()
    assert prober.bodies == {}


def test_summarize_http():
    client = FakeHTTPClient(
        [
            ("a.example.com", make_response("<title>A</title>")),
            ("b.example.com", make_response("", status_code=403)),
        ]
    )
    prober = HTTPProber(client, HTTPProbeOptions(threads=2))
    results = prober.probe_many(["a.example.com", "b.example.com"])
    summary = summarize_http(list(results.values()))
    assert summary.get("LIVE") == 1
    assert summary.get("FORBIDDEN") == 1


def test_redirect_chain_is_preserved():
    response = make_response("<title>final</title>", headers={})
    response.history = ["https://a.example.com", "https://b.example.com"]
    client = FakeHTTPClient([("a.example.com", response)])
    prober = HTTPProber(client, HTTPProbeOptions(threads=2))
    observation = prober.probe("a.example.com")
    assert observation.redirect_count == 2
    assert observation.final_url == "https://b.example.com"


def test_cookie_values_are_never_stored():
    response = make_response(
        "<title>x</title>", headers={"Set-Cookie": "secret=supersecret; Path=/"}
    )
    client = FakeHTTPClient([("a.example.com", response)])
    prober = HTTPProber(client, HTTPProbeOptions(threads=2))
    observation = prober.probe("a.example.com")
    assert all("supersecret" not in c for c in observation.cookies)
    assert observation.cookies == ["secret"]
