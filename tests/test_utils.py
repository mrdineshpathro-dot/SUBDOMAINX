"""Tests for the shared HTTP layer, logging helpers and small utilities."""

from __future__ import annotations

import logging
import time

import requests

from subdomainx.utils.helpers import (
    clean_text,
    collapse_whitespace,
    humanize_count,
    random_hostnames,
    random_label,
    sha256,
    truncate,
    unique,
)
from subdomainx.utils.http import HTTPClient, HTTPResponse, RateLimiter, build_headers
from subdomainx.utils.logging import JSONFormatter, get_logger, setup_logging


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def test_clean_text_removes_control_characters():
    # Null bytes are dropped, other control characters become spaces.
    assert clean_text("a\x00b\nc") == "ab c"


def test_clean_text_truncates():
    assert clean_text("x" * 100, limit=10).endswith("…")


def test_collapse_whitespace():
    assert collapse_whitespace("  a   b \t c ") == "a b c"


def test_random_label_is_dns_safe():
    label = random_label(12)
    assert len(label) == 12
    assert label[0].isalpha()
    assert label.isalnum()


def test_random_hostnames():
    hosts = random_hostnames("example.com", 3)
    assert len(hosts) == 3
    assert all(h.endswith(".example.com") for h in hosts)


def test_sha256_is_stable():
    assert sha256("a") == sha256("a")
    assert sha256("a") != sha256("b")


def test_truncate():
    assert truncate("abcdef", 3) == "ab…"
    assert truncate("abc", 10) == "abc"
    assert truncate(None, 3) == ""


def test_unique_preserves_order():
    assert unique([3, 1, 3, 2, 1]) == [3, 1, 2]


def test_humanize_count():
    assert humanize_count(999) == "999"
    assert humanize_count(1500) == "1.5k"


def test_build_headers_identifies_the_tool():
    headers = build_headers({"Accept": "application/json"})
    assert headers["Accept"] == "application/json"
    assert "SubdomainX" in headers["User-Agent"]


# ---------------------------------------------------------------------------
# HTTPResponse
# ---------------------------------------------------------------------------


def test_response_ok_and_json():
    response = HTTPResponse(url="https://x", status_code=200, text='{"a": 1}')
    assert response.ok is True
    assert response.json() == {"a": 1}


def test_response_json_failure_returns_none():
    assert HTTPResponse(url="x", text="not json").json() is None


def test_response_rate_limited_flag():
    assert HTTPResponse(url="x", status_code=429).rate_limited is True
    assert HTTPResponse(url="x", status_code=503).rate_limited is True
    assert HTTPResponse(url="x", status_code=200).rate_limited is False


# ---------------------------------------------------------------------------
# HTTPClient (using a stubbed transport)
# ---------------------------------------------------------------------------


class _FakeSession:
    """Minimal stand-in for ``requests.Session`` used to exercise HTTPClient."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False
        self.headers = {}

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        item = self.responses.pop(0) if self.responses else None
        if isinstance(item, Exception):
            raise item
        return item

    def close(self):
        self.closed = True


class _FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self._text = text
        self.headers = headers or {"Content-Type": "application/json"}
        self.encoding = "utf-8"
        self.apparent_encoding = None
        self.history = []

    def iter_content(self, chunk_size=8192):
        yield self._text.encode("utf-8")

    def close(self):
        return None


def _client_with(responses, **kwargs) -> tuple:
    client = HTTPClient(**kwargs)
    session = _FakeSession(responses)
    client.session = session
    return client, session


def test_client_returns_parsed_response():
    client, session = _client_with([_FakeResponse(200, '{"ok": true}')])
    response = client.get("https://example.test/x")
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_client_retries_on_server_error():
    client, session = _client_with(
        [
            _FakeResponse(503, "busy"),
            _FakeResponse(200, "ok"),
        ],
        retries=2,
        backoff=0.01,
    )
    response = client.get("https://example.test/x")
    assert response.status_code == 200
    assert len(session.calls) == 2


def test_client_stops_after_retries():
    client, session = _client_with(
        [_FakeResponse(500, "err"), _FakeResponse(500, "err"), _FakeResponse(500, "err")],
        retries=1,
        backoff=0.01,
    )
    response = client.get("https://example.test/x")
    assert response.error == "HTTP 500"
    assert response.attempts == 2


def test_client_does_not_retry_tls_errors():
    client, session = _client_with(
        [requests.exceptions.SSLError("bad cert"), _FakeResponse(200, "ok")],
        retries=3,
        backoff=0.01,
    )
    response = client.get("https://example.test/x")
    assert "tls error" in (response.error or "")
    assert len(session.calls) == 1


def test_client_handles_timeout():
    client, session = _client_with(
        [requests.exceptions.Timeout(), _FakeResponse(200, "ok")], retries=1, backoff=0.01
    )
    response = client.get("https://example.test/x")
    assert response.status_code == 200


def test_client_validates_content_type():
    client, session = _client_with([_FakeResponse(200, "<html>", headers={"Content-Type": "text/html"})])
    response = client.get("https://example.test/x", allowed_content_types=["application/json"])
    assert "unexpected content-type" in (response.error or "")


def test_client_limits_body_size(monkeypatch):
    class BigResponse(_FakeResponse):
        def iter_content(self, chunk_size=8192):
            yield b"a" * 100
            yield b"b" * 100

    client, session = _client_with([BigResponse(200)])
    response = client.get("https://example.test/x", max_body_size=50)
    assert len(response.text) == 50
    assert response.truncated is True


def test_client_strips_null_bytes():
    class NullResponse(_FakeResponse):
        def iter_content(self, chunk_size=8192):
            yield b"a\x00b"

    client, _ = _client_with([NullResponse(200)])
    response = client.get("https://example.test/x")
    assert response.text == "ab"


def test_client_uses_cache_on_second_call(tmp_path):
    from subdomainx.storage.cache import ResponseCache

    cache = ResponseCache(root=str(tmp_path / ".cache"))
    client, session = _client_with([_FakeResponse(200, "hello")], cache=cache)
    first = client.get("https://example.test/x")
    second = client.get("https://example.test/x")
    assert first.from_cache is False
    assert second.from_cache is True
    assert len(session.calls) == 1


def test_client_close_closes_session():
    client, session = _client_with([])
    client.close()
    assert session.closed is True


def test_client_never_raises_on_unexpected_errors():
    client, session = _client_with([ValueError("kaboom")], retries=1)
    response = client.get("https://example.test/x")
    assert "kaboom" in (response.error or "")


# ---------------------------------------------------------------------------
# rate limiter
# ---------------------------------------------------------------------------


def test_rate_limiter_waits():
    limiter = RateLimiter(0.05)
    started = time.monotonic()
    limiter.wait("a")
    limiter.wait("a")
    assert time.monotonic() - started >= 0.04


def test_rate_limiter_zero_is_noop():
    limiter = RateLimiter(0)
    started = time.monotonic()
    limiter.wait("a")
    assert time.monotonic() - started < 0.01


# ---------------------------------------------------------------------------
# logging
# ---------------------------------------------------------------------------


def test_setup_logging_text_and_json(capsys):
    logger = setup_logging(level="INFO", json_format=False, color=False)
    logger.info("plain message")
    assert "plain message" in capsys.readouterr().err

    logger = setup_logging(level="DEBUG", json_format=True)
    logger.info("json message")
    import json

    record = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert record["message"] == "json message"
    assert record["level"] == "INFO"


def test_json_formatter_handles_exceptions():
    formatter = JSONFormatter()
    import sys

    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.LogRecord(
            "x", logging.ERROR, "f", 1, "failed", None, sys.exc_info()
        )
    payload = formatter.format(record)
    assert "boom" in payload


def test_quiet_logging_suppresses_info(capsys):
    logger = setup_logging(level="INFO", quiet=True)
    logger.info("hidden")
    assert "hidden" not in capsys.readouterr().err


def test_log_with_structured_fields(capsys):
    from subdomainx.utils.logging import log_with

    logger = setup_logging(level="INFO", json_format=True)
    log_with(logger, logging.INFO, "source completed", source="crtsh", results=12)
    import json

    record = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert record["source"] == "crtsh"
    assert record["results"] == 12


def test_get_logger_is_idempotent():
    assert get_logger() is get_logger()
