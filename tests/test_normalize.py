"""Tests for the hostname normalization pipeline."""

from __future__ import annotations

import pytest

from subdomainx.discovery.normalize import (
    normalize_detailed,
    normalize_host,
    normalize_many,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("api.example.com", "api.example.com"),
        ("HTTPS://API.Example.com:443/", "api.example.com"),
        ("*.API.Example.com.", "api.example.com"),
        ("http://www.example.com/path?x=1#frag", "www.example.com"),
        ("dev.api.example.com", "dev.api.example.com"),
        ("  mail.example.com  ", "mail.example.com"),
        ("mail.example.com.", "mail.example.com"),
        ("api..example..com", "api.example.com"),
        ("//cdn.example.com/assets/app.js", "cdn.example.com"),
        ("api%2Eexample%2Ecom", "api.example.com"),
        ("<admin.example.com>", "admin.example.com"),
        ("vpn.example.com:8443", "vpn.example.com"),
        ("*.dev.example.com", "dev.example.com"),
        ("Ünicode.example.com", "xn--nicode-2ya.example.com"),
        ("münchen.example.de", "xn--mnchen-3ya.example.de"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("a" * 63 + ".example.com", "a" * 63 + ".example.com"),
    ],
)
def test_normalization_accepts_valid_inputs(raw, expected):
    assert normalize_host(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        None,
        "javascript:alert(1)",
        "data:text/html,<h1>x</h1>",
        "file:///etc/passwd",
        "mailto:admin@example.com",
        "localhost",
        "127.0.0.1",
        "169.254.169.254",
        "::1",
        "192.168.1.1",
        "api example.com",
        "api.example.com\\evil.com",
        ".",
        "..",
        "*.",
        "http://",
        "https://:443/",
        "ftp://files.example.com",
        "example com",
        "a" * 300,
        "-bad.example.com",
        "bad-.example.com",
        "example.123",
    ],
)
def test_normalization_rejects_invalid_inputs(raw):
    assert normalize_host(raw) is None


def test_wildcard_and_port_notes():
    host, notes = normalize_detailed("HTTPS://*.API.Example.com:443/path")
    assert host == "api.example.com"
    assert any("wildcard" in note for note in notes)
    assert any("port" in note for note in notes)


def test_scheme_rejection_is_reported():
    host, notes = normalize_detailed("javascript:alert(1)")
    assert host is None
    assert any("javascript" in note for note in notes)


def test_normalize_many_deduplicates_and_preserves_order():
    values = [
        "HTTPS://API.Example.com:443/",
        "api.example.com",
        "*.api.example.com.",
        "www.example.com",
        "javascript:alert(1)",
        "evil.com",
    ]
    # "evil.com" is syntactically valid - scope filtering happens later.
    assert normalize_many(values) == ["api.example.com", "www.example.com", "evil.com"]


def test_null_bytes_and_control_characters_are_stripped():
    assert normalize_host("api.example.com\x00") == "api.example.com"
    assert normalize_host("api\n.example.com") is None


def test_bytes_input_is_decoded():
    assert normalize_host(b"cdn.example.com") == "cdn.example.com"


def test_non_string_types_are_rejected():
    assert normalize_host(12345) is None
    assert normalize_host(["api.example.com"]) is None


def test_idna_uppercase_and_nfkc():
    assert normalize_host("ＢＩＧ.example.com") == "big.example.com"
