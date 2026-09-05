"""Scope enforcement and hostname validation tests."""

from __future__ import annotations

import pytest

from subdomainx.discovery.validate import (
    ExclusionMatcher,
    ScopeMatcher,
    filter_hosts,
    is_in_scope,
    is_valid_hostname,
    registrable_domain,
)


@pytest.mark.parametrize("host", ["example.com", "www.example.com", "dev.api.example.com"])
def test_in_scope_hosts(host):
    assert is_in_scope(host, "example.com") is True


@pytest.mark.parametrize(
    "host",
    [
        "example.com.evil.com",
        "evil-example.com",
        "example.org",
        "fooexample.com",
        "notexample.com",
        "example.com.attacker.net",
        "localhost",
        "127.0.0.1",
    ],
)
def test_out_of_scope_hosts(host):
    assert is_in_scope(host, "example.com") is False


@pytest.mark.parametrize(
    "host,domain,expected",
    [
        ("www.example.co.uk", "example.co.uk", True),
        ("api.example.com.au", "example.com.au", True),
        ("shop.example.co.in", "example.co.in", True),
        ("www.example.org.uk", "example.org.uk", True),
        ("evil.co.uk", "example.co.uk", False),
        ("example.co.uk.attacker.com", "example.co.uk", False),
        ("a.b.c.example.co.uk", "example.co.uk", True),
    ],
)
def test_multi_part_suffixes(host, domain, expected):
    assert is_in_scope(host, domain) is expected


@pytest.mark.parametrize(
    "host,expected",
    [
        ("example.com", "example.com"),
        ("www.example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("x.example.com.au", "example.com.au"),
        ("deep.nested.example.co.in", "example.co.in"),
        ("example.com.evil.com", "evil.com"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize(
    "host,expected",
    [
        ("example.com", True),
        ("a-b.example.com", True),
        ("_dmarc.example.com", True),
        ("api.example.com.", True),
        ("example", False),
        ("-example.com", False),
        ("example..com", False),
        ("example.123", False),
        ("192.168.0.1", False),
        ("localhost", False),
        ("a" * 64 + ".com", False),
        ("", False),
        (None, False),
    ],
)
def test_is_valid_hostname(host, expected):
    assert is_valid_hostname(host) is expected


def test_scope_matcher_wildcards():
    scope = ScopeMatcher(["*.example.com", "api.other.com"])
    assert scope.matches("www.example.com") is True
    assert scope.matches("example.com") is False
    assert scope.matches("api.other.com") is True
    assert scope.matches("evil.com") is False


def test_scope_matcher_prefix_dot():
    scope = ScopeMatcher([".example.com"])
    assert scope.matches("a.example.com") is True
    assert scope.matches("example.com") is False


def test_scope_matcher_empty_allows_everything():
    assert ScopeMatcher().matches("anything.example.com") is True


def test_exclusion_matcher():
    exclude = ExclusionMatcher(["tracking.example.com", "*.ads.example.com", "re:^cdn\\d"])
    assert exclude.matches("tracking.example.com") is True
    assert exclude.matches("a.ads.example.com") is True
    assert exclude.matches("cdn12.example.com") is True
    assert exclude.matches("api.example.com") is False


def test_filter_hosts_combines_everything():
    hosts = [
        "api.example.com",
        "dev.example.com",
        "tracking.example.com",
        "example.com.evil.com",
        "portal.example.com",
    ]
    scope = ScopeMatcher(["*.example.com"])
    exclude = ExclusionMatcher(["tracking.example.com"])
    import re

    kept = filter_hosts(hosts, "example.com", scope, exclude, re.compile(r"api|portal"), None)
    assert kept == ["api.example.com", "portal.example.com"]


def test_filter_hosts_exclude_regex():
    import re

    hosts = ["api.example.com", "cdn.example.com", "static.example.com"]
    kept = filter_hosts(hosts, "example.com", None, None, None, re.compile(r"cdn|static"))
    assert kept == ["api.example.com"]


def test_read_pattern_file_ignores_comments(tmp_path):
    path = tmp_path / "scope.txt"
    path.write_text("# comment\n*.example.com\n\napi.example.com\n", encoding="utf-8")
    from subdomainx.discovery.validate import read_pattern_file

    assert read_pattern_file(str(path)) == ["*.example.com", "api.example.com"]
