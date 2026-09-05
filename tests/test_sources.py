"""Tests for the passive source adapters (fully mocked, no network)."""

from __future__ import annotations

import json

from subdomainx.models import SourceStatus
from subdomainx.sources.base import PassiveSource
from subdomainx.sources.registry import build_registry, filter_sources, get_source, iter_source_classes

from .conftest import (
    BUFFEROVER_PAYLOAD,
    CERTSPOTTER_PAYLOAD,
    COMMONCRAWL_BODY,
    CRT_SH_PAYLOAD,
    HACKERTARGET_BODY,
    OTX_PAYLOAD,
    RAPIDDNS_BODY,
    URLSCAN_PAYLOAD,
    WAYBACK_PAYLOAD,
    FakeHTTPClient,
    make_response,
)


def _client(routes):
    return FakeHTTPClient(routes)


# ---------------------------------------------------------------------------
# crt.sh
# ---------------------------------------------------------------------------


def test_crtsh_parses_certificate_records():
    from subdomainx.sources.crtsh import CrtShSource

    client = _client([("crt.sh", make_response(json.dumps(CRT_SH_PAYLOAD)))])
    source = CrtShSource(http=client)
    result = source.run("example.com")

    assert result.status is SourceStatus.ONLINE
    hosts = set(result.observations)
    assert hosts == {"api.example.com", "www.example.com", "dev.example.com", "mail.example.com"}
    assert result.observations["api.example.com"].first_seen == "2023-12-01"
    assert result.observations["api.example.com"].last_seen == "2024-01-12"
    assert result.history["mail.example.com"].first_seen == "2023-04-01"


def test_crtsh_handles_invalid_json():
    from subdomainx.sources.crtsh import CrtShSource

    client = _client([("crt.sh", make_response("<html>gateway timeout</html>"))])
    source = CrtShSource(http=client)
    result = source.run("example.com")
    assert result.status is SourceStatus.FAILED
    assert "parser failure" in (result.error or "").lower()


def test_crtsh_handles_empty_payload():
    from subdomainx.sources.crtsh import CrtShSource

    client = _client([("crt.sh", make_response(""))])
    result = CrtShSource(http=client).run("example.com")
    assert result.status is SourceStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# certspotter / urlscan / otx / bufferover
# ---------------------------------------------------------------------------


def test_certspotter_expands_dns_names():
    from subdomainx.sources.certspotter import CertSpotterSource

    client = _client([("certspotter", make_response(json.dumps(CERTSPOTTER_PAYLOAD)))])
    result = CertSpotterSource(http=client).run("example.com")
    assert set(result.observations) == {"api.example.com", "admin.example.com"}


def test_urlscan_reads_page_domains():
    from subdomainx.sources.urlscan import URLScanSource

    client = _client([("urlscan.io", make_response(json.dumps(URLSCAN_PAYLOAD)))])
    result = URLScanSource(http=client).run("example.com")
    assert set(result.observations) == {"portal.example.com", "api.example.com"}
    assert result.observations["api.example.com"].count == 2
    assert result.observations["api.example.com"].first_seen.startswith("2024-04-09")


def test_otx_records_first_and_last_seen():
    from subdomainx.sources.otx import OTXSource

    client = _client([("alienvault", make_response(json.dumps(OTX_PAYLOAD)))])
    result = OTXSource(http=client).run("example.com")
    assert result.observations["vpn.example.com"].first_seen == "2022-01-01"
    assert result.observations["vpn.example.com"].last_seen == "2023-01-01"


def test_bufferover_handles_ip_host_pairs():
    from subdomainx.sources.bufferover import BufferOverSource

    client = _client([("bufferover", make_response(json.dumps(BUFFEROVER_PAYLOAD)))])
    result = BufferOverSource(http=client).run("example.com")
    assert set(result.observations) == {"api.example.com", "db.example.com", "backup.example.com"}


def test_bufferover_reports_upstream_error():
    from subdomainx.sources.bufferover import BufferOverSource

    client = _client([("bufferover", make_response(json.dumps({"Error": "rate limited"})))])
    result = BufferOverSource(http=client).run("example.com")
    assert result.status is SourceStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# hackertarget / rapiddns
# ---------------------------------------------------------------------------


def test_hackertarget_parses_csv():
    from subdomainx.sources.hackertarget import HackerTargetSource

    client = _client([("hackertarget", make_response(HACKERTARGET_BODY))])
    result = HackerTargetSource(http=client).run("example.com")
    assert set(result.observations) == {"api.example.com", "www.example.com", "dev.example.com"}


def test_hackertarget_detects_quota_error():
    from subdomainx.sources.hackertarget import HackerTargetSource

    client = _client([("hackertarget", make_response("API count exceeded - Increase Quota"))])
    result = HackerTargetSource(http=client).run("example.com")
    assert result.status is SourceStatus.UNAVAILABLE
    assert "count exceeded" in result.error


def test_rapiddns_scrapes_table():
    from subdomainx.sources.rapiddns import RapidDNSSource

    client = _client([("rapiddns.io", make_response(RAPIDDNS_BODY))])
    result = RapidDNSSource(http=client).run("example.com")
    assert "cdn.example.com" in result.observations
    assert "old.example.com" in result.observations


def test_rapiddns_without_table_is_unavailable():
    from subdomainx.sources.rapiddns import RapidDNSSource

    client = _client([("rapiddns.io", make_response("<html><body>blocked</body></html>"))])
    result = RapidDNSSource(http=client).run("example.com")
    assert result.status is SourceStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# archive sources
# ---------------------------------------------------------------------------


def test_wayback_parses_cdx_rows():
    from subdomainx.sources.wayback import WaybackSource

    routes = [
        ("web.archive.org", make_response(json.dumps(WAYBACK_PAYLOAD))),
    ]
    client = _client(routes)
    result = WaybackSource(http=client).run("example.com")
    assert set(result.observations) == {"old-api.example.com", "www.example.com"}
    assert result.history["old-api.example.com"].first_seen == "2023-02-11"


def test_wayback_without_rows_is_unavailable():
    from subdomainx.sources.wayback import WaybackSource

    client = _client([("web.archive.org", make_response("[]"))])
    result = WaybackSource(http=client).run("example.com")
    assert result.status is SourceStatus.UNAVAILABLE


def test_commoncrawl_uses_latest_collection():
    from subdomainx.sources.commoncrawl import CommonCrawlSource

    collinfo = [{"id": "CC-MAIN-2025-33", "name": "Aug 2025"}, {"id": "CC-MAIN-2025-30"}]
    client = _client(
        [
            ("collinfo.json", make_response(json.dumps(collinfo))),
            ("CC-MAIN-2025-33-index", make_response(COMMONCRAWL_BODY)),
        ]
    )
    result = CommonCrawlSource(http=client).run("example.com")
    assert set(result.observations) == {"blog.example.com", "shop.example.com"}


# ---------------------------------------------------------------------------
# failure isolation & registry
# ---------------------------------------------------------------------------


class ExplodingSource(PassiveSource):
    name = "exploding"
    description = "always raises"

    def discover(self, domain):
        raise RuntimeError("boom")


class RateLimitedSource(PassiveSource):
    name = "ratelimited"
    description = "always rate limited"

    def discover(self, domain):
        from subdomainx.sources.base import RateLimitedError

        raise RateLimitedError("HTTP 429")


def test_source_failure_is_isolated():
    result = ExplodingSource(http=_client([])).run("example.com")
    assert result.status is SourceStatus.FAILED
    assert "boom" in (result.error or "")
    assert result.observations == {}


def test_rate_limited_source_is_recorded():
    source = RateLimitedSource(http=_client([]))
    result = source.run("example.com")
    assert result.status is SourceStatus.RATE_LIMITED
    assert source.health.rate_limit_events == 1


def test_source_without_http_client_is_unavailable():
    result = ExplodingSource(http=None).run("example.com")
    assert result.status is SourceStatus.FAILED


def test_health_tracking_accumulates():
    from subdomainx.sources.crtsh import CrtShSource

    client = _client([("crt.sh", make_response(json.dumps(CRT_SH_PAYLOAD)))])
    source = CrtShSource(http=client)
    source.run("example.com")
    source.run("example.com")
    assert source.health.success_count == 2
    assert source.health.results == 8
    assert source.health.last_success_at


def test_registry_discovers_all_modules():
    classes = iter_source_classes()
    assert "crtsh" in classes
    assert "wayback" in classes
    assert len(classes) >= 12


def test_registry_marks_key_required_sources_disabled():
    sources = build_registry()
    names = {s.name for s in sources}
    assert "virustotal" in names
    vt = get_source("virustotal", sources)
    assert vt.requires_api_key is True
    assert vt.enabled is False
    result = vt.run("example.com")
    assert result.status is SourceStatus.UNSUPPORTED


def test_filter_sources_by_name():
    sources = build_registry()
    selected = filter_sources(sources, "crtsh, urlscan")
    assert {s.name for s in selected} == {"crtsh", "urlscan"}


def test_filter_sources_unknown_name_warns():
    sources = build_registry()
    selected = filter_sources(sources, ["crtsh", "does-not-exist"])
    assert {s.name for s in selected} == {"crtsh"}


def test_filter_sources_all_excludes_keyed_sources():
    sources = build_registry()
    selected = filter_sources(sources, "all")
    assert all(not s.requires_api_key for s in selected)


def test_disabled_source_is_not_executed():
    from subdomainx.sources.crtsh import CrtShSource

    source = CrtShSource(http=_client([]), enabled=False)
    result = source.run("example.com")
    assert result.status is SourceStatus.DISABLED


def test_parser_errors_are_counted():
    from subdomainx.sources.crtsh import CrtShSource

    client = _client([("crt.sh", make_response("{not json"))])
    source = CrtShSource(http=client)
    source.run("example.com")
    assert source.health.error_count == 1
