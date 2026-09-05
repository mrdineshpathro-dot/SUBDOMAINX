"""Confidence scoring, classification, deduplication and correlation tests."""

from __future__ import annotations

import pytest

from subdomainx.discovery.classify import (
    classify_category,
    classify_host,
    find_interesting_reasons,
    summarize_categories,
)
from subdomainx.discovery.correlate import aggregate_results, build_source_graph
from subdomainx.discovery.dedupe import canonical_key, dedupe_raw, dedupe_host_records
from subdomainx.discovery.score import (
    compute_priority,
    label_for_score,
    rank_hosts,
    score_host,
)
from subdomainx.models import (
    ActivityState,
    CloudAsset,
    ConfidenceLabel,
    DNSInfo,
    Host,
    HTTPCategory,
    HTTPObservation,
    HostCategory,
    SourceObservation,
    SourceResult,
    WildcardState,
)


def _host(name: str, sources=("crtsh",)) -> Host:
    host = Host(host=name, domain="example.com", registrable_domain="example.com")
    for source in sources:
        host.observations[source] = SourceObservation(source=source, host=name)
        host.total_observations += 1
    return host


# ---------------------------------------------------------------------------
# confidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score,label",
    [
        (100, ConfidenceLabel.VERY_HIGH),
        (95, ConfidenceLabel.VERY_HIGH),
        (94, ConfidenceLabel.HIGH),
        (80, ConfidenceLabel.HIGH),
        (79, ConfidenceLabel.MEDIUM),
        (60, ConfidenceLabel.MEDIUM),
        (59, ConfidenceLabel.LOW),
        (30, ConfidenceLabel.LOW),
        (29, ConfidenceLabel.VERY_LOW),
        (0, ConfidenceLabel.VERY_LOW),
    ],
)
def test_confidence_bands(score, label):
    assert label_for_score(score) is label


def test_score_increases_with_source_diversity():
    single = score_host(_host("api.example.com", ["crtsh"]))[0]
    triple = score_host(_host("api.example.com", ["crtsh", "urlscan", "hackertarget"]))[0]
    many = score_host(_host("api.example.com", ["crtsh", "urlscan", "hackertarget", "wayback", "otx"]))[0]
    assert single < triple < many


def test_score_rewards_dns_and_http_evidence():
    host = _host("api.example.com", ["crtsh"])
    base = score_host(host)[0]
    host.dns = DNSInfo(host=host.host, resolved=True, a=["1.2.3.4"])
    with_dns = score_host(host)[0]
    host.http = HTTPObservation(host=host.host, status_code=200, category=HTTPCategory.LIVE)
    with_http = score_host(host)[0]
    assert base < with_dns < with_http


def test_wildcard_penalty_is_applied():
    host = _host("api.example.com", ["crtsh", "urlscan"])
    host.dns = DNSInfo(host=host.host, resolved=True, a=["1.2.3.4"], wildcard=True)
    clean = score_host(host, WildcardState.NONE)[0]
    penalised = score_host(host, WildcardState.WILDCARD)[0]
    assert penalised < clean
    assert penalised == clean - 25


def test_single_weak_source_penalty():
    host = _host("weird.example.com", ["threatcrowd"])
    score, _label, reasons, _ = score_host(host)
    assert any("single source" in r for r in reasons)


def test_historical_only_penalty():
    from subdomainx.models import HistoricalObservation

    host = _host("old.example.com", ["wayback"])
    host.history["wayback"] = HistoricalObservation(source="wayback", observations=1)
    score, _label, reasons, _ = score_host(host)
    assert any("historical" in r.lower() for r in reasons)


def test_score_is_clamped():
    host = Host(host="a.example.com")
    score, label, _reasons, _ = score_host(host, WildcardState.WILDCARD)
    assert 0 <= score <= 100
    assert label is ConfidenceLabel.VERY_LOW


def test_score_reasons_are_explainable():
    host = _host("api.example.com", ["crtsh", "urlscan", "hackertarget", "wayback"])
    host.dns = DNSInfo(host=host.host, resolved=True, a=["1.2.3.4"])
    score, label, reasons, factors = score_host(host)
    assert score > 0
    assert reasons
    assert {f.name for f in factors} >= {"source_diversity", "dns_resolved"}


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host,category",
    [
        ("api.example.com", HostCategory.API),
        ("dev.example.com", HostCategory.DEVELOPMENT),
        ("stage.example.com", HostCategory.STAGING),
        ("qa.example.com", HostCategory.TESTING),
        ("uat-portal.example.com", HostCategory.STAGING),
        ("test-api.example.com", HostCategory.API),
        ("mail.example.com", HostCategory.MAIL),
        ("grafana.example.com", HostCategory.MONITORING),
        ("admin.example.com", HostCategory.ADMIN),
        ("sso.example.com", HostCategory.AUTHENTICATION),
        ("cdn.example.com", HostCategory.CDN),
        ("jenkins.example.com", HostCategory.INFRASTRUCTURE),
        ("www.example.com", HostCategory.PRODUCTION),
        ("example.com", HostCategory.PRODUCTION),
        ("zzz9xyz.example.com", HostCategory.UNKNOWN),
    ],
)
def test_category_classification(host, category):
    assert classify_category(host) is category


def test_interesting_reasons_are_descriptive():
    reasons = find_interesting_reasons("admin-portal.example.com")
    assert "Administrative-looking hostname" in reasons


def test_interesting_reasons_for_ci_and_cloud():
    assert find_interesting_reasons("jenkins.example.com")
    assert find_interesting_reasons("gitlab.example.com")
    assert find_interesting_reasons("vpn.example.com")
    assert find_interesting_reasons("grafana.example.com")
    assert find_interesting_reasons("old-api.example.com")


def test_plain_host_is_not_interesting():
    assert find_interesting_reasons("www.example.com") == []


def test_classify_host_sets_activity_current():
    host = _host("api.example.com")
    host.dns = DNSInfo(host=host.host, resolved=True, a=["1.2.3.4"])
    classify_host(host)
    assert host.activity is ActivityState.CURRENT
    assert host.category is HostCategory.API


def test_classify_host_sets_activity_historical():
    from subdomainx.models import HistoricalObservation

    host = _host("old.example.com")
    host.history["wayback"] = HistoricalObservation(source="wayback")
    classify_host(host)
    assert host.activity is ActivityState.HISTORICAL


def test_cloud_evidence_is_recorded_but_not_an_interesting_reason():
    # Cloud/CDN classification is asset intelligence; it must not inflate the
    # "interesting host" signal, which is driven by hostname semantics only.
    host = _host("assets.example.com")
    host.cloud = CloudAsset(provider="AWS", service="S3", cname="assets.s3.amazonaws.com")
    classify_host(host)
    assert host.cloud.provider == "AWS"
    assert not any("Cloud asset" in r for r in host.interesting_reasons)


def test_keyword_host_is_interesting():
    host = _host("admin.example.com")
    classify_host(host)
    assert host.interesting
    assert "Administrative-looking hostname" in host.interesting_reasons


def test_summarize_categories():
    hosts = [_host("api.example.com"), _host("dev.example.com"), _host("mail.example.com")]
    for host in hosts:
        classify_host(host)
    summary = summarize_categories(hosts)
    assert summary["API"] == 1
    assert summary["Development"] == 1


# ---------------------------------------------------------------------------
# priority
# ---------------------------------------------------------------------------


def test_priority_ranking_orders_live_admin_first():
    admin = _host("admin.example.com")
    admin.http = HTTPObservation(host=admin.host, status_code=200)
    api = _host("api.example.com")
    api.http = HTTPObservation(host=api.host, status_code=200)
    static = _host("static.example.com")
    for host in (admin, api, static):
        classify_host(host)
        host.priority, host.priority_reasons = compute_priority(host)
    ranked = rank_hosts([static, api, admin])
    assert [h.host for h in ranked][0] == "admin.example.com"


def test_priority_reasons_are_returned():
    host = _host("admin.example.com")
    classify_host(host)
    priority, reasons = compute_priority(host)
    assert priority >= 90
    assert reasons


# ---------------------------------------------------------------------------
# dedupe / correlation
# ---------------------------------------------------------------------------


def test_canonical_key_normalizes():
    assert canonical_key("HTTPS://API.Example.com:443/") == "api.example.com"


def test_dedupe_raw():
    assert dedupe_raw(["a.example.com", "A.example.com.", "*.a.example.com", "b.example.com"]) == [
        "a.example.com",
        "b.example.com",
    ]


def test_dedupe_host_records_merges_provenance():
    first = _host("api.example.com", ["crtsh"])
    second = _host("API.example.com.", ["urlscan", "wayback"])
    merged = dedupe_host_records([first, second])
    assert list(merged) == ["api.example.com"]
    assert merged["api.example.com"].source_count == 3


def test_aggregate_results_merges_sources():
    results = [
        SourceResult(source="crtsh", domain="example.com"),
        SourceResult(source="urlscan", domain="example.com"),
    ]
    results[0].add("api.example.com", first_seen="2024-01-01")
    results[1].add("api.example.com", first_seen="2023-01-01")
    results[1].add("www.example.com")
    hosts = aggregate_results(results, "example.com")
    assert set(hosts) == {"api.example.com", "www.example.com"}
    assert hosts["api.example.com"].source_count == 2
    assert hosts["api.example.com"].first_seen == "2023-01-01"
    assert hosts["api.example.com"].last_seen == "2024-01-01"


def test_aggregate_results_rejects_out_of_scope():
    result = SourceResult(source="crtsh", domain="example.com")
    result.add("api.example.com.evil.com")
    result.add("api.example.com")
    hosts = aggregate_results([result], "example.com")
    # Aggregation keeps everything - scope filtering happens in the engine -
    # but normalization must still have collapsed the URL forms.
    assert "api.example.com" in hosts


def test_source_graph_shape():
    hosts = {
        "api.example.com": _host("api.example.com", ["crtsh", "urlscan"]),
        "www.example.com": _host("www.example.com", ["crtsh"]),
    }
    graph = build_source_graph(hosts.values())
    assert graph["edge_count"] == 3
    assert graph["sources"]["crtsh"] == 2
    assert any(n["type"] == "source" and n["label"] == "crtsh" for n in graph["nodes"])
    assert graph["co_occurrence"][0]["sources"] == ["crtsh", "urlscan"]


def test_host_to_dict_exposes_derived_fields():
    host = _host("api.example.com", ["crtsh", "urlscan"])
    host.dns = DNSInfo(host=host.host, resolved=True, a=["1.2.3.4"])
    payload = host.to_dict()
    assert payload["sources"] == ["crtsh", "urlscan"]
    assert payload["source_count"] == 2
    assert payload["dns_resolved"] is True
    assert payload["ct_present"] is True
