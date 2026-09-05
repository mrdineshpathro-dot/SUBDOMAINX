"""Technology, CDN, cloud, TLS, ASN and cache module tests (no network)."""

from __future__ import annotations

import time

import pytest

from subdomainx.enrichment.asn import ASNEnricher, _is_public_ip
from subdomainx.enrichment.cdn import classify_cdn, summarize_cdn
from subdomainx.enrichment.cloud import detect_cloud_asset, summarize_cloud
from subdomainx.enrichment.technology import detect_technologies, technologies_from_dns
from subdomainx.enrichment.tls import certificate_matches_host, parse_certificate
from subdomainx.models import (
    CDNConfidence,
    CloudAsset,
    DNSInfo,
    HTTPObservation,
    TLSInfo,
)
from subdomainx.storage.cache import ResponseCache

from .conftest import FakeHTTPClient, make_response


def _observation(headers=None, cookies=None, status=200) -> HTTPObservation:
    return HTTPObservation(
        host="app.example.com",
        status_code=status,
        headers=headers or {},
        cookies=cookies or [],
    )


# ---------------------------------------------------------------------------
# technology
# ---------------------------------------------------------------------------


def test_detect_web_server_from_headers():
    found = detect_technologies(_observation({"Server": "nginx/1.24"}))
    assert "nginx" in [t.name for t in found]


def test_detect_cloudflare_from_headers():
    found = detect_technologies(_observation({"CF-RAY": "abc-LHR", "Server": "cloudflare"}))
    names = {t.name for t in found}
    assert "Cloudflare" in names


def test_detect_wordpress_and_nextjs_from_body():
    body = '<html><head><meta name="generator" content="WordPress 6.4"></head>' '<script src="/_next/static/x.js"></script></html>'
    found = detect_technologies(_observation(), body=body)
    names = {t.name for t in found}
    assert "WordPress" in names
    assert "Next.js" in names


def test_detect_framework_from_cookies():
    found = detect_technologies(_observation(cookies=["laravel_session", "XSRF-TOKEN"]))
    assert "Laravel" in [t.name for t in found]


def test_detect_returns_empty_without_observation():
    assert detect_technologies(None) == []


def test_technologies_are_sorted_by_confidence():
    found = detect_technologies(_observation({"Server": "nginx", "X-Powered-By": "PHP/8.2"}))
    assert found[0].confidence >= found[-1].confidence


def test_technology_evidence_is_recorded():
    found = detect_technologies(_observation({"Server": "nginx"}))
    nginx = next(t for t in found if t.name == "nginx")
    assert "server" in nginx.evidence.lower()


def test_technologies_from_cname():
    found = technologies_from_dns(["d123.cloudfront.net", "x.amazonaws.com"])
    names = {t.name for t in found}
    assert "CloudFront" in names
    assert "AWS" in names


# ---------------------------------------------------------------------------
# CDN
# ---------------------------------------------------------------------------


def test_cdn_from_cname():
    dns = DNSInfo(host="www.example.com", cname=["www.example.com.cdn.cloudflare.net"])
    classification = classify_cdn("www.example.com", dns)
    assert classification.provider == "Cloudflare"
    assert classification.confidence is CDNConfidence.CONFIRMED


def test_cdn_from_headers():
    http = _observation({"CF-RAY": "1"})
    classification = classify_cdn("www.example.com", None, http)
    assert classification.provider == "Cloudflare"
    assert classification.confidence is CDNConfidence.CONFIRMED


def test_cdn_from_azure_front_door():
    dns = DNSInfo(host="a.example.com", cname=["a.azurefd.net"])
    assert classify_cdn("a.example.com", dns).provider == "Azure Front Door"


def test_cdn_none_without_evidence():
    classification = classify_cdn("a.example.com", DNSInfo(host="a.example.com"))
    assert classification.provider is None
    assert classification.confidence is CDNConfidence.NONE


def test_cdn_possible_generic_cache_header():
    http = _observation({"X-Cache": "HIT"})
    classification = classify_cdn("a.example.com", None, http)
    assert classification.confidence is CDNConfidence.POSSIBLE


def test_summarize_cdn():
    summary = summarize_cdn(
        {
            "a": classify_cdn("a", None, _observation({"CF-RAY": "1"})),
            "b": classify_cdn("b", DNSInfo(host="b", cname=["x.fastly.net"])),
        }
    )
    assert summary == {"Cloudflare": 1, "Fastly": 1}


# ---------------------------------------------------------------------------
# cloud
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cname,provider",
    [
        ("bucket.s3.amazonaws.com", "AWS"),
        ("app.azurewebsites.net", "Azure"),
        ("data.blob.core.windows.net", "Azure"),
        ("static.storage.googleapis.com", "Google Cloud"),
        ("d123.cloudfront.net", "AWS"),
        ("files.digitaloceanspaces.com", "DigitalOcean"),
        ("site.herokuapp.com", "Heroku"),
        ("x.netlify.app", "Netlify"),
    ],
)
def test_cloud_detection(cname, provider):
    dns = DNSInfo(host="asset.example.com", cname=[cname])
    asset = detect_cloud_asset("asset.example.com", dns)
    assert asset is not None
    assert asset.provider == provider
    assert asset.confidence >= 50


def test_cloud_detection_from_headers():
    http = _observation({"X-Amz-Bucket-Region": "eu-west-1"})
    asset = detect_cloud_asset("asset.example.com", None, http)
    assert asset and asset.provider == "AWS"


def test_no_cloud_detection():
    dns = DNSInfo(host="a.example.com", cname=["internal.example.net"])
    assert detect_cloud_asset("a.example.com", dns) is None


def test_summarize_cloud():
    assets = [
        CloudAsset(provider="AWS", service="S3"),
        CloudAsset(provider="AWS", service="EC2"),
        CloudAsset(provider="Azure", service="App Service"),
    ]
    assert summarize_cloud(assets) == {"AWS": 2, "Azure": 1}


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def test_parse_certificate_basic_fields():
    cert = {
        "subject": ((("commonName", "api.example.com"),),),
        "issuer": ((("commonName", "R3"),), (("organizationName", "Let's Encrypt"),)),
        "notBefore": "Feb  1 00:00:00 2024 GMT",
        "notAfter": "May  1 23:59:59 2024 GMT",
        "subjectAltName": (("DNS", "api.example.com"), ("DNS", "www.example.com")),
        "serialNumber": "1234567890",
        "_tls_version": "TLSv1.3",
    }
    info = parse_certificate("api.example.com", cert)
    assert info.subject == "api.example.com"
    assert info.issuer == "R3"
    assert info.valid_from == "2024-02-01"
    assert info.valid_until == "2024-05-01"
    assert "www.example.com" in info.sans
    assert info.tls_version == "TLSv1.3"
    assert info.valid is True


def test_certificate_matching():
    info = TLSInfo(host="a.example.com", sans=["*.example.com", "a.example.com"])
    assert certificate_matches_host(info, "a.example.com") is True
    assert certificate_matches_host(info, "b.example.com") is True
    assert certificate_matches_host(info, "evil.com") is False
    assert certificate_matches_host(None, "a.example.com") is False


# ---------------------------------------------------------------------------
# ASN (mocked)
# ---------------------------------------------------------------------------


def test_asn_lookup_via_bgpview():
    payload = {
        "status": "ok",
        "data": {
            "asn": {"asn": 15169, "name": "GOOGLE", "country_code": "US"},
            "prefixes": [{"prefix": "8.8.8.0/24"}],
        },
    }
    client = FakeHTTPClient([("bgpview", make_response(__import__("json").dumps(payload)))])
    enricher = ASNEnricher(client, threads=2)
    info = enricher.lookup("8.8.8.8")
    assert info.asn == "AS15169"
    assert info.organization == "GOOGLE"
    assert info.country == "US"


def test_asn_falls_back_to_ipapi():
    import json

    client = FakeHTTPClient(
        [
            ("bgpview", make_response("", status_code=500, error="HTTP 500")),
            ("ip-api.com", make_response(json.dumps({"status": "success", "as": "AS1 X", "org": "Org", "countryCode": "DE"}))),
        ]
    )
    enricher = ASNEnricher(client, threads=2)
    info = enricher.lookup("1.1.1.1")
    assert info.organization == "Org"
    assert info.source == "ip-api"


def test_asn_skips_private_ips():
    client = FakeHTTPClient([])
    info = ASNEnricher(client).lookup("10.0.0.1")
    assert info.error == "private or invalid address"


def test_asn_all_sources_failing_is_graceful():
    client = FakeHTTPClient([])
    info = ASNEnricher(client).lookup("8.8.8.8")
    assert info.error


def test_is_public_ip_helper():
    assert _is_public_ip("8.8.8.8") is True
    assert _is_public_ip("10.0.0.1") is False
    assert _is_public_ip("not-an-ip") is False


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------


def test_cache_put_get_roundtrip(tmp_path):
    cache = ResponseCache(root=str(tmp_path / ".cache"), ttl=60)
    cache.put("crtsh:GET:https://crt.sh/?q=x", {"text": "hello"})
    assert cache.get("crtsh:GET:https://crt.sh/?q=x") == {"text": "hello"}
    assert cache.hits == 1


def test_cache_disabled_returns_none(tmp_path):
    cache = ResponseCache(root=str(tmp_path / ".cache"), enabled=False)
    cache.put("k", {"a": 1})
    assert cache.get("k") is None


def test_cache_expiry(tmp_path):
    cache = ResponseCache(root=str(tmp_path / ".cache"), ttl=1)
    cache.put("crtsh:k", {"a": 1})
    path = cache.path_for("crtsh:k")
    import os

    old = time.time() - 100
    os.utime(path, (old, old))
    assert cache.get("crtsh:k") is None


def test_cache_namespaces_by_source(tmp_path):
    cache = ResponseCache(root=str(tmp_path / ".cache"))
    cache.put("crtsh:abc", {"a": 1})
    cache.put("urlscan:def", {"b": 2})
    assert "crtsh" in str(cache.path_for("crtsh:abc"))
    assert "urlscan" in str(cache.path_for("urlscan:def"))
    assert cache.stats()["entries"] == 2


def test_cache_clear(tmp_path):
    cache = ResponseCache(root=str(tmp_path / ".cache"))
    cache.put("crtsh:a", {"a": 1})
    cache.put("crtsh:b", {"b": 2})
    assert cache.clear() == 2
    assert cache.clear() == 0
