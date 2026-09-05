"""DNS enrichment and wildcard detection tests (mocked resolver)."""

from __future__ import annotations

from subdomainx.enrichment.dns import DNSOptions, DNSEngine, WildcardReport, summarize_dns
from subdomainx.models import WildcardState


def test_resolve_collects_record_types(patch_dns):
    server = (
        __import__("tests.conftest", fromlist=["FakeDNSServer"]).FakeDNSServer()
        .add("api.example.com", "A", ["93.184.216.34"])
        .add("api.example.com", "AAAA", ["2606:2800:220:1:248:1893:25c8:1946"])
        .add("api.example.com", "CNAME", ["edge.example.net"])
        .add("api.example.com", "MX", ["10 mail.example.com"])
        .add("api.example.com", "NS", ["ns1.example.com"])
        .add("api.example.com", "TXT", ['"v=spf1 include:_spf.example.com ~all"'])
        .add("api.example.com", "CAA", ['0 issue "letsencrypt.org"'])
    )
    patch_dns(server)
    engine = DNSEngine(DNSOptions(threads=2))
    info = engine.resolve("api.example.com")

    assert info.resolved is True
    assert info.a == ["93.184.216.34"]
    assert info.aaaa == ["2606:2800:220:1:248:1893:25c8:1946"]
    assert info.cname == ["edge.example.net"]
    assert info.mx == ["10 mail.example.com"]
    assert info.ns == ["ns1.example.com"]
    assert info.txt == ["v=spf1 include:_spf.example.com ~all"]
    # CAA values are quote-stripped and lower-cased for safe storage/export.
    assert info.caa == ["0 issue letsencrypt.org"]


def test_resolve_unknown_host_is_not_resolved(patch_dns):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    engine = DNSEngine(DNSOptions(threads=2))
    info = engine.resolve("does-not-exist.example.com")
    assert info.resolved is False
    assert info.a == []


def test_internal_looking_addresses_are_flagged(patch_dns):
    from tests.conftest import FakeDNSServer

    server = FakeDNSServer().add("intranet.example.com", "A", ["10.0.0.5"])
    patch_dns(server)
    engine = DNSEngine(DNSOptions(threads=2))
    assert engine.resolve("intranet.example.com").internal_looking is True


def test_internal_cname_suffix_is_flagged(patch_dns):
    from tests.conftest import FakeDNSServer

    server = FakeDNSServer().add("corp.example.com", "CNAME", ["host.internal"])
    patch_dns(server)
    engine = DNSEngine(DNSOptions(threads=2))
    assert engine.resolve("corp.example.com").internal_looking is True


def test_wildcard_not_detected(patch_dns):
    from tests.conftest import FakeDNSServer

    server = FakeDNSServer().add("api.example.com", "A", ["93.184.216.34"])
    patch_dns(server)
    engine = DNSEngine(DNSOptions(threads=4, detect_wildcard=True))
    report = engine.detect_wildcard("example.com")
    assert report.state is WildcardState.NONE
    assert report.resolved_count == 0


def test_wildcard_detected(patch_dns):
    from tests.conftest import FakeDNSServer

    server = FakeDNSServer(wildcard=["93.184.216.99"])
    patch_dns(server)
    engine = DNSEngine(DNSOptions(threads=4, detect_wildcard=True, probes=3))
    report = engine.detect_wildcard("example.com")
    assert report.state is WildcardState.WILDCARD
    assert report.resolved_count == 3
    assert "93.184.216.99" in report.signature


def test_wildcard_disabled_returns_unknown(patch_dns):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer(wildcard=["1.2.3.4"]))
    engine = DNSEngine(DNSOptions(detect_wildcard=False))
    assert engine.detect_wildcard("example.com").state is WildcardState.UNKNOWN


def test_resolve_many_marks_wildcard_matches(patch_dns):
    from tests.conftest import FakeDNSServer

    server = (
        FakeDNSServer(wildcard=["93.184.216.99"])
        .add("api.example.com", "A", ["93.184.216.99"])
        .add("real.example.com", "A", ["93.184.216.34"])
    )
    patch_dns(server)
    engine = DNSEngine(DNSOptions(threads=4, probes=3))
    report = engine.detect_wildcard("example.com")
    results = engine.resolve_many(["api.example.com", "real.example.com"], wildcard=report)
    assert results["api.example.com"].wildcard is True
    assert results["real.example.com"].wildcard is False


def test_resolve_many_survives_resolver_crash(patch_dns, monkeypatch):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    engine = DNSEngine(DNSOptions(threads=2))

    def boom(self, host, rtype, **kwargs):
        raise RuntimeError("resolver exploded")

    monkeypatch.setattr(DNSEngine, "resolve", boom)
    results = engine.resolve_many(["a.example.com"])
    assert results["a.example.com"].error


def test_summarize_dns(patch_dns):
    from tests.conftest import FakeDNSServer

    server = (
        FakeDNSServer()
        .add("a.example.com", "A", ["1.1.1.1"])
        .add("b.example.com", "CNAME", ["cdn.example.net"])
    )
    patch_dns(server)
    engine = DNSEngine(DNSOptions(threads=2))
    records = [engine.resolve("a.example.com"), engine.resolve("b.example.com")]
    summary = summarize_dns(records)
    assert summary == {"resolved": 2, "cnames": 1, "internal": 0}


def test_dnssec_status_is_best_effort(patch_dns):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    engine = DNSEngine(DNSOptions(dnssec=True))
    # The stub raises for DNSKEY, so the status must degrade gracefully.
    assert engine.dnssec_status("example.com") is None


def test_wildcard_report_serialisation():
    report = WildcardReport(domain="example.com", state=WildcardState.PARTIAL)
    payload = report.to_dict()
    assert payload["state"] == "PARTIAL WILDCARD"
    assert payload["domain"] == "example.com"
