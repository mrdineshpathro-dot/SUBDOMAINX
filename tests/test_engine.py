"""End-to-end engine tests with mocked sources, DNS and HTTP."""

from __future__ import annotations

import json

import pytest

from subdomainx.config import Config
from subdomainx.discovery.diff import diff_host_lists, diff_hosts, load_previous_hosts
from subdomainx.engine import Engine

from .conftest import (
    CRT_SH_PAYLOAD,
    HACKERTARGET_BODY,
    URLSCAN_PAYLOAD,
    FakeHTTPClient,
    make_response,
)


@pytest.fixture()
def engine(tmp_path):
    config = Config()
    config.storage.path = str(tmp_path / "test.db")
    config.cache.enabled = False
    config.dns.enabled = True
    config.http.enabled = True
    config.dns.threads = 4
    config.http.threads = 4
    instance = Engine(config)
    yield instance
    instance.close()


ENGINE_CRT_PAYLOAD = list(CRT_SH_PAYLOAD) + [
    {
        "issuer_ca_id": 2,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "admin.example.com",
        "name_value": "admin.example.com",
        "id": 200,
        "entry_timestamp": "2024-03-03T10:00:00",
        "not_before": "2024-02-01T00:00:00",
        "not_after": "2024-06-01T00:00:00",
    }
]


def _routes():
    return [
        ("crt.sh", make_response(json.dumps(ENGINE_CRT_PAYLOAD))),
        ("hackertarget", make_response(HACKERTARGET_BODY)),
        ("urlscan.io", make_response(json.dumps(URLSCAN_PAYLOAD))),
        ("api.example.com", make_response("<title>API</title>", headers={"Server": "nginx"})),
        ("www.example.com", make_response("<title>Home</title>", headers={"Server": "cloudflare", "CF-RAY": "1"})),
        ("admin.example.com", make_response("<title>Admin</title>", status_code=403)),
    ]


def test_engine_end_to_end(engine, patch_dns):
    from tests.conftest import FakeDNSServer

    server = (
        FakeDNSServer()
        .add("api.example.com", "A", ["93.184.216.34"])
        .add("www.example.com", "A", ["93.184.216.34"])
        .add("www.example.com", "CNAME", ["www.example.com.cdn.cloudflare.net"])
        .add("admin.example.com", "A", ["93.184.216.40"])
    )
    patch_dns(server)
    engine.http = FakeHTTPClient(_routes())

    result = engine.scan("example.com", sources="crtsh,hackertarget,urlscan")

    hosts = {h.host for h in result.hosts}
    assert "api.example.com" in hosts
    assert "www.example.com" in hosts
    assert "admin.example.com" in hosts
    # crt.sh payload contains *.dev.example.com which must be normalized.
    assert "dev.example.com" in hosts

    stats = result.statistics
    assert stats.sources_total == 3
    assert stats.sources_successful >= 2
    assert stats.valid_results == len(result.hosts)
    assert stats.dns_resolved >= 3
    assert stats.http_live >= 2
    assert stats.interesting >= 1

    api = next(h for h in result.hosts if h.host == "api.example.com")
    assert api.source_count >= 2
    assert api.dns_resolved is True
    assert api.http.status_code == 200
    assert api.title == "API"
    assert "nginx" in api.technology_names
    assert api.category.value == "API"
    assert api.confidence > 50
    assert api.confidence_label is not None

    www = next(h for h in result.hosts if h.host == "www.example.com")
    assert www.cdn.provider == "Cloudflare"


def test_engine_enforces_scope(engine, patch_dns):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    payload = [
        {
            "common_name": "evil.com.evil.net",
            "name_value": "example.com.attacker.tld\nnotevil.com",
            "entry_timestamp": "2024-01-01T00:00:00",
        }
    ]
    engine.http = FakeHTTPClient(
        [
            ("crt.sh", make_response(json.dumps(payload))),
        ]
    )
    result = engine.scan("example.com", sources="crtsh")
    assert result.hosts == []
    assert result.statistics.out_of_scope >= 1


def test_engine_source_failure_is_isolated(engine, patch_dns):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    engine.http = FakeHTTPClient(
        [
            ("crt.sh", make_response(json.dumps(ENGINE_CRT_PAYLOAD))),
            ("hackertarget", make_response("", status_code=500, error="HTTP 500")),
        ]
    )
    result = engine.scan("example.com", sources="crtsh,hackertarget")
    assert result.statistics.sources_failed >= 1
    assert result.hosts
    assert any("hackertarget" in e for e in result.errors)


def test_engine_respects_disabled_sources(engine, patch_dns):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    engine.http = FakeHTTPClient(_routes())
    result = engine.scan("example.com", sources="crtsh")
    assert set(result.source_health) == {"crtsh"}


def test_engine_excludes_hosts(engine, patch_dns):
    from subdomainx.discovery.validate import ExclusionMatcher

    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    engine.http = FakeHTTPClient([("crt.sh", make_response(json.dumps(ENGINE_CRT_PAYLOAD)))])
    result = engine.scan("example.com", sources="crtsh", exclude=ExclusionMatcher(["dev.example.com"]))
    assert "dev.example.com" not in {h.host for h in result.hosts}


def test_engine_regex_filters(engine, patch_dns):
    import re

    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    engine.http = FakeHTTPClient([("crt.sh", make_response(json.dumps(ENGINE_CRT_PAYLOAD)))])
    result = engine.scan("example.com", sources="crtsh", include_regex=re.compile(r"^api\."))
    assert {h.host for h in result.hosts} == {"api.example.com"}


def test_engine_detects_wildcard_dns(engine, patch_dns):
    from subdomainx.models import WildcardState

    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer(wildcard=["93.184.216.99"]))
    engine.http = FakeHTTPClient([("crt.sh", make_response(json.dumps(ENGINE_CRT_PAYLOAD)))])
    result = engine.scan("example.com", sources="crtsh")
    assert result.graph["wildcard"]["state"] == WildcardState.WILDCARD.value


def test_engine_persists_to_database(engine, patch_dns):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    engine.http = FakeHTTPClient([("crt.sh", make_response(json.dumps(ENGINE_CRT_PAYLOAD)))])
    result = engine.scan("example.com", sources="crtsh")
    rows = engine.database.hosts("example.com")
    assert {r["host"] for r in rows} == {h.host for h in result.hosts}


def test_engine_change_detection(engine, patch_dns):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    engine.http = FakeHTTPClient([("crt.sh", make_response(json.dumps(ENGINE_CRT_PAYLOAD)))])
    engine.scan("example.com", sources="crtsh")

    previous = engine.previous_hosts("example.com")
    assert previous

    changed_payload = [
        {
            "common_name": "api.example.com",
            "name_value": "api.example.com",
            "entry_timestamp": "2024-05-05T00:00:00",
        }
    ]
    engine.http = FakeHTTPClient([("crt.sh", make_response(json.dumps(changed_payload)))])
    result = engine.scan("example.com", sources="crtsh", previous_hosts=previous)
    assert result.changes is not None
    assert result.changes["removed"]


def test_engine_baseline_diff(engine, patch_dns, tmp_path):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    baseline = tmp_path / "previous.json"
    baseline.write_text(json.dumps({"hosts": [{"host": "gone.example.com"}, {"host": "api.example.com"}]}))
    engine.http = FakeHTTPClient([("crt.sh", make_response(json.dumps(ENGINE_CRT_PAYLOAD)))])
    result = engine.scan("example.com", sources="crtsh", baseline=str(baseline))
    assert "gone.example.com" in result.changes["removed"]
    assert "api.example.com" not in result.changes["new"]


def test_engine_progress_callback(engine, patch_dns):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    engine.http = FakeHTTPClient([("crt.sh", make_response(json.dumps(ENGINE_CRT_PAYLOAD)))])
    seen = []
    engine.scan("example.com", sources="crtsh", progress=lambda s, t, m: seen.append(m))
    assert len(seen) == 7
    assert seen[0] == "Loading sources"


def test_engine_rejects_invalid_target(engine):
    with pytest.raises(ValueError):
        engine.scan("not a domain")


def test_engine_fast_profile_skips_enrichment(tmp_path, patch_dns):
    from tests.conftest import FakeDNSServer

    patch_dns(FakeDNSServer())
    config = Config()
    config.apply_profile("fast")
    config.storage.path = str(tmp_path / "fast.db")
    config.cache.enabled = False
    instance = Engine(config)
    instance.http = FakeHTTPClient([("crt.sh", make_response(json.dumps(ENGINE_CRT_PAYLOAD)))])
    result = instance.scan("example.com", sources="crtsh")
    instance.close()
    assert result.statistics.dns_resolved == 0
    assert result.statistics.http_probed == 0


# ---------------------------------------------------------------------------
# diff helpers
# ---------------------------------------------------------------------------


def test_diff_host_lists():
    diff = diff_host_lists(["a.example.com", "b.example.com"], ["b.example.com", "c.example.com"])
    assert diff.new == ["c.example.com"]
    assert diff.removed == ["a.example.com"]
    assert diff.unchanged == ["b.example.com"]
    assert diff.changed is True


def test_diff_normalizes_before_comparing():
    diff = diff_host_lists(["HTTPS://A.Example.com:443/"], ["a.example.com"])
    assert diff.new == []
    assert diff.unchanged == ["a.example.com"]


def test_load_previous_hosts_json_and_txt(tmp_path):
    payload = tmp_path / "prev.json"
    payload.write_text(json.dumps({"hosts": [{"host": "api.example.com"}, {"host": "www.example.com"}]}))
    assert load_previous_hosts(str(payload)) == ["api.example.com", "www.example.com"]

    txt = tmp_path / "prev.txt"
    txt.write_text("api.example.com\nhttps://www.example.com/x\n", encoding="utf-8")
    assert load_previous_hosts(str(txt)) == ["api.example.com", "www.example.com"]

    csv_file = tmp_path / "prev.csv"
    csv_file.write_text("host,confidence\napi.example.com,88\n", encoding="utf-8")
    assert load_previous_hosts(str(csv_file)) == ["api.example.com"]


def test_load_previous_hosts_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_previous_hosts(str(tmp_path / "nope.json"))


def test_diff_hosts_detects_attribute_changes():
    payload = {
        "hosts": [
            {
                "host": "api.example.com",
                "dns": {"resolved": True, "a": ["1.1.1.1"]},
                "http": {"status_code": 200, "title": "API"},
                "technology": ["nginx"],
                "sources": ["crtsh"],
            }
        ]
    }
    previous = {name: host for name, host in _hosts_from_payload(payload).items()}

    from subdomainx.models import DNSInfo, HTTPObservation, Host, Technology

    current = {
        "api.example.com": _host_with(
            Host(host="api.example.com"),
            dns=DNSInfo(host="api.example.com", resolved=True, a=["2.2.2.2"]),
            http=HTTPObservation(host="api.example.com", status_code=403, title="Denied"),
            tech=[Technology(name="Cloudflare", category="cdn")],
            sources=["crtsh", "urlscan"],
        )
    }
    changes = diff_hosts(previous, current)
    assert len(changes) == 1
    notes = " ".join(changes[0].changes)
    assert "dns_a" in notes
    assert "http_status" in notes
    assert "urlscan" in notes


def _hosts_from_payload(payload):  # noqa: ANN201
    import json
    import tempfile as _tf

    from subdomainx.discovery.diff import hosts_from_json

    with _tf.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(payload, handle)
        path = handle.name
    return hosts_from_json(path)


def _host_with(host, dns=None, http=None, tech=None, sources=()):  # noqa: ANN001, ANN201
    from subdomainx.models import SourceObservation

    host.dns = dns
    host.http = http
    host.technologies = tech or []
    for source in sources:
        host.observations[source] = SourceObservation(source=source, host=host.host)
    return host


def test_diff_hosts_ignores_unchanged():
    from subdomainx.models import DNSInfo, Host

    previous = {"a.example.com": _host_with(Host(host="a.example.com"), dns=DNSInfo(host="a.example.com", resolved=True, a=["1.1.1.1"]))}
    current = {"a.example.com": _host_with(Host(host="a.example.com"), dns=DNSInfo(host="a.example.com", resolved=True, a=["1.1.1.1"]))}
    assert diff_hosts(previous, current) == []
