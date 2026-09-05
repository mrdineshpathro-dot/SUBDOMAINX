"""SQLite storage tests (temporary database files, no network)."""

from __future__ import annotations

import json

import pytest

from subdomainx.models import (
    ActivityState,
    CloudAsset,
    DNSInfo,
    HTTPCategory,
    HTTPObservation,
    Host,
    HostCategory,
    ScanResult,
    ScanStatistics,
    SourceObservation,
    SourceStatus,
    SourceHealth,
)
from subdomainx.storage.database import Database
from subdomainx.storage.migrations import apply_migrations, current_version


def _result(target: str, names, run: int = 1) -> ScanResult:
    stats = ScanStatistics(raw_results=len(names), unique_results=len(names), valid_results=len(names))
    hosts = []
    for name in names:
        host = Host(host=name, domain=target, registrable_domain=target)
        host.observations["crtsh"] = SourceObservation(source="crtsh", host=name, first_seen="2024-01-01")
        host.total_observations = 1
        host.dns = DNSInfo(host=name, resolved=True, a=["1.2.3.4"], cname=["edge.example.net"])
        host.http = HTTPObservation(
            host=name, status_code=200, category=HTTPCategory.LIVE, title="T", server="nginx"
        )
        host.activity = ActivityState.CURRENT
        host.category = HostCategory.API
        host.confidence = 80
        hosts.append(host)
    return ScanResult(target=target, hosts=hosts, statistics=stats)


@pytest.fixture()
def db(tmp_path):
    database = Database(str(tmp_path / "subdomainx.db"))
    database.connect()
    yield database
    database.close()


def test_migrations_are_applied(db):
    assert current_version(db.conn) >= 1
    apply_migrations(db.conn)  # idempotent
    assert current_version(db.conn) >= 1


def test_all_expected_tables_exist(db):
    tables = {
        row[0]
        for row in db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    expected = {
        "targets",
        "hosts",
        "sources",
        "observations",
        "dns_records",
        "http_observations",
        "tls_observations",
        "technology",
        "historical_observations",
        "scan_runs",
        "run_hosts",
        "source_runs",
        "errors",
    }
    assert expected <= tables


def test_save_and_reload_hosts(db):
    result = _result("example.com", ["api.example.com", "www.example.com"])
    db.save_scan(result)
    rows = db.hosts("example.com")
    assert {r["host"] for r in rows} == {"api.example.com", "www.example.com"}


def test_history_records_first_and_last_seen(db):
    result = _result("example.com", ["api.example.com"])
    result.hosts[0].first_seen = "2023-01-01"
    result.hosts[0].last_seen = "2024-06-01"
    db.save_scan(result)
    history = db.history("example.com")
    assert history[0]["first_seen"] == "2023-01-01"
    assert history[0]["last_seen"] == "2024-06-01"


def test_new_and_removed_hosts_between_runs(db):
    first = _result("example.com", ["api.example.com", "old.example.com"])
    db.save_scan(first)
    second = _result("example.com", ["api.example.com", "new.example.com"])
    db.save_scan(second)

    assert [r["host"] for r in db.new_hosts("example.com")] == ["new.example.com"]
    assert [r["host"] for r in db.removed_hosts("example.com")] == ["old.example.com"]


def test_single_run_has_no_delta(db):
    db.save_scan(_result("example.com", ["api.example.com"]))
    assert db.new_hosts("example.com") == []
    assert db.removed_hosts("example.com") == []


def test_host_detail_includes_children(db):
    result = _result("example.com", ["api.example.com"])
    host = result.hosts[0]
    from subdomainx.models import Technology

    host.technologies = [Technology(name="nginx", category="web-server", evidence="Server", confidence=90)]
    host.cloud = CloudAsset(provider="AWS", service="CloudFront", cname="x.cloudfront.net")
    db.save_scan(result)

    detail = db.host("example.com", "api.example.com")
    assert detail is not None
    assert detail["host"] == "api.example.com"
    assert [t["name"] for t in detail["technology"]] == ["nginx"]
    assert any(d["record_type"] == "A" for d in detail["dns"])
    assert detail["http"][0]["status_code"] == 200


def test_source_stats_are_persisted(db):
    result = _result("example.com", ["api.example.com"])
    result.source_health["crtsh"] = SourceHealth(
        name="crtsh", category="certificate", status=SourceStatus.ONLINE, results=5
    )
    db.save_scan(result)
    stats = db.source_stats("example.com")
    assert stats and stats[0]["name"] == "crtsh"
    assert stats[0]["results"] == 5


def test_stats_summary(db):
    db.save_scan(_result("example.com", ["api.example.com", "www.example.com"]))
    stats = db.stats("example.com")
    assert stats["hosts"] == 2
    assert stats["exists"] is True
    assert stats["scans"] == 1
    assert "API" in stats["categories"]


def test_stats_for_unknown_target(db):
    assert db.stats("nope.com")["exists"] is False


def test_list_and_delete_targets(db):
    db.save_scan(_result("a.com", ["x.a.com"]))
    db.save_scan(_result("b.com", ["y.b.com"]))
    assert {t["domain"] for t in db.list_targets()} == {"a.com", "b.com"}
    assert db.delete_target("a.com") is True
    assert {t["domain"] for t in db.list_targets()} == {"b.com"}


def test_errors_table_records_failures(db):
    db.record_error(None, "crtsh", "boom")
    rows = db.conn.execute("SELECT * FROM errors").fetchall()
    assert len(rows) == 1
    assert rows[0]["message"] == "boom"


def test_repeated_scans_do_not_duplicate_hosts(db):
    db.save_scan(_result("example.com", ["api.example.com"]))
    db.save_scan(_result("example.com", ["api.example.com"]))
    rows = db.hosts("example.com")
    assert len(rows) == 1
    assert rows[0]["total_observations"] >= 1


def test_export_json_snapshot(db):
    db.save_scan(_result("example.com", ["api.example.com"]))
    payload = db.export_json("example.com")
    assert payload["target"]["domain"] == "example.com"
    assert payload["hosts"][0]["host"] == "api.example.com"
    json.dumps(payload)  # must be serialisable


def test_context_manager(tmp_path):
    with Database(str(tmp_path / "ctx.db")) as database:
        database.upsert_target("example.com")
        assert database.get_target("example.com") is not None


def test_database_creates_parent_directory(tmp_path):
    path = tmp_path / "nested" / "dir" / "subdomainx.db"
    database = Database(str(path))
    database.connect()
    assert path.exists()
    database.close()
