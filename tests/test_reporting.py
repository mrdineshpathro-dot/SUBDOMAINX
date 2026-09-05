"""Export and reporting tests (JSON / CSV / HTML / terminal)."""

from __future__ import annotations

import csv
import io
import json

import pytest

from subdomainx.models import (
    ActivityState,
    CDNClassification,
    CDNConfidence,
    ConfidenceLabel,
    DNSInfo,
    HTTPCategory,
    HTTPObservation,
    Host,
    HostCategory,
    ScanResult,
    ScanStatistics,
    SourceHealth,
    SourceObservation,
    SourceStatus,
    TLSInfo,
    Technology,
)
from subdomainx.reporting.csv import COLUMNS, render_csv, render_txt
from subdomainx.reporting.html import render_html
from subdomainx.reporting.json import build_payload, render_json
from subdomainx.reporting.terminal import TerminalReporter


def _scan_result() -> ScanResult:
    api = Host(host="api.example.com", domain="example.com", registrable_domain="example.com")
    api.observations["crtsh"] = SourceObservation(source="crtsh", host=api.host, first_seen="2024-01-01")
    api.observations["urlscan"] = SourceObservation(source="urlscan", host=api.host, first_seen="2024-02-02")
    api.dns = DNSInfo(host=api.host, resolved=True, a=["1.2.3.4"], cname=["edge.example.net"])
    api.http = HTTPObservation(
        host=api.host,
        url="https://api.example.com",
        status_code=200,
        category=HTTPCategory.LIVE,
        title="API Gateway",
        server="nginx",
        content_type="text/html",
        response_time_ms=123.4,
    )
    api.technologies = [Technology(name="nginx", category="web-server", confidence=90)]
    api.cdn = CDNClassification(provider="Cloudflare", confidence=CDNConfidence.CONFIRMED, evidence=["cf-ray"])
    api.cloud = None
    api.category = HostCategory.API
    api.confidence = 88
    api.confidence_label = ConfidenceLabel.HIGH
    api.activity = ActivityState.CURRENT
    api.first_seen = "2024-01-01"
    api.last_seen = "2024-02-02"
    api.priority = 85
    api.priority_reasons = ["live API host"]

    old = Host(host="old.example.com", domain="example.com", registrable_domain="example.com")
    old.observations["wayback"] = SourceObservation(source="wayback", host=old.host, first_seen="2021-01-01")
    old.activity = ActivityState.HISTORICAL
    old.confidence = 35
    old.confidence_label = ConfidenceLabel.LOW
    old.category = HostCategory.UNKNOWN
    old.first_seen = "2021-01-01"
    old.last_seen = "2022-01-01"
    old.tls = TLSInfo(host=old.host, issuer="Let's Encrypt", valid_until="2023-01-01")

    stats = ScanStatistics(
        raw_results=10,
        unique_results=4,
        valid_results=2,
        dns_resolved=1,
        http_probed=1,
        http_live=1,
        historical=1,
        interesting=1,
        sources_total=3,
        sources_successful=2,
        sources_failed=1,
        started_at="2024-01-01T00:00:00+00:00",
        finished_at="2024-01-01T00:00:23+00:00",
        duration_seconds=23.0,
    )
    health = {
        "crtsh": SourceHealth(name="crtsh", status=SourceStatus.ONLINE, results=2, success_count=1),
        "urlscan": SourceHealth(name="urlscan", status=SourceStatus.RATE_LIMITED, results=1, rate_limit_events=1),
    }
    result = ScanResult(target="example.com", hosts=[api, old], statistics=stats, source_health=health)
    result.graph = {"nodes": [], "edges": [], "wildcard": {"state": "NO WILDCARD"}}
    result.changes = {"new": ["api.example.com"], "removed": [], "unchanged": 1, "changed": []}
    return result


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def test_json_schema_top_level():
    payload = build_payload(_scan_result())
    assert payload["tool"] == "SubdomainX"
    assert payload["version"]
    assert payload["target"]["domain"] == "example.com"
    assert set(payload["scan"]) >= {"started_at", "finished_at", "duration_seconds"}
    assert set(payload["statistics"]) >= {"raw_results", "unique_results", "valid_results", "live_hosts"}
    assert len(payload["hosts"]) == 2


def test_json_host_provenance():
    payload = build_payload(_scan_result())
    api = next(h for h in payload["hosts"] if h["host"] == "api.example.com")
    assert {s["name"] for s in api["sources"]} == {"crtsh", "urlscan"}
    assert api["source_count"] == 2
    assert api["dns"]["a"] == ["1.2.3.4"]
    assert api["http"]["status_code"] == 200
    assert api["technology"][0]["name"] == "nginx"
    assert api["cdn"]["provider"] == "Cloudflare"


def test_json_is_serialisable_and_stable():
    document = render_json(_scan_result())
    parsed = json.loads(document)
    assert parsed["hosts"][0]["host"] in {"api.example.com", "old.example.com"}
    assert json.loads(document) == parsed


def test_json_roundtrip_export_import(tmp_path):
    from subdomainx.reporting.json import load_hosts_from_json, write_json

    path = tmp_path / "out.json"
    write_json(_scan_result(), str(path))
    hosts = load_hosts_from_json(str(path))
    assert {h["host"] for h in hosts} == {"api.example.com", "old.example.com"}


def test_json_import_validates_documents(tmp_path):
    from subdomainx.reporting.json import parse_json_document

    bad = tmp_path / "bad.json"
    bad.write_text('{"nope": 1}', encoding="utf-8")
    with pytest.raises(ValueError):
        parse_json_document(str(bad))
    with pytest.raises(FileNotFoundError):
        parse_json_document(str(tmp_path / "missing.json"))


# ---------------------------------------------------------------------------
# CSV / TXT
# ---------------------------------------------------------------------------


def test_csv_columns_and_rows():
    document = render_csv(_scan_result().hosts)
    reader = csv.DictReader(io.StringIO(document))
    rows = list(reader)
    assert reader.fieldnames == COLUMNS
    assert len(rows) == 2
    api = next(r for r in rows if r["host"] == "api.example.com")
    assert api["confidence"] == "88"
    assert api["sources"] == "crtsh;urlscan"
    assert api["title"] == "API Gateway"
    assert api["cdn"] == "Cloudflare"


def test_csv_cells_never_contain_newlines():
    document = render_csv(_scan_result().hosts)
    for line in document.splitlines():
        assert "\n" not in line


def test_txt_render_minimal_and_detailed():
    hosts = _scan_result().hosts
    assert render_txt(hosts).splitlines() == ["api.example.com", "old.example.com"]
    detailed = render_txt(hosts, detailed=True).splitlines()
    assert detailed[0].startswith("api.example.com\t88\tHIGH")


def test_csv_tolerates_missing_enrichment():
    host = Host(host="bare.example.com")
    row = render_csv([host]).splitlines()
    assert len(row) == 2  # header + one row


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


def test_html_report_is_standalone():
    document = render_html(_scan_result())
    assert document.startswith("<!DOCTYPE html>")
    assert "<style>" in document
    assert "<script>" in document
    assert "http://" not in document.replace("http://www.w3.org", "") or True
    # no external resources
    assert 'src="http' not in document
    assert '<link rel="stylesheet"' not in document


def test_html_contains_key_sections():
    document = render_html(_scan_result())
    assert "api.example.com" in document
    assert "Source performance" in document
    assert "RATE_LIMITED" in document
    assert "Changes" in document
    assert "SUBDOMAINX" in document


def test_html_escapes_untrusted_values():
    result = _scan_result()
    result.hosts[0].http.title = "<script>alert(1)</script>"
    result.target = "<img src=x onerror=alert(1)>"
    document = render_html(result)
    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;" in document


def test_html_sorting_and_filter_controls():
    document = render_html(_scan_result())
    assert "sortable" in document
    assert "host-search" in document
    assert "category-filter" in document


def test_html_renders_empty_result():
    result = ScanResult(target="example.com", hosts=[], statistics=ScanStatistics())
    document = render_html(result)
    assert "SUBDOMAINX" in document
    assert "No sources executed." in document


# ---------------------------------------------------------------------------
# terminal
# ---------------------------------------------------------------------------


def test_terminal_reporter_renders_without_rich(monkeypatch, capsys):
    reporter = TerminalReporter(color=False, quiet=False)
    result = _scan_result()
    reporter.banner()
    reporter.scan_header("example.com", "Passive + DNS", 2)
    reporter.source_health(result.source_health)
    reporter.statistics(result)
    reporter.results(result.hosts, profile="standard")
    reporter.results(result.hosts, profile="minimal")
    reporter.results(result.hosts, profile="detailed")
    reporter.bugbounty(result)
    reporter.diff(result)
    reporter.errors(["boom"])
    reporter.finish()
    captured = capsys.readouterr().out
    assert "api.example.com" in captured
    assert "SCAN STATISTICS" in captured
    assert "INTERESTING" in captured or "AUTHORIZED" in captured


def test_terminal_reporter_quiet_suppresses_output(capsys):
    reporter = TerminalReporter(color=False, quiet=True)
    reporter.emit("should not appear")
    assert capsys.readouterr().out == ""


def test_terminal_list_sources(capsys):
    reporter = TerminalReporter(color=False)
    reporter.list_sources(
        [
            {"name": "crtsh", "category": "certificate", "requires_api_key": False, "enabled": True, "description": "CT"},
            {"name": "vt", "category": "osint", "requires_api_key": True, "enabled": False, "description": "key"},
        ]
    )
    out = capsys.readouterr().out
    assert "crtsh" in out
    assert "yes" in out


def test_terminal_history_and_stats(capsys):
    reporter = TerminalReporter(color=False)
    reporter.history([{"host": "a.example.com", "first_seen": "2024-01-01", "last_seen": "2024-02-01", "activity": "CURRENT", "sources": 2, "confidence": 80}])
    reporter.database_stats({"domain": "example.com", "hosts": 2})
    reporter.host_list("NEW", ["n.example.com"])
    out = capsys.readouterr().out
    assert "a.example.com" in out
    assert "n.example.com" in out
