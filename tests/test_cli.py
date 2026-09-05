"""CLI and configuration tests (no network, temp databases)."""

from __future__ import annotations

import json

import pytest

from subdomainx.cli import build_parser, main, run_scan
from subdomainx.config import Config, load_config

from .conftest import CRT_SH_PAYLOAD, FakeHTTPClient, make_response


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Never let a CLI test reach the network.

    The HTTP client is replaced with a canned crt.sh response and the DNS
    engine is replaced by an offline stub.
    """
    from subdomainx.engine import Engine
    from subdomainx.enrichment.dns import DNSEngine
    from subdomainx.models import DNSInfo, WildcardState

    from subdomainx.enrichment.dns import WildcardReport

    original_init = Engine.__init__

    def patched_init(self, config=None, logger=None):
        original_init(self, config, logger)
        self.http = FakeHTTPClient([("crt.sh", make_response(json.dumps(CRT_SH_PAYLOAD)))])

    def patched_wildcard(self, domain):
        return WildcardReport(domain=domain, state=WildcardState.NONE)

    def patched_resolve_many(self, hosts, wildcard=None, callback=None):
        results = {}
        for host in hosts or []:
            info = DNSInfo(host=host, resolved=True, a=["93.184.216.34"])
            results[host] = info
            if callback:
                callback(info)
        return results

    monkeypatch.setattr(Engine, "__init__", patched_init)
    monkeypatch.setattr(DNSEngine, "detect_wildcard", patched_wildcard)
    monkeypatch.setattr(DNSEngine, "resolve_many", patched_resolve_many)
    yield


def test_parser_defaults():
    parser = build_parser()
    args = parser.parse_args(["example.com"])
    assert args.domain == "example.com"
    assert args.format is None
    assert args.quiet is False


def test_parser_accepts_all_documented_flags():
    parser = build_parser()
    args = parser.parse_args(
        [
            "example.com",
            "--sources", "all",
            "--resolve",
            "--probe",
            "--tech",
            "--threads", "20",
            "--timeout", "15",
            "--retries", "3",
            "--output", "out.json",
            "--format", "json",
            "--db", "/tmp/x.db",
            "--no-color",
            "--quiet",
            "--diff", "prev.json",
            "--profile", "deep",
        ]
    )
    assert args.threads == 20
    assert args.profile == "deep"
    assert args.format == "json"


def test_list_sources_command(capsys):
    exit_code = main(["--list-sources", "--no-color"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "crtsh" in out


def test_scan_writes_json(tmp_path, capsys, monkeypatch):
    out = tmp_path / "report.json"
    exit_code = main(
        [
            "example.com",
            "--sources", "crtsh",
            "--no-db",
            "--no-color",
            "--quiet",
            "--output", str(out),
            "--format", "json",
        ]
    )
    assert exit_code == 0
    assert out.exists()
    payload = json.loads(out.read_text())
    assert payload["target"]["domain"] == "example.com"
    assert payload["hosts"]


def test_scan_writes_txt_csv_html(tmp_path):
    for fmt, name in (("txt", "r.txt"), ("csv", "r.csv"), ("html", "r.html")):
        out = tmp_path / name
        exit_code = main(
            [
                "example.com",
                "--sources", "crtsh",
                "--no-db",
                "--quiet",
                "--output", str(out),
                "--format", fmt,
            ]
        )
        assert exit_code == 0, fmt
        assert out.exists() and out.stat().st_size > 0


def test_scan_with_minimal_profile(tmp_path, capsys):
    out = tmp_path / "r.txt"
    assert main(["example.com", "--sources", "crtsh", "--no-db", "--output-profile", "minimal", "--output", str(out)]) == 0
    lines = out.read_text().strip().splitlines()
    assert all(" " not in line.strip() for line in lines)


def test_scan_with_input_file(tmp_path):
    domains = tmp_path / "domains.txt"
    domains.write_text("# comment\napi.example.com\nexample.com\n", encoding="utf-8")
    out = tmp_path / "r.json"
    exit_code = main(["--input", str(domains), "--sources", "crtsh", "--no-db", "--quiet", "--output", str(out), "--format", "json"])
    assert exit_code == 0
    # one file per target
    assert (tmp_path / "r_api_example_com.json").exists() or out.exists()


def test_scan_invalid_regex_returns_error(tmp_path, capsys):
    exit_code = main(["example.com", "--filter", "[unclosed", "--no-db", "--quiet"])
    assert exit_code == 2


def test_scan_with_scope_and_exclude(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("*.example.com\n", encoding="utf-8")
    exclude = tmp_path / "exclude.txt"
    exclude.write_text("mail.example.com\n", encoding="utf-8")
    out = tmp_path / "r.json"
    exit_code = main(
        [
            "example.com",
            "--sources", "crtsh",
            "--scope", str(scope),
            "--exclude", str(exclude),
            "--no-db",
            "--quiet",
            "--output", str(out),
            "--format", "json",
        ]
    )
    assert exit_code == 0
    payload = json.loads(out.read_text())
    hosts = {h["host"] for h in payload["hosts"]}
    assert "mail.example.com" not in hosts
    assert "api.example.com" in hosts


def test_database_commands(tmp_path, capsys):
    db = tmp_path / "subdomainx.db"
    main(["example.com", "--sources", "crtsh", "--db", str(db), "--quiet"])
    assert db.exists()

    assert main(["stats", "example.com", "--db", str(db), "--no-color"]) == 0
    assert main(["history", "example.com", "--db", str(db), "--no-color"]) == 0
    assert main(["new", "example.com", "--db", str(db), "--no-color"]) == 0
    assert main(["removed", "example.com", "--db", str(db), "--no-color"]) == 0
    assert main(["sources", "example.com", "--db", str(db), "--no-color"]) == 0
    assert main(["targets", "--db", str(db), "--no-color"]) == 0


def test_database_command_unknown_target(tmp_path, capsys):
    db = tmp_path / "subdomainx.db"
    exit_code = main(["stats", "missing.com", "--db", str(db), "--no-color"])
    assert exit_code == 1


def test_write_config(tmp_path):
    path = tmp_path / "config.toml"
    assert main(["--write-config", str(path)]) == 0
    assert path.exists()
    loaded = load_config(str(path))
    assert loaded.general.threads == Config().general.threads


def test_config_roundtrip(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        "\n".join(
            [
                "[general]",
                "threads = 25",
                "timeout = 42",
                "",
                "[dns]",
                "enabled = false",
                "",
                "[http]",
                "max_body_size = 123456",
                "",
                "[sources]",
                "crtsh = true",
                "urlscan = false",
                "",
            ]
        ),
        encoding="utf-8",
    )
    config = load_config(str(path))
    assert config.general.threads == 25
    assert config.general.timeout == 42
    assert config.dns.enabled is False
    assert config.http.max_body_size == 123456
    assert config.sources.enabled["urlscan"] is False
    assert config.sources.enabled["crtsh"] is True


def test_config_profiles():
    config = Config().apply_profile("fast")
    assert config.dns.enabled is False and config.http.enabled is False
    config = Config().apply_profile("balanced")
    assert config.dns.enabled and config.http.enabled
    config = Config().apply_profile("deep")
    assert config.http.capture_tls and config.dns.dnssec

    with pytest.raises(ValueError):
        Config().apply_profile("turbo")


def test_config_merge_cli():
    config = Config()
    config.merge_cli(
        {
            "threads": 3,
            "timeout": 7,
            "retries": 1,
            "resolve": True,
            "probe": True,
            "no_cache": True,
            "no_color": True,
            "format": "csv",
        }
    )
    assert config.general.threads == 3
    assert config.general.timeout == 7
    assert config.dns.enabled is True
    assert config.http.enabled is True
    assert config.cache.enabled is False
    assert config.output.color is False
    assert config.output.format == "csv"


def test_unknown_target_reports_error():
    with pytest.raises(SystemExit):
        run_scan([])


def test_import_previous_export(tmp_path, capsys):
    previous = tmp_path / "old.json"
    previous.write_text(
        json.dumps({"hosts": [{"host": "api.example.com", "confidence": 90}]}), encoding="utf-8"
    )
    exit_code = main(["--import", str(previous), "--no-db", "--no-color"])
    assert exit_code == 0
    assert "api.example.com" in capsys.readouterr().out


def test_import_missing_file(tmp_path, capsys):
    exit_code = main(["--import", str(tmp_path / "nope.json"), "--no-db", "--no-color"])
    assert exit_code == 2


def test_version_flag():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_bugbounty_flag(tmp_path):
    out = tmp_path / "bb.html"
    exit_code = main(["example.com", "--sources", "crtsh", "--bugbounty", "--no-db", "--quiet", "--output", str(out), "--format", "html"])
    assert exit_code == 0
    assert "AUTHORIZED RESEARCH" in out.read_text() or "SUBDOMAINX" in out.read_text()
