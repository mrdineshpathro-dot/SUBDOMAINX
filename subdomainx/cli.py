"""Command line interface for SUBDOMAINX.

Usage styles::

    subdomainx example.com
    subdomainx example.com --sources all --resolve --probe --tech
    subdomainx example.com --bugbounty --output report.html --format html
    subdomainx history example.com
    subdomainx --input domains.txt --resolve --probe
    subdomainx --interactive

Everything is optional; the simplest form is just a domain name.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .config import (
    FORMATS,
    OUTPUT_PROFILES,
    PROFILES,
    Config,
    find_default_config,
    load_config,
)
from .discovery.validate import ExclusionMatcher, ScopeMatcher, read_pattern_file
from .engine import Engine
from .sources.registry import filter_sources
from .models import Host, ScanResult, utcnow_iso
from .utils.logging import setup_logging, get_logger

#: Sub-commands that operate on the local database instead of running a scan.
DB_COMMANDS = ("history", "new", "removed", "sources", "stats", "targets", "show")

EPILOG = """
examples:
  subdomainx example.com
  subdomainx example.com --sources all --resolve --probe --tech
  subdomainx example.com --bugbounty --output report.html --format html
  subdomainx example.com --diff previous.json
  subdomainx --input domains.txt --resolve --probe
  subdomainx history example.com
  subdomainx --interactive

SUBDOMAINX is a passive reconnaissance tool.  It never brute-forces, never
exploits and never requires credentials or API keys.
"""

BANNER_VERSION = __version__


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the main scan argument parser."""
    parser = argparse.ArgumentParser(
        prog="subdomainx",
        description="SUBDOMAINX - passive subdomain discovery and asset intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
        add_help=True,
    )

    target = parser.add_argument_group("target")
    target.add_argument("domain", nargs="?", help="root domain to investigate")
    target.add_argument("--input", "-i", help="file with one domain per line")
    target.add_argument("--scope", help="scope file restricting results (*.example.com)")
    target.add_argument("--exclude", help="exclusion file")

    discovery = parser.add_argument_group("discovery")
    discovery.add_argument(
        "--sources",
        default=None,
        help="comma separated source list or 'all' (default: all keyless sources)",
    )
    discovery.add_argument("--list-sources", action="store_true", help="list available sources and exit")
    discovery.add_argument(
        "--filter", dest="include_regex", help="only keep hosts matching this regex"
    )
    discovery.add_argument(
        "--exclude-regex", dest="exclude_regex", help="drop hosts matching this regex"
    )
    discovery.add_argument(
        "--history",
        action="store_true",
        help="include historical sources and mark historical hosts",
    )

    enrich = parser.add_argument_group("enrichment")
    enrich.add_argument("--resolve", action="store_true", default=None, help="enable DNS enrichment")
    enrich.add_argument("--no-resolve", action="store_true", help="disable DNS enrichment")
    enrich.add_argument("--probe", action="store_true", default=None, help="enable HTTP probing")
    enrich.add_argument("--no-probe", action="store_true", help="disable HTTP probing")
    enrich.add_argument("--tech", action="store_true", help="enable technology detection")
    enrich.add_argument("--tls", action="store_true", help="capture TLS certificate metadata")
    enrich.add_argument("--asn", action="store_true", help="enrich resolved IPs with ASN metadata")
    enrich.add_argument(
        "--profile",
        choices=PROFILES,
        default=None,
        help="performance profile: fast, balanced or deep",
    )

    engine = parser.add_argument_group("engine")
    engine.add_argument("--threads", type=int, help="global concurrency (default 10)")
    engine.add_argument("--timeout", type=int, help="per-request timeout in seconds")
    engine.add_argument("--retries", type=int, help="retries per request")
    engine.add_argument(
        "--rate-limit", type=float, help="minimum seconds between requests to the same source"
    )

    cache = parser.add_argument_group("cache")
    cache.add_argument("--cache", action="store_true", default=None, help="enable the local cache")
    cache.add_argument("--no-cache", action="store_true", help="disable the local cache")
    cache.add_argument("--cache-ttl", type=int, help="cache TTL in seconds (default 86400)")
    cache.add_argument("--clear-cache", action="store_true", help="delete cached responses and exit")

    storage = parser.add_argument_group("storage")
    storage.add_argument("--db", default=None, help="SQLite database path (default subdomainx.db)")
    storage.add_argument("--no-db", action="store_true", help="do not write to the database")

    output = parser.add_argument_group("output")
    output.add_argument("--output", "-o", help="write the report to this file")
    output.add_argument("--format", choices=FORMATS, default=None, help="report format")
    output.add_argument(
        "--output-profile",
        dest="output_profile",
        choices=OUTPUT_PROFILES,
        default=None,
        help="terminal output profile: minimal, standard, detailed",
    )
    output.add_argument("--bugbounty", action="store_true", help="authorized-research view")
    output.add_argument("--quiet", "-q", action="store_true", help="suppress console output")
    output.add_argument("--verbose", "-v", action="store_true", help="verbose logging")
    output.add_argument("--debug", action="store_true", help="debug logging")
    output.add_argument("--no-color", action="store_true", help="disable coloured output")
    output.add_argument(
        "--log-format", choices=("text", "json"), default=None, help="logging format"
    )
    output.add_argument("--log-file", default=None, help="also write logs to this file")

    diff = parser.add_argument_group("diff & monitoring")
    diff.add_argument("--diff", help="compare against a previous JSON/TXT/CSV export")
    diff.add_argument("--baseline", help="alias for --diff")
    diff.add_argument("--watch", action="store_true", help="rerun discovery periodically")
    diff.add_argument("--interval", type=int, default=21600, help="watch interval in seconds")

    config = parser.add_argument_group("configuration")
    config.add_argument("--config", help="path to config.toml")
    config.add_argument("--write-config", help="write an example config file and exit")
    config.add_argument("--import", dest="import_file", help="import a previous JSON export")
    config.add_argument("--interactive", action="store_true", help="run interactive mode")
    config.add_argument("--version", action="version", version=f"SUBDOMAINX {__version__}")

    return parser


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point.  Returns a process exit code."""
    args_list = list(sys.argv[1:] if argv is None else argv)

    if not args_list:
        build_parser().print_help()
        return 0

    command = args_list[0]
    if command in ("--list-sources",):
        return _list_sources(args_list)
    if command in DB_COMMANDS:
        return run_db_command(command, args_list[1:])
    if command == "interactive" or "--interactive" in args_list:
        return run_interactive(args_list)

    return run_scan(args_list)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def run_scan(args_list: Sequence[str]) -> int:
    """Run one or more scans described by command line arguments."""
    parser = build_parser()
    args = parser.parse_args(list(args_list))

    config = _build_config(args)
    logger = _setup_logger(args, config)
    from .reporting.terminal import TerminalReporter

    reporter = TerminalReporter(
        color=config.output.color and not args.quiet,
        quiet=args.quiet,
    )

    if args.list_sources:
        engine = Engine(config, logger=logger)
        reporter.list_sources(_catalog(engine))
        engine.close()
        return 0

    if args.clear_cache:
        removed = _clear_cache(config)
        reporter.emit(f"[green]Removed {removed} cached responses.[/green]")
        return 0

    if args.write_config:
        Path(args.write_config).write_text(config.render_toml(), encoding="utf-8")
        reporter.emit(f"[green]Wrote example configuration to {args.write_config}[/green]")
        return 0

    if args.import_file:
        return _import_report(args.import_file, config, reporter)

    targets = _collect_targets(args)
    if not targets:
        parser.error("no target domain given (use a positional domain or --input)")

    filters = _build_filters(args, logger)
    if filters is None:
        return 2

    scope, exclude, include_regex, exclude_regex = filters
    source_selection = _parse_sources(args.sources)

    results: List[ScanResult] = []
    exit_code = 0
    engine = Engine(config, logger=logger)

    if not args.quiet:
        try:
            source_count = len(filter_sources(engine.available_sources(), source_selection))
        except Exception:  # noqa: BLE001 - the header must never break a scan
            source_count = 0
        label = ", ".join(targets[:3]) + ("..." if len(targets) > 3 else "")
        reporter.banner(BANNER_VERSION)
        reporter.scan_header(label, _mode_label(config), source_count)
    try:
        for index, target in enumerate(targets, start=1):
            if len(targets) > 1 and not args.quiet:
                reporter.emit("")
                reporter.emit(f"[bold cyan]═══ Target {index}/{len(targets)}: {target} ═══[/bold cyan]")

            if args.watch:
                exit_code = max(exit_code, _watch_loop(engine, target, args, config, filters, reporter))
                continue

            try:
                result = engine.scan(
                    target,
                    sources=source_selection,
                    scope=scope,
                    exclude=exclude,
                    include_regex=include_regex,
                    exclude_regex=exclude_regex,
                    baseline=args.diff or args.baseline,
                    previous_hosts=_previous_snapshot(engine, target, args),
                    progress=(lambda s, t, m: reporter.phase(s, t, m)) if not args.quiet else None,
                )
            except ValueError as exc:
                logger.error("%s", exc)
                exit_code = max(exit_code, 2)
                continue

            if args.asn:
                engine.enrich_asn(result.hosts)

            results.append(result)
            if not args.quiet:
                _render(result, config, args, reporter)
            _write_report(result, config, args, logger, multiple=len(targets) > 1)

        if not args.quiet and results:
            reporter.finish()
    except KeyboardInterrupt:  # pragma: no cover - interactive abort
        reporter.emit("")
        reporter.emit("[yellow]Interrupted by user.[/yellow]")
        exit_code = 130
    finally:
        engine.close()

    return exit_code


def _watch_loop(engine, target, args, config, filters, reporter) -> int:  # noqa: ANN001
    """Run discovery repeatedly, printing what changed each round."""
    scope, exclude, include_regex, exclude_regex = filters
    previous: List[str] = []
    iteration = 0
    try:
        while True:
            iteration += 1
            result = engine.scan(
                target,
                sources=_parse_sources(args.sources),
                scope=scope,
                exclude=exclude,
                include_regex=include_regex,
                exclude_regex=exclude_regex,
            )
            current = [h.host for h in result.hosts]
            new = sorted(set(current) - set(previous)) if previous else []
            reporter.watch_update(target, int(args.interval), len(previous), len(current), new)
            if not args.quiet:
                reporter.results(result.hosts, profile=config.output.profile)
            if args.output:
                _write_report(result, config, args, get_logger(), multiple=False)
            previous = current
            reporter.emit(
                f"[dim]Next run in {args.interval}s (iteration {iteration}, Ctrl+C to stop).[/dim]"
            )
            time.sleep(max(1, int(args.interval)))
    except KeyboardInterrupt:
        reporter.emit("[yellow]Watch mode stopped.[/yellow]")
    return 0


# ---------------------------------------------------------------------------
# database commands
# ---------------------------------------------------------------------------


def run_db_command(command: str, argv: Sequence[str]) -> int:
    """Handle ``history`` / ``new`` / ``removed`` / ``sources`` / ``stats``."""
    parser = argparse.ArgumentParser(prog=f"subdomainx {command}")
    parser.add_argument("domain", nargs="?", help="target domain ('targets' lists all of them)")
    parser.add_argument("host", nargs="?", help="host name (only used by 'show')")
    parser.add_argument("--db", default=None)
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--format", choices=("txt", "json"), default="txt")
    args = parser.parse_args(list(argv))

    config = Config()
    if args.db:
        config.storage.path = args.db
    from .storage.database import Database

    database = Database(config.storage.path)
    database.connect()
    from .reporting.terminal import TerminalReporter

    reporter = TerminalReporter(color=not args.no_color)

    try:
        if command == "targets" or (command in DB_COMMANDS and not args.domain):
            pass
        if not args.domain and command != "targets":
            parser.error("a target domain is required")
        if command == "show" and not args.host:
            parser.error("'show' requires a host name, e.g. subdomainx show example.com api.example.com")

        if command == "targets":
            rows = database.list_targets()
            if args.format == "json":
                print(_json_dumps(rows))
            else:
                reporter.emit("")
                reporter.emit("[bold]KNOWN TARGETS[/bold]")
                reporter.rule()
                for row in rows:
                    reporter.emit(
                        f"  {row['domain']:<40}{row.get('hosts', 0):>6} hosts   "
                        f"last scan: {row.get('last_scan') or 'never'}"
                    )
            return 0

        if database.get_target(args.domain) is None:
            reporter.emit(f"[yellow]No data stored for {args.domain}[/yellow]")
            return 1

        if command == "history":
            rows = database.history(args.domain)
            if args.format == "json":
                print(_json_dumps(rows))
            else:
                reporter.history(rows)
        elif command == "new":
            rows = database.new_hosts(args.domain)
            if args.format == "json":
                print(_json_dumps([r["host"] for r in rows]))
            else:
                reporter.host_list("NEW SUBDOMAINS", rows)
        elif command == "removed":
            rows = database.removed_hosts(args.domain)
            if args.format == "json":
                print(_json_dumps([r["host"] for r in rows]))
            else:
                reporter.host_list("REMOVED SUBDOMAINS", rows)
        elif command == "sources":
            rows = database.source_stats(args.domain)
            if args.format == "json":
                print(_json_dumps(rows))
            else:
                reporter.emit("")
                reporter.emit("[bold]SOURCE PERFORMANCE (last run)[/bold]")
                reporter.rule()
                reporter.emit(f"{'SOURCE':<22}{'STATUS':<14}{'RESULTS':>9}{'LATENCY':>10}{'ERRORS':>8}")
                for row in rows:
                    reporter.emit(
                        f"{row['name']:<22}{row.get('status',''):<14}{row.get('results',0):>9}"
                        f"{row.get('response_time_ms',0):>9.0f}ms{row.get('error_count',0):>8}"
                    )
                reporter.rule()
        elif command == "stats":
            stats = database.stats(args.domain)
            if args.format == "json":
                print(_json_dumps(stats))
            else:
                reporter.database_stats(stats)
        elif command == "show":
            detail = database.host(args.domain, args.host)
            print(_json_dumps(detail) if detail else "not found")
        return 0
    finally:
        database.close()


# ---------------------------------------------------------------------------
# interactive mode
# ---------------------------------------------------------------------------


def run_interactive(args_list: Sequence[str]) -> int:
    """Simple menu driven workflow."""
    from .reporting.terminal import TerminalReporter

    reporter = TerminalReporter()
    reporter.banner(BANNER_VERSION)
    reporter.emit("")
    reporter.emit("[bold]SUBDOMAINX Interactive Mode[/bold]")
    reporter.emit("")

    try:
        target = input("Target domain: ").strip()
    except (EOFError, KeyboardInterrupt):  # pragma: no cover
        return 0
    if not target:
        reporter.emit("[red]No target given.[/red]")
        return 1

    config = Config()
    _setup_logger(argparse.Namespace(quiet=False, verbose=False, debug=False, no_color=False,
                                     log_format=None, log_file=None), config)
    engine = Engine(config)

    state: Dict[str, Any] = {"result": None}
    try:
        while True:
            reporter.emit("")
            reporter.rule()
            reporter.emit("  [1] Passive discovery")
            reporter.emit("  [2] DNS enrichment")
            reporter.emit("  [3] HTTP probing")
            reporter.emit("  [4] Technology detection")
            reporter.emit("  [5] Historical analysis")
            reporter.emit("  [6] Export results")
            reporter.emit("  [7] Exit")
            reporter.rule()
            try:
                choice = input("Select> ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if choice == "7":
                break
            if choice == "1":
                config.dns.enabled = False
                config.http.enabled = False
                state["result"] = engine.scan(target, progress=lambda s, t, m: reporter.phase(s, t, m))
                reporter.results(state["result"].hosts, profile="standard")
            elif choice == "2":
                config.dns.enabled = True
                result = state["result"] or engine.scan(target)
                state["result"] = result
                reporter.emit(f"[green]{result.statistics.dns_resolved} hosts resolve.[/green]")
            elif choice == "3":
                config.http.enabled = True
                result = state["result"] or engine.scan(target)
                state["result"] = result
                reporter.results(result.hosts, profile="standard")
            elif choice == "4":
                result = state["result"] or engine.scan(target)
                state["result"] = result
                for host in [h for h in result.hosts if h.technologies][:20]:
                    reporter.emit(f"  {host.host:<40}{', '.join(host.technology_names)}")
            elif choice == "5":
                from .storage.database import Database

                database = Database(config.storage.path)
                database.connect()
                reporter.history(database.history(target))
                database.close()
            elif choice == "6":
                result = state["result"]
                if result is None:
                    reporter.emit("[yellow]Run discovery first.[/yellow]")
                    continue
                path = input("Output file (report.html): ").strip() or "report.html"
                suffix = Path(path).suffix.lower().lstrip(".")
                config.output.format = suffix if suffix in FORMATS else "txt"
                config.output.output = path
                _write_report(result, config, argparse.Namespace(output=path), get_logger())
                reporter.emit(f"[green]Wrote {path}[/green]")
            else:
                reporter.emit("[yellow]Unknown option.[/yellow]")
    finally:
        engine.close()
    return 0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _build_config(args: argparse.Namespace) -> Config:
    """Assemble the effective configuration (file < CLI)."""
    config_path = getattr(args, "config", None) or find_default_config()
    if config_path:
        try:
            config = load_config(config_path)
        except Exception as exc:  # noqa: BLE001
            print(f"warning: could not read {config_path}: {exc}", file=sys.stderr)
            config = Config()
    else:
        config = Config()

    config.merge_cli(args)
    if getattr(args, "profile", None):
        config.apply_profile(args.profile)
    if getattr(args, "tech", False):
        config.http.enabled = True
    if getattr(args, "tls", False):
        config.http.capture_tls = True
        config.http.enabled = True
    if getattr(args, "history", False):
        config.dns.detect_wildcard = config.dns.detect_wildcard
    if getattr(args, "rate_limit", None):
        config.general.rate_limit = float(args.rate_limit)
    if getattr(args, "threads", None):
        config.general.threads = int(args.threads)
    return config


def _setup_logger(args, config: Config):  # noqa: ANN001
    """Configure logging based on verbosity flags."""
    level = "INFO"
    if getattr(args, "verbose", False):
        level = "DEBUG"
    if getattr(args, "debug", False):
        level = "DEBUG"
    if getattr(args, "quiet", False):
        level = "ERROR"
    return setup_logging(
        level=level,
        json_format=(getattr(args, "log_format", None) == "json"),
        color=config.output.color,
        quiet=bool(getattr(args, "quiet", False)),
        log_file=getattr(args, "log_file", None),
    )


def _collect_targets(args: argparse.Namespace) -> List[str]:
    """Return the list of target domains from the CLI."""
    from .discovery.normalize import normalize_host

    targets: List[str] = []
    if args.domain:
        for part in str(args.domain).split(","):
            host = normalize_host(part)
            if host and host not in targets:
                targets.append(host)
    if args.input:
        path = Path(args.input)
        if not path.exists():
            raise SystemExit(f"input file not found: {args.input}")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            host = normalize_host(line.split(",")[0])
            if host and host not in targets:
                targets.append(host)
    return targets


def _build_filters(args, logger):  # noqa: ANN001
    """Build scope/exclusion matchers and compiled regexes."""
    scope = ScopeMatcher(read_pattern_file(args.scope)) if getattr(args, "scope", None) else None
    exclude = ExclusionMatcher(read_pattern_file(args.exclude)) if getattr(args, "exclude", None) else None

    include_regex = None
    exclude_regex = None
    if getattr(args, "include_regex", None):
        try:
            include_regex = re.compile(args.include_regex, re.IGNORECASE)
        except re.error as exc:
            logger.error("Invalid --filter regex: %s", exc)
            return None
    if getattr(args, "exclude_regex", None):
        try:
            exclude_regex = re.compile(args.exclude_regex, re.IGNORECASE)
        except re.error as exc:
            logger.error("Invalid --exclude-regex regex: %s", exc)
            return None
    return scope, exclude, include_regex, exclude_regex


def _parse_sources(value: Optional[str]) -> Optional[List[str]]:
    """Parse the ``--sources`` argument."""
    if not value:
        return None
    parts = [p.strip() for p in str(value).split(",") if p.strip()]
    return parts or None


def _previous_snapshot(engine: Engine, target: str, args) -> Optional[Dict[str, Host]]:  # noqa: ANN001
    """Load the previous DB snapshot so change detection can run."""
    if getattr(args, "no_db", False) or not engine.config.storage.enabled:
        return None
    try:
        return engine.previous_hosts(target)
    except Exception:  # noqa: BLE001
        return None


def _mode_label(config: Config) -> str:
    parts = ["Passive"]
    if config.dns.enabled:
        parts.append("DNS")
    if config.http.enabled:
        parts.append("HTTP")
    if config.http.capture_tls:
        parts.append("TLS")
    return " + ".join(parts)


def _render(result: ScanResult, config: Config, args, reporter) -> None:  # noqa: ANN001
    """Print the configured terminal views."""
    reporter.source_health(result.source_health)
    reporter.statistics(result)

    profile = config.output.profile
    if getattr(args, "bugbounty", False):
        reporter.bugbounty(result)
    elif profile == "detailed":
        reporter.results(result.hosts, profile="detailed")
    else:
        reporter.results(result.hosts, profile=profile)

    if result.changes:
        reporter.diff(result)
    reporter.errors(result.errors)


def _write_report(result: ScanResult, config, args, logger, multiple: bool = False) -> Optional[str]:  # noqa: ANN001
    """Write the report file in the requested format."""
    fmt = (config.output.format or "txt").lower()
    output = getattr(args, "output", None) or config.output.output
    if not output:
        return None

    path = Path(output)
    if multiple:
        stem = path.stem
        suffix = path.suffix or f".{fmt}"
        path = path.with_name(f"{stem}_{result.target.replace('.', '_')}{suffix}")
    if fmt == "auto":
        fmt = (path.suffix.lstrip(".") or "txt").lower()

    try:
        if fmt == "json":
            from .reporting.json import write_json

            write_json(result, str(path))
        elif fmt == "csv":
            from .reporting.csv import write_csv

            write_csv(result, str(path))
        elif fmt == "html":
            from .reporting.html import write_html

            write_html(result, str(path))
        else:
            from .reporting.csv import write_txt

            write_txt(result, str(path), detailed=(config.output.profile == "detailed"))
    except OSError as exc:
        logger.error("Could not write report: %s", exc)
        return None
    logger.info("Report written to %s", path)
    return str(path)


def _catalog(engine: Engine) -> List[Dict[str, Any]]:
    from .sources.registry import source_catalog

    return source_catalog(engine.available_sources())


def _list_sources(args_list: Sequence[str]) -> int:
    """Handle ``--list-sources`` as the first argument."""
    parser = build_parser()
    args = parser.parse_args(list(args_list))
    config = _build_config(args)
    engine = Engine(config)
    from .reporting.terminal import TerminalReporter

    reporter = TerminalReporter(color=not args.no_color)
    reporter.list_sources(_catalog(engine))
    engine.close()
    return 0


def _clear_cache(config: Config) -> int:
    from .storage.cache import ResponseCache

    cache = ResponseCache(root=config.cache.path, ttl=config.cache.ttl, enabled=True)
    return cache.clear()


def _import_report(path: str, config: Config, reporter) -> int:  # noqa: ANN001
    """Import a previous JSON export and render it."""
    from .discovery.diff import hosts_from_json

    try:
        hosts = hosts_from_json(path)
    except (OSError, ValueError) as exc:
        reporter.emit(f"[red]{exc}[/red]")
        return 2

    result = ScanResult(target=path, hosts=list(hosts.values()))
    result.statistics.valid_results = len(hosts)
    result.statistics.started_at = utcnow_iso()
    result.statistics.finished_at = utcnow_iso()
    reporter.emit(f"[green]Imported {len(hosts)} hosts from {path}[/green]")
    reporter.results(result.hosts, profile=config.output.profile)
    return 0


def _json_dumps(value: Any) -> str:  # noqa: ANN401
    import json

    return json.dumps(value, indent=2, default=str, ensure_ascii=False)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
