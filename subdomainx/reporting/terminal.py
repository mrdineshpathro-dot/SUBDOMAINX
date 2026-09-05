"""Terminal reporting.

Produces the polished console interface: banner, phase progress, source-health
dashboard, statistics tree, result tables, detailed host views, diff output and
the bug-bounty friendly view.

``rich`` is used for colour when available; the layout itself is produced by
SUBDOMAINX so output stays deterministic and testable.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

from ..models import (
    ConfidenceLabel,
    Host,
    ScanResult,
    SourceHealth,
    SourceStatus,
    to_dict,
)
from ..utils.helpers import truncate

_STATUS_COLORS = {
    SourceStatus.ONLINE: "green",
    SourceStatus.ENABLED: "cyan",
    SourceStatus.RATE_LIMITED: "yellow",
    SourceStatus.FAILED: "red",
    SourceStatus.UNAVAILABLE: "red",
    SourceStatus.UNSUPPORTED: "dim",
    SourceStatus.DISABLED: "dim",
}

_CONFIDENCE_COLORS = {
    ConfidenceLabel.VERY_HIGH: "bold green",
    ConfidenceLabel.HIGH: "green",
    ConfidenceLabel.MEDIUM: "yellow",
    ConfidenceLabel.LOW: "magenta",
    ConfidenceLabel.VERY_LOW: "red",
}


class TerminalReporter:
    """Renders scan results to the terminal."""

    def __init__(self, color: bool = True, quiet: bool = False, width: int = 100) -> None:
        self.color = color
        self.quiet = quiet
        self.width = width
        self.console = None
        if color:
            try:
                from rich.console import Console

                self.console = Console(highlight=False, soft_wrap=True)
            except Exception:  # pragma: no cover - rich is optional at runtime
                self.console = None

    # -- primitives --------------------------------------------------------
    def emit(self, text: str = "") -> None:
        """Print one line through rich (if available) or plain stdout."""
        if self.quiet and text.strip():
            return
        if self.console is not None:
            self.console.print(text)
        else:
            print(_strip_markup(text))

    def rule(self, title: str = "") -> None:
        """Print a horizontal rule with an optional title."""
        line = "─" * max(10, self.width - len(title) - 4)
        self.emit(f"[dim]{title} {line}[/dim]" if title else f"[dim]{'─' * self.width}[/dim]")

    # -- header ------------------------------------------------------------
    def banner(self, version: str = "1.0.0") -> None:
        """Print the SUBDOMAINX banner."""
        inner = self.width - 4
        top = "╔" + "═" * inner + "╗"
        bottom = "╚" + "═" * inner + "╝"
        title = f"SUBDOMAINX v{version}"
        subtitle = "Passive Subdomain Discovery & Intelligence"
        self.emit(f"[cyan]{top}[/cyan]")
        self.emit(f"[cyan]║[/cyan][bold]{title.center(inner)}[/bold][cyan]║[/cyan]")
        self.emit(f"[cyan]║[/cyan][dim]{subtitle.center(inner)}[/dim][cyan]║[/cyan]")
        self.emit(f"[cyan]{bottom}[/cyan]")

    def scan_header(self, target: str, mode: str, source_count: int) -> None:
        """Print the target summary block shown right after the banner."""
        self.emit("")
        self.emit(f"[bold]Target:[/bold] {target}")
        self.emit(f"[bold]Mode:[/bold] {mode}")
        self.emit("[bold]API Keys:[/bold] [green]NONE[/green]")
        self.emit("[bold]Authentication Required:[/bold] [green]NONE[/green]")
        self.emit(f"[bold]Sources:[/bold] {source_count}")

    def phase(self, step: int, total: int, message: str) -> None:
        """Print a pipeline phase indicator."""
        self.emit(f"[cyan][{step}/{total}][/cyan] {message}...")

    # -- dashboards --------------------------------------------------------
    def source_health(self, health: Dict[str, SourceHealth]) -> None:
        """Print the source-health dashboard."""
        if not health:
            return
        self.emit("")
        self.emit("[bold]SOURCE HEALTH[/bold]")
        self.rule()
        self.emit(f"{'SOURCE':<22}{'STATUS':<15}{'RESULTS':>9}{'LATENCY':>10}{'ERRORS':>8}")
        for name, entry in sorted(health.items()):
            color = _STATUS_COLORS.get(entry.status, "white")
            status = entry.status.value.replace("_", " ")
            self.emit(
                f"{truncate(name, 20):<22}"
                f"[{color}]{status:<15}[/{color}]"
                f"{entry.results:>9}"
                f"{entry.average_response_time_ms:>9.0f}ms"
                f"{entry.error_count:>8}"
            )
        self.rule()
        for name, entry in sorted(health.items()):
            if entry.last_error:
                self.emit(f"  [dim]{name}: {truncate(entry.last_error, 80)}[/dim]")

    def statistics(self, result: ScanResult) -> None:
        """Print the scan statistics block."""
        stats = result.statistics
        self.emit("")
        self.emit("[bold]SCAN STATISTICS[/bold]")
        self.rule()
        self.emit(
            f"Sources:      {stats.sources_total} total  "
            f"[green]{stats.sources_successful} successful[/green]  "
            f"[red]{stats.sources_failed} failed[/red]"
            + (f"  [yellow]{stats.sources_rate_limited} rate limited[/yellow]" if stats.sources_rate_limited else "")
        )
        self.emit(
            f"Discovery:    {stats.raw_results} raw  "
            f"{stats.unique_results} unique  [green]{stats.valid_results} valid[/green]"
            + (f"  [dim]{stats.out_of_scope} out of scope[/dim]" if stats.out_of_scope else "")
            + (f"  [dim]{stats.invalid_hostnames} invalid[/dim]" if stats.invalid_hostnames else "")
        )
        self.emit(
            f"Enrichment:   {stats.dns_resolved} DNS  {stats.http_probed} HTTP  "
            f"[green]{stats.http_live} live[/green]  {stats.interesting} interesting  "
            f"{stats.historical} historical"
        )
        self.emit(
            f"Assets:       {stats.cdn_hosts} CDN  {stats.cloud_assets} cloud"
        )
        self.emit(f"Duration:     {stats.duration_seconds:.2f}s")

    # -- results -----------------------------------------------------------
    def results(self, hosts: Sequence[Host], profile: str = "standard") -> None:
        """Print the host table in the requested output profile."""
        if profile == "minimal":
            for host in hosts:
                self.emit(host.host)
            return

        if profile == "detailed":
            self.detailed(hosts)
            return

        self.emit("")
        self.emit("[bold]RESULTS[/bold]")
        self.rule()
        header = f"{'HOST':<40}{'SCORE':>6}  {'LBL':<10}{'SRC':>4}  {'DNS':<4}{'HTTP':>5}  {'CATEGORY':<16}TITLE"
        self.emit(f"[dim]{header}[/dim]")
        for host in hosts:
            score_color = _CONFIDENCE_COLORS.get(host.confidence_label, "white")
            dns = "YES" if host.dns_resolved else ("NO" if host.dns else "-")
            status = str(host.http.status_code) if host.http and host.http.status_code else "-"
            self.emit(
                f"{truncate(host.host, 39):<40}"
                f"[{score_color}]{host.confidence:>6}[/{score_color}]  "
                f"{host.confidence_label.value:<10}"
                f"{host.source_count:>4}  {dns:<4}{status:>5}  "
                f"{host.category.value:<16}{truncate(host.title or '', 40)}"
            )
        self.rule()

    def detailed(self, hosts: Sequence[Host]) -> None:
        """Print one multi-line block per host."""
        for host in hosts:
            self.emit("")
            self.emit(f"[bold cyan]{host.host}[/bold cyan]")
            self.emit(f"  {'SOURCES':<14}: {host.source_count} ({', '.join(host.sources) or 'none'})")
            self.emit(f"  {'CONFIDENCE':<14}: {host.confidence} {host.confidence_label.value}")
            for reason in host.confidence_reasons[:4]:
                self.emit(f"  {'':<14}  [dim]{reason}[/dim]")
            if host.dns:
                dns = host.dns
                self.emit(f"  {'DNS':<14}: {'resolved' if dns.resolved else 'no records'}")
                for rtype, values in (
                    ("A", dns.a),
                    ("AAAA", dns.aaaa),
                    ("CNAME", dns.cname),
                    ("MX", dns.mx),
                    ("NS", dns.ns),
                    ("TXT", dns.txt),
                    ("CAA", dns.caa),
                ):
                    if values:
                        self.emit(f"  {'':<14}  {rtype}: {', '.join(values[:4])}")
                if dns.dnssec:
                    self.emit(f"  {'DNSSEC':<14}: {dns.dnssec}")
                if dns.wildcard:
                    self.emit("  [yellow]WILDCARD: answer matches wildcard DNS[/yellow]")
            if host.http:
                http = host.http
                self.emit(
                    f"  {'HTTP':<14}: {http.status_code or '-'} {http.category.value} "
                    f"({http.response_time_ms:.0f} ms, {http.redirect_count} redirect(s))"
                )
                if http.title:
                    self.emit(f"  {'TITLE':<14}: {truncate(http.title, 60)}")
                if http.server:
                    self.emit(f"  {'SERVER':<14}: {truncate(http.server, 60)}")
            if host.tls:
                self.emit(
                    f"  {'TLS':<14}: issuer={host.tls.issuer} valid_until={host.tls.valid_until} "
                    f"sans={len(host.tls.sans)}"
                )
            if host.technologies:
                self.emit(f"  {'TECHNOLOGY':<14}: {', '.join(host.technology_names[:8])}")
            if host.cdn and host.cdn.provider:
                self.emit(f"  {'CDN':<14}: {host.cdn.provider} ({host.cdn.confidence.value})")
            if host.cloud:
                self.emit(
                    f"  {'CLOUD':<14}: {host.cloud.provider} / {host.cloud.service} "
                    f"({host.cloud.confidence}%)"
                )
            self.emit(f"  {'CATEGORY':<14}: {host.category.value}")
            if host.interesting:
                self.emit("  [yellow]INTERESTING HOST[/yellow]")
                for reason in host.interesting_reasons[:3]:
                    self.emit(f"  [yellow]REASON: {reason}[/yellow]")
            self.emit(
                f"  {'FIRST SEEN':<14}: {host.first_seen or 'unknown'}    "
                f"{'LAST SEEN':<10}: {host.last_seen or 'unknown'}"
            )
            self.emit(f"  {'ACTIVITY':<14}: {host.activity.value}")

    def bugbounty(self, result: ScanResult) -> None:
        """Print the authorized-research view (no vulnerability claims)."""
        hosts = result.hosts
        groups: List[tuple] = [
            ("INTERESTING HOSTS (administrative / auth / dev)", lambda h: h.interesting and h.priority >= 80),
            ("LIVE HOSTS", lambda h: bool(h.http and h.http.status_code and h.http.status_code < 400)),
            ("API-LIKE HOSTS", lambda h: h.category.value == "API"),
            ("AUTH-LIKE HOSTS", lambda h: h.category.value == "AUTHENTICATION"),
            ("DEVELOPMENT / TESTING HOSTS", lambda h: h.category.value in {"DEVELOPMENT", "TESTING", "STAGING", "Development", "Testing", "Staging"}),
            ("CLOUD HOSTS", lambda h: h.cloud is not None),
            ("CDN-FRONTED HOSTS", lambda h: bool(h.cdn and h.cdn.provider)),
            ("HISTORICAL HOSTS", lambda h: h.activity.value == "HISTORICAL"),
        ]
        self.emit("")
        self.emit("[bold]AUTHORIZED RESEARCH VIEW[/bold]  [dim](prioritisation only - not vulnerabilities)[/dim]")
        for title, predicate in groups:
            matching = [h for h in hosts if _safe_predicate(predicate, h)]
            if not matching:
                continue
            self.emit("")
            self.emit(f"[bold cyan]{title}[/bold cyan]  [dim]({len(matching)})[/dim]")
            self.rule()
            for host in matching[:40]:
                status = str(host.http.status_code) if host.http and host.http.status_code else "-"
                reasons = host.interesting_reasons[0] if host.interesting_reasons else host.category.value
                self.emit(
                    f"  {truncate(host.host, 38):<40}{host.confidence:>4}  {status:>5}  {reasons}"
                )
            if len(matching) > 40:
                self.emit(f"  [dim]... {len(matching) - 40} more[/dim]")

    def diff(self, result: ScanResult) -> None:
        """Print new / removed / changed hosts."""
        changes = result.changes or {}
        self.emit("")
        self.emit("[bold]CHANGES[/bold]")
        for title, key, color in (
            ("NEW SUBDOMAINS", "new", "green"),
            ("REMOVED SUBDOMAINS", "removed", "red"),
        ):
            values = changes.get(key) or []
            self.emit("")
            self.emit(f"[bold {color}]{title}[/bold {color}]")
            self.rule()
            if not values:
                self.emit("  [dim]none[/dim]")
            for value in values[:200]:
                self.emit(f"  [{color}]{value}[/{color}]")
            if len(values) > 200:
                self.emit(f"  [dim]... {len(values) - 200} more[/dim]")

        changed = changes.get("changed") or []
        self.emit("")
        self.emit("[bold yellow]CHANGED HOSTS[/bold yellow]")
        self.rule()
        if not changed:
            self.emit("  [dim]none[/dim]")
        for record in changed[:50]:
            self.emit(f"  [bold]{record['host']}[/bold]")
            for note in record.get("changes", [])[:4]:
                self.emit(f"    [yellow]{note}[/yellow]")

        if changes.get("unchanged") is not None:
            self.emit("")
            self.emit(f"UNCHANGED: {changes['unchanged']} hosts")

    def list_sources(self, catalog: Sequence[Dict[str, Any]]) -> None:
        """Print the source catalogue (``--list-sources``)."""
        self.emit("")
        self.emit("[bold]AVAILABLE PASSIVE SOURCES[/bold]")
        self.rule()
        self.emit(f"{'NAME':<20}{'CATEGORY':<14}{'KEY':<6}{'ENABLED':<9}DESCRIPTION")
        for item in catalog:
            key = "yes" if item.get("requires_api_key") else "no"
            enabled = "yes" if item.get("enabled") else "no"
            color = "red" if item.get("requires_api_key") else "green"
            self.emit(
                f"{item['name']:<20}{item.get('category', ''):<14}"
                f"[{color}]{key:<6}[/{color}]{enabled:<9}{truncate(item.get('description', ''), 48)}"
            )
        self.rule()
        self.emit("[dim]Sources marked KEY=yes are skipped: SUBDOMAINX never uses credentials.[/dim]")

    def database_stats(self, stats: Dict[str, Any]) -> None:
        """Print ``stats <domain>`` output."""
        self.emit("")
        self.emit(f"[bold]DATABASE STATISTICS[/bold]  {stats.get('domain','')}")
        self.rule()
        for key, value in stats.items():
            if key in {"sources", "categories"}:
                continue
            self.emit(f"  {key:<26}: {value}")
        categories = stats.get("categories") or {}
        if categories:
            self.emit("  categories:")
            for name, count in categories.items():
                self.emit(f"    {name:<24}: {count}")
        sources = stats.get("sources") or []
        if sources:
            self.emit("")
            self.emit(f"{'SOURCE':<22}{'STATUS':<14}{'RESULTS':>9}{'LATENCY':>10}{'ERRORS':>8}")
            for item in sources:
                self.emit(
                    f"{item['name']:<22}{item.get('status',''):<14}{item.get('results',0):>9}"
                    f"{item.get('response_time_ms',0):>9.0f}ms{item.get('error_count',0):>8}"
                )

    def history(self, rows: Sequence[Dict[str, Any]]) -> None:
        """Print ``history <domain>`` output."""
        self.emit("")
        self.emit("[bold]HISTORY[/bold]")
        self.rule()
        self.emit(f"{'HOST':<40}{'FIRST SEEN':<14}{'LAST SEEN':<14}{'ACTIVITY':<12}{'SRC':>4}{'CONF':>6}")
        for row in rows:
            self.emit(
                f"{truncate(row.get('host',''), 39):<40}"
                f"{str(row.get('first_seen') or '-'):<14}"
                f"{str(row.get('last_seen') or '-'):<14}"
                f"{str(row.get('activity') or '-'):<12}"
                f"{int(row.get('sources') or 0):>4}"
                f"{int(row.get('confidence') or 0):>6}"
            )
        self.rule()

    def host_list(self, title: str, rows: Sequence[Any]) -> None:
        """Print a simple list of hostnames under a heading."""
        self.emit("")
        self.emit(f"[bold]{title}[/bold]")
        self.rule()
        if not rows:
            self.emit("  [dim]none[/dim]")
        for row in rows:
            if isinstance(row, dict):
                host = row.get("host") or row.get("hostname") or ""
                extra = row.get("confidence")
                self.emit(f"  {host}{f'  ({extra})' if extra is not None else ''}")
            else:
                self.emit(f"  {row}")
        self.rule()

    def watch_update(self, target: str, interval: int, previous: int, current: int, new: Sequence[str]) -> None:
        """Print one watch-mode iteration summary."""
        self.emit("")
        self.emit("=" * self.width)
        self.emit("[bold]SUBDOMAINX WATCH MODE[/bold]")
        self.emit("=" * self.width)
        self.emit(f"Target: {target}")
        self.emit(f"Interval: {interval} seconds")
        self.emit(f"Previous: {previous}")
        self.emit(f"Current: {current}")
        if new:
            self.emit("")
            self.emit("[bold green]NEW:[/bold green]")
            for host in new[:50]:
                self.emit(f"  {host}")

    def errors(self, errors: Sequence[str]) -> None:
        """Print non-fatal errors collected during the scan."""
        if not errors:
            return
        self.emit("")
        self.emit("[bold]NON-FATAL ISSUES[/bold]")
        self.rule()
        for message in errors[:20]:
            self.emit(f"  [dim]{truncate(message, self.width - 4)}[/dim]")

    def finish(self, message: str = "Scan completed successfully.") -> None:
        """Print the closing line."""
        self.emit("")
        self.emit(f"[bold green]{message}[/bold green]")


def _safe_predicate(predicate, host: Host) -> bool:
    try:
        return bool(predicate(host))
    except Exception:  # noqa: BLE001
        return False


def _strip_markup(text: str) -> str:
    """Remove rich markup tags from a string."""
    import re

    return re.sub(r"\[/?[a-z ]+/?\]", "", str(text))


def render_hosts_plain(hosts: Iterable[Host]) -> str:
    """Render hosts as a plain newline separated list (TXT export helper)."""
    return "\n".join(h.host for h in hosts)


def render_summary(result: ScanResult) -> Dict[str, Any]:
    """Return a compact summary dictionary (used by JSON exports and tests)."""
    return {
        "target": result.target,
        "statistics": to_dict(result.statistics),
        "hosts": [h.host for h in result.hosts],
    }
