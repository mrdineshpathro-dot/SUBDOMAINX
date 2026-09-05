"""CSV export.

One row per host with the most useful columns for spreadsheets and downstream
tooling.  Values are flattened (lists joined with ``;``) and never contain
embedded newlines.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, List, Sequence

from ..models import Host, ScanResult

COLUMNS: List[str] = [
    "host",
    "confidence",
    "confidence_label",
    "sources",
    "source_count",
    "dns_resolved",
    "ipv4",
    "ipv6",
    "cname",
    "http_status",
    "http_category",
    "title",
    "server",
    "technology",
    "cdn",
    "cloud_provider",
    "cloud_service",
    "category",
    "interesting",
    "interesting_reasons",
    "priority",
    "activity",
    "first_seen",
    "last_seen",
]


def _clean(value: Any) -> str:  # noqa: ANN401
    """Flatten a value into a single CSV-safe cell."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple, set)):
        return ";".join(str(v) for v in sorted(value) if v is not None)
    text = str(value)
    return " ".join(text.split())


def host_row(host: Host) -> Dict[str, str]:
    """Convert a host into a CSV row dictionary."""
    dns = host.dns
    http = host.http
    return {
        "host": host.host,
        "confidence": str(host.confidence),
        "confidence_label": host.confidence_label.value,
        "sources": _clean(host.sources),
        "source_count": str(host.source_count),
        "dns_resolved": _clean(host.dns_resolved),
        "ipv4": _clean(dns.a if dns else []),
        "ipv6": _clean(dns.aaaa if dns else []),
        "cname": _clean(dns.cname if dns else []),
        "http_status": str(http.status_code) if http and http.status_code is not None else "",
        "http_category": http.category.value if http else "",
        "title": _clean(host.title),
        "server": _clean(http.server if http else None),
        "technology": _clean(host.technology_names),
        "cdn": _clean(host.cdn.provider if host.cdn else None),
        "cloud_provider": _clean(host.cloud.provider if host.cloud else None),
        "cloud_service": _clean(host.cloud.service if host.cloud else None),
        "category": host.category.value,
        "interesting": _clean(host.interesting),
        "interesting_reasons": _clean(host.interesting_reasons),
        "priority": str(host.priority),
        "activity": host.activity.value,
        "first_seen": _clean(host.first_seen),
        "last_seen": _clean(host.last_seen),
    }


def render_csv(hosts: Sequence[Host]) -> str:
    """Render hosts as a CSV document (including the header row)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    for host in hosts or []:
        writer.writerow(host_row(host))
    return buffer.getvalue()


def write_csv(result: ScanResult, path: str) -> str:
    """Write the CSV report and return the rendered document."""
    document = render_csv(result.hosts_by_confidence())
    from pathlib import Path

    target = Path(path)
    if target.parent and str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(document, encoding="utf-8")
    return document


def render_txt(hosts: Sequence[Host], detailed: bool = False) -> str:
    """Render hosts as plain text (one host per line, or host<TAB>score)."""
    if detailed:
        lines = [f"{h.host}\t{h.confidence}\t{h.confidence_label.value}\t{h.category.value}" for h in hosts]
        return "\n".join(lines)
    return "\n".join(h.host for h in hosts)


def write_txt(result: ScanResult, path: str, detailed: bool = False) -> str:
    """Write the TXT report and return the rendered document."""
    from pathlib import Path

    document = render_txt(result.hosts_by_confidence(), detailed=detailed)
    target = Path(path)
    if target.parent and str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(document + "\n", encoding="utf-8")
    return document


def parse_csv(path: str) -> List[Dict[str, str]]:
    """Read back a CSV report (used by ``--import``)."""
    from pathlib import Path

    with Path(path).open("r", encoding="utf-8", errors="replace", newline="") as handle:
        return list(csv.DictReader(handle))


def rows_from_hosts(hosts: Sequence[Host]) -> List[Dict[str, str]]:
    """Return CSV-ready rows for an arbitrary host list."""
    return [host_row(h) for h in hosts or []]


def summary_row(result: ScanResult) -> Dict[str, str]:
    """Return a single-row summary of a scan (useful for dashboards)."""
    stats = result.statistics
    return {
        "host": result.target,
        "confidence": str(stats.valid_results),
        "confidence_label": "hosts",
        "sources": ";".join(sorted(result.source_health)),
        "source_count": str(stats.sources_total),
        "dns_resolved": str(stats.dns_resolved),
        "http_status": str(stats.http_probed),
        "category": "summary",
        "first_seen": str(stats.started_at or ""),
        "last_seen": str(stats.finished_at or ""),
    }
