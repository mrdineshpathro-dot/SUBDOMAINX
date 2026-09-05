"""Diffing and change detection.

Two complementary things are computed here:

1. **Set diff** - which hosts are new, removed or unchanged compared with a
   previous run (``--diff FILE`` / ``--baseline FILE``).
2. **Attribute diff** - what changed *about* a host: DNS answers, CNAME target,
   HTTP status, page title, detected technology (``CHANGE DETECTED``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..models import Host
from .normalize import normalize_host


@dataclass
class DiffResult:
    """Outcome of comparing two host sets."""

    new: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    unchanged: List[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.new or self.removed)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "new": self.new,
            "removed": self.removed,
            "unchanged_count": len(self.unchanged),
        }


@dataclass
class ChangeRecord:
    """A single host whose observable attributes changed between runs."""

    host: str
    changes: List[str] = field(default_factory=list)
    previous: Dict[str, Any] = field(default_factory=dict)
    current: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "changes": self.changes,
            "previous": self.previous,
            "current": self.current,
        }


def diff_host_lists(previous: Iterable[str], current: Iterable[str]) -> DiffResult:
    """Compare two hostname collections, returning new/removed/unchanged."""
    before = {normalize_host(h) for h in (previous or [])}
    after = {normalize_host(h) for h in (current or [])}
    before.discard(None)
    after.discard(None)
    return DiffResult(
        new=sorted(after - before),
        removed=sorted(before - after),
        unchanged=sorted(before & after),
    )


def load_previous_hosts(path: str) -> List[str]:
    """Load hostnames from a previous JSON/TXT/CSV export."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"baseline file not found: {path}")

    text = file_path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []

    if file_path.suffix.lower() == ".json":
        try:
            payload = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"invalid JSON baseline: {exc}") from exc
        return _hosts_from_payload(payload)

    if file_path.suffix.lower() == ".csv":
        import csv as _csv
        import io

        reader = _csv.DictReader(io.StringIO(text))
        column = None
        if reader.fieldnames:
            for candidate in ("host", "hostname", "domain", "subdomain"):
                if candidate in [c.lower() for c in reader.fieldnames]:
                    column = next(c for c in reader.fieldnames if c.lower() == candidate)
                    break
        hosts = [normalize_host(row.get(column or "", "")) for row in reader]
        return [h for h in hosts if h]

    return [h for h in (normalize_host(line) for line in text.splitlines()) if h]


def _hosts_from_payload(payload: Any) -> List[str]:
    """Extract hostnames from an exported JSON document (any known shape)."""
    hosts: List[str] = []
    if isinstance(payload, dict):
        for key in ("hosts", "results", "subdomains", "domains"):
            value = payload.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        hosts.append(item)
                    elif isinstance(item, dict):
                        for field_name in ("host", "hostname", "domain", "name"):
                            if item.get(field_name):
                                hosts.append(str(item[field_name]))
                                break
            if hosts:
                break
        if not hosts and isinstance(payload.get("target"), dict):
            hosts = []
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, str):
                hosts.append(item)
            elif isinstance(item, dict):
                for field_name in ("host", "hostname", "domain", "name"):
                    if item.get(field_name):
                        hosts.append(str(item[field_name]))
                        break
    return [h for h in (normalize_host(h) for h in hosts) if h]


def _signature(host: Host) -> Dict[str, Any]:
    """Reduce a host to the attributes we compare between runs."""
    return {
        "dns_a": sorted((host.dns.a if host.dns else []) or []),
        "dns_aaaa": sorted((host.dns.aaaa if host.dns else []) or []),
        "cname": sorted((host.dns.cname if host.dns else []) or []),
        "resolved": bool(host.dns and host.dns.resolved),
        "http_status": host.http.status_code if host.http else None,
        "title": host.http.title if host.http else None,
        "server": host.http.server if host.http else None,
        "technology": sorted(host.technology_names),
        "sources": host.sources,
        "confidence": host.confidence,
    }


def diff_hosts(previous: Dict[str, Host], current: Dict[str, Host]) -> List[ChangeRecord]:
    """Compare hosts attribute by attribute and describe what changed."""
    changes: List[ChangeRecord] = []
    for name, current_host in (current or {}).items():
        previous_host = (previous or {}).get(name)
        if previous_host is None:
            continue
        before = _signature(previous_host)
        after = _signature(current_host)
        notes: List[str] = []
        for key in before:
            if before[key] == after[key]:
                continue
            if key == "confidence":
                notes.append(f"confidence {before[key]} -> {after[key]}")
            elif key == "sources":
                added = sorted(set(after[key]) - set(before[key]))
                removed = sorted(set(before[key]) - set(after[key]))
                if added:
                    notes.append(f"new source(s): {', '.join(added)}")
                if removed:
                    notes.append(f"source(s) no longer observing: {', '.join(removed)}")
            else:
                notes.append(f"{key}: {_render(before[key])} -> {_render(after[key])}")
        if notes:
            changes.append(
                ChangeRecord(
                    host=name,
                    changes=notes,
                    previous={k: before[k] for k in before if before[k] != after[k]},
                    current={k: after[k] for k in after if before[k] != after[k]},
                )
            )
    return sorted(changes, key=lambda c: c.host)


def hosts_from_json(path: str) -> Dict[str, Host]:
    """Rebuild a ``{host: Host}`` mapping from an exported JSON document.

    Only the fields needed for change detection are reconstructed.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    hosts: Dict[str, Host] = {}
    entries = payload.get("hosts") if isinstance(payload, dict) else payload
    for entry in entries or []:
        if isinstance(entry, str):
            host = Host(host=entry)
            hosts[entry] = host
            continue
        if not isinstance(entry, dict):
            continue
        name = entry.get("host") or entry.get("hostname")
        if not name:
            continue
        hosts[str(name)] = _host_from_dict(entry)
    return hosts


def _host_from_dict(entry: Dict[str, Any]) -> Host:
    from ..models import DNSInfo, HTTPObservation

    host = Host(
        host=str(entry.get("host")),
        domain=str(entry.get("domain") or ""),
        registrable_domain=str(entry.get("registrable_domain") or ""),
        confidence=int(entry.get("confidence") or 0),
    )
    dns = entry.get("dns") or {}
    if isinstance(dns, dict) and dns:
        host.dns = DNSInfo(
            host=host.host,
            resolved=bool(dns.get("resolved")),
            a=list(dns.get("a") or []),
            aaaa=list(dns.get("aaaa") or []),
            cname=list(dns.get("cname") or []),
        )
    http = entry.get("http") or {}
    if isinstance(http, dict) and http:
        host.http = HTTPObservation(
            host=host.host,
            status_code=http.get("status_code"),
            title=http.get("title"),
            server=http.get("server"),
        )
    for tech in entry.get("technology") or []:
        if isinstance(tech, str):
            host.technologies.append(_technology(tech))
        elif isinstance(tech, dict) and tech.get("name"):
            host.technologies.append(_technology(str(tech["name"])))
    for source in entry.get("sources") or []:
        from ..models import SourceObservation

        if isinstance(source, str):
            host.observations[source] = SourceObservation(source=source, host=host.host)
        elif isinstance(source, dict) and source.get("name"):
            host.observations[str(source["name"])] = SourceObservation(
                source=str(source["name"]), host=host.host
            )
    return host


def _technology(name: str):
    from ..models import Technology

    return Technology(name=name, category="unknown", evidence="imported", confidence=50)


def _render(value: Any) -> str:  # noqa: ANN401
    if value is None:
        return "none"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in sorted(value)) or "none"
    return str(value)


def summarize_changes(records: Sequence[ChangeRecord]) -> Dict[str, int]:
    """Count how many hosts changed per attribute."""
    summary: Dict[str, int] = {}
    for record in records or []:
        for change in record.changes:
            key = change.split(":", 1)[0].split(" ")[0]
            summary[key] = summary.get(key, 0) + 1
    return dict(sorted(summary.items(), key=lambda kv: (-kv[1], kv[0])))


def build_changes_payload(
    diff: Optional[DiffResult],
    changes: Optional[Sequence[ChangeRecord]],
    force: bool = False,
) -> Optional[Dict[str, Any]]:
    """Shape the ``changes`` block of the JSON/HTML output.

    ``force`` produces the block even when nothing changed (used when the user
    explicitly asked for change detection against a stored baseline).
    """
    if diff is None and not changes and not force:
        return None
    return {
        "new": diff.new if diff else [],
        "removed": diff.removed if diff else [],
        "unchanged": len(diff.unchanged) if diff else 0,
        "changed": [c.to_dict() for c in (changes or [])],
        "summary": summarize_changes(changes or []),
    }
