"""JSON export.

The exported document follows the documented SUBDOMAINX schema::

    {
      "tool": "SubdomainX",
      "version": "1.0.0",
      "target": {"domain": "example.com"},
      "scan":  {"started_at": ..., "finished_at": ..., "duration_seconds": 23, "profile": ...},
      "statistics": {...},
      "hosts": [...]
    }
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .. import __version__
from ..models import Host, ScanResult, to_dict


def render_json(result: ScanResult, indent: int = 2, include_raw: bool = False) -> str:
    """Serialise a :class:`ScanResult` to a JSON string."""
    payload = build_payload(result, include_raw=include_raw)
    return json.dumps(payload, indent=indent, ensure_ascii=False, default=str, sort_keys=False)


def build_payload(result: ScanResult, include_raw: bool = False) -> Dict[str, Any]:
    """Build the complete JSON document for a scan."""
    payload = result.to_dict(include_raw=include_raw)
    payload["version"] = __version__
    payload["hosts"] = [host_payload(h, include_raw=include_raw) for h in result.hosts_by_confidence()]
    payload["summary"] = {
        "hosts": len(result.hosts),
        "interesting": sum(1 for h in result.hosts if h.interesting),
        "live": sum(1 for h in result.hosts if h.http and h.http.status_code and h.http.status_code < 400),
        "historical": sum(1 for h in result.hosts if h.activity.value == "HISTORICAL"),
    }
    return payload


def host_payload(host: Host, include_raw: bool = False) -> Dict[str, Any]:
    """Serialise one host, including a stable ``sources`` provenance block."""
    data = host.to_dict(include_raw=include_raw)
    data["sources"] = [
        {
            "name": observation.source,
            "first_seen": observation.first_seen,
            "last_seen": observation.last_seen,
            "observations": observation.count,
        }
        for name, observation in sorted(host.observations.items())
    ]
    data["interesting_reasons"] = host.interesting_reasons
    data["priority"] = host.priority
    data["activity"] = host.activity.value
    data["category"] = host.category.value
    data["confidence_label"] = host.confidence_label.value
    data["technology"] = [
        {"name": t.name, "category": t.category, "evidence": t.evidence, "confidence": t.confidence}
        for t in host.technologies
    ]
    if host.cdn:
        data["cdn"] = {
            "provider": host.cdn.provider,
            "confidence": host.cdn.confidence.value,
            "evidence": host.cdn.evidence,
        }
    if host.cloud:
        data["cloud"] = to_dict(host.cloud)
    data["asn"] = [to_dict(a) for a in host.asn]
    return data


def write_json(result: ScanResult, path: str, include_raw: bool = False) -> str:
    """Write the JSON report to ``path`` and return the rendered document."""
    document = render_json(result, include_raw=include_raw)
    target = Path(path)
    if target.parent and str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(document, encoding="utf-8")
    return document


def hosts_to_json(hosts: Sequence[Host], target: Optional[str] = None) -> str:
    """Serialise a bare list of hosts (used by ``--import`` round-trips)."""
    payload = {
        "tool": "SubdomainX",
        "version": __version__,
        "target": {"domain": target or ""},
        "hosts": [host_payload(h) for h in hosts],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def parse_json_document(path: str) -> Dict[str, Any]:
    """Read and validate a previously exported JSON document."""
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"file not found: {path}")
    payload = json.loads(target.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(payload, dict):
        raise ValueError("expected a JSON object at the top level")
    if "hosts" not in payload and "results" not in payload:
        raise ValueError("document does not contain a 'hosts' list")
    return payload


def load_hosts_from_json(path: str) -> List[Dict[str, Any]]:
    """Return the host entries of a previously exported JSON document."""
    payload = parse_json_document(path)
    hosts = payload.get("hosts") or payload.get("results") or []
    if not isinstance(hosts, list):
        raise ValueError("'hosts' must be a list")
    return [h for h in hosts if isinstance(h, dict)]
