"""Source correlation.

Aggregation converts per-source results into a single host-centric view.
Beyond simple merging this module builds a *source correlation graph*: the more
independent sources that independently observed a host, the stronger the
evidence that the host really exists.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from itertools import combinations
from typing import Any, Dict, Iterable, List, Sequence

from ..models import Host, SourceResult, to_dict
from ..utils.helpers import unique
from .dedupe import canonical_key
from .normalize import normalize_host
from .validate import registrable_domain


def aggregate_results(
    results: Sequence[SourceResult],
    target: str,
) -> Dict[str, Host]:
    """Merge all :class:`SourceResult` objects into :class:`Host` records."""
    hosts: Dict[str, Host] = {}
    registrable = registrable_domain(target) or target

    for result in results or []:
        for raw_host, observation in (result.observations or {}).items():
            host_key = normalize_host(raw_host) or canonical_key(raw_host)
            if not host_key:
                continue
            record = hosts.get(host_key)
            if record is None:
                record = Host(
                    host=host_key,
                    domain=target,
                    registrable_domain=registrable,
                )
                hosts[host_key] = record
            record.add_observation(observation)

        for raw_host, history in (result.history or {}).items():
            host_key = normalize_host(raw_host) or canonical_key(raw_host)
            if not host_key:
                continue
            record = hosts.get(host_key)
            if record is None:
                record = Host(
                    host=host_key,
                    domain=target,
                    registrable_domain=registrable,
                )
                hosts[host_key] = record
            record.add_history(history)

    return hosts


def build_source_graph(hosts: Iterable[Host]) -> Dict[str, Any]:
    """Build the internal host <-> source correlation graph.

    Returns a JSON-serialisable structure containing nodes, edges and the
    strongest co-occurrence pairs (useful for the HTML report).
    """
    host_records = list(hosts or [])
    source_hosts: Dict[str, List[str]] = defaultdict(list)
    co_occurrence: Counter = Counter()
    edges: List[Dict[str, Any]] = []

    for host in host_records:
        sources = sorted(host.observations)
        for source in sources:
            source_hosts[source].append(host.host)
            edges.append({"source": source, "host": host.host})
        for a, b in combinations(sources, 2):
            co_occurrence[(a, b)] += 1

    nodes = [
        {
            "id": f"source:{name}",
            "type": "source",
            "label": name,
            "hosts": len(set(items)),
        }
        for name, items in sorted(source_hosts.items())
    ]
    nodes += [
        {
            "id": f"host:{host.host}",
            "type": "host",
            "label": host.host,
            "sources": host.source_count,
            "confidence": host.confidence,
        }
        for host in sorted(host_records, key=lambda h: (-h.confidence, h.host))
    ]

    strongest = [
        {"sources": list(pair), "shared_hosts": count}
        for pair, count in co_occurrence.most_common(10)
    ]

    return {
        "nodes": nodes,
        "edges": edges[:5000],
        "edge_count": len(edges),
        "co_occurrence": strongest,
        "sources": {name: len(set(items)) for name, items in sorted(source_hosts.items())},
    }


def source_diversity(host: Host) -> int:
    """Number of *independent* source categories that observed a host."""
    return len(host.sources)


def correlate_ct_dns_http(host: Host) -> Dict[str, bool]:
    """Return the CT / DNS / HTTP correlation triple used in reports."""
    return {
        "ct": host.ct_present,
        "dns": host.dns_resolved,
        "http": bool(host.http and host.http.status_code is not None),
    }


def unique_sources(results: Sequence[SourceResult]) -> List[str]:
    """All source names present in a set of results."""
    return unique([r.source for r in (results or []) if r.source])


def host_source_matrix(hosts: Sequence[Host]) -> Dict[str, List[str]]:
    """``{host: [sources]}`` view used by the CSV/HTML exporters."""
    return {host.host: host.sources for host in hosts or []}


def to_plain(obj: Any) -> Any:  # noqa: ANN401
    """Serialise any model object to plain Python types."""
    return to_dict(obj)
