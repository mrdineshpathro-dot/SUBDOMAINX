"""Result de-duplication.

Duplicates are removed across every axis that sources can disagree on:

* letter case            ``API.example.com``  ==  ``api.example.com``
* trailing dots          ``api.example.com.`` ==  ``api.example.com``
* URL scheme / ports     ``https://api.example.com:443/x``
* wildcard notation      ``*.api.example.com``
* repeated separators    ``api..example.com``
* source duplication     five sources reporting the same host

Provenance is preserved: de-duplication merges observation records, it never
discards the information about *who* saw a host and *when*.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence

from ..models import Host, SourceObservation
from .normalize import normalize_host


def canonical_key(host: str) -> str:
    """Return the canonical deduplication key for a hostname."""
    return normalize_host(host) or str(host or "").strip().lower().rstrip(".")


def dedupe_raw(values: Iterable[object]) -> List[str]:
    """Normalise and de-duplicate a raw list of strings."""
    seen: Dict[str, str] = {}
    for value in values or []:
        host = normalize_host(value)
        if not host:
            continue
        seen.setdefault(host, host)
    return sorted(seen)


def dedupe_hosts(hosts: Sequence[str]) -> List[str]:
    """De-duplicate hostnames that are already normalised-ish."""
    return dedupe_raw(hosts)


def dedupe_observations(observations: Iterable[SourceObservation]) -> Dict[str, SourceObservation]:
    """Merge observations referring to the same canonical host."""
    merged: Dict[str, SourceObservation] = {}
    for observation in observations or []:
        key = canonical_key(observation.host)
        if not key:
            continue
        existing = merged.get(key)
        if existing is None:
            merged[key] = SourceObservation(
                source=observation.source,
                host=key,
                first_seen=observation.first_seen,
                last_seen=observation.last_seen,
                count=observation.count,
                raw=observation.raw,
            )
        else:
            existing.merge(observation)
    return merged


def dedupe_host_records(hosts: Iterable[Host]) -> Dict[str, Host]:
    """Merge :class:`Host` records that describe the same canonical hostname."""
    merged: Dict[str, Host] = {}
    for host in hosts or []:
        key = canonical_key(host.host)
        if not key:
            continue
        target = merged.get(key)
        if target is None:
            host.host = key
            merged[key] = host
            continue
        for observation in list(host.observations.values()):
            target.add_observation(observation)
        for record in list(host.history.values()):
            target.add_history(record)
    return merged
