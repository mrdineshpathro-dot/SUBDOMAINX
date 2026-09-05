"""Core data models for SUBDOMAINX.

The models are plain dataclasses (with ``to_dict`` / ``from_dict`` helpers) so
that the whole pipeline can be serialised to JSON, CSV, HTML and SQLite without
adding a heavy runtime dependency.  Pydantic is available as an optional
validation layer for configuration objects only.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


from .discovery.normalize import normalize_host

def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    """Return the current UTC timestamp as an ISO-8601 string."""
    return utcnow().isoformat(timespec="seconds")


def to_dict(obj: Any) -> Any:  # noqa: ANN401 - deliberately generic
    """Recursively convert dataclasses / enums / containers into plain types."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat(timespec="seconds")
    if isinstance(obj, dict):
        return {str(k): to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_dict(v) for v in obj]
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_dict(getattr(obj, f.name)) for f in fields(obj)}
    return str(obj)


# ---------------------------------------------------------------------------
# enums
# ---------------------------------------------------------------------------


class SourceStatus(str, Enum):
    """Lifecycle state of a passive source adapter."""

    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    ONLINE = "ONLINE"
    RATE_LIMITED = "RATE_LIMITED"
    FAILED = "FAILED"
    UNSUPPORTED = "UNSUPPORTED"
    UNAVAILABLE = "UNAVAILABLE"

    @property
    def ok(self) -> bool:
        return self in (SourceStatus.ONLINE, SourceStatus.ENABLED)


class SourceCategory(str, Enum):
    CERTIFICATE = "certificate"
    DNS = "dns"
    OSINT = "osint"
    WEB = "web"
    SEARCH = "search"
    ARCHIVE = "archive"
    OTHER = "other"


class HTTPCategory(str, Enum):
    """Coarse classification of an HTTP observation."""

    LIVE = "LIVE"
    REDIRECT = "REDIRECT"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    SERVER_ERROR = "SERVER_ERROR"
    TIMEOUT = "TIMEOUT"
    TLS_ERROR = "TLS_ERROR"
    DNS_FAILURE = "DNS_FAILURE"
    UNKNOWN = "UNKNOWN"


class ConfidenceLabel(str, Enum):
    VERY_HIGH = "VERY HIGH"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    VERY_LOW = "VERY LOW"


class WildcardState(str, Enum):
    NONE = "NO WILDCARD"
    PARTIAL = "PARTIAL WILDCARD"
    WILDCARD = "WILDCARD DETECTED"
    UNKNOWN = "UNKNOWN"


class CDNConfidence(str, Enum):
    CONFIRMED = "Confirmed CDN"
    LIKELY = "Likely CDN"
    POSSIBLE = "Possible CDN"
    NONE = "No CDN evidence"


class HostCategory(str, Enum):
    PRODUCTION = "Production"
    DEVELOPMENT = "Development"
    TESTING = "Testing"
    STAGING = "Staging"
    INFRASTRUCTURE = "Infrastructure"
    AUTHENTICATION = "Authentication"
    API = "API"
    MAIL = "Mail"
    MONITORING = "Monitoring"
    CLOUD = "Cloud"
    CDN = "CDN"
    ADMIN = "Admin"
    UNKNOWN = "Unknown"


class ActivityState(str, Enum):
    CURRENT = "CURRENT"
    HISTORICAL = "HISTORICAL"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# source layer
# ---------------------------------------------------------------------------


@dataclass
class HistoricalObservation:
    """A dated sighting of a host coming from an archive / CT source."""

    source: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    observations: int = 1
    currently_observed: bool = False


@dataclass
class SourceObservation:
    """Provenance record: one source seeing one host."""

    source: str
    host: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    count: int = 1
    raw: Optional[str] = None

    def merge(self, other: "SourceObservation") -> None:
        self.count += other.count
        self.first_seen = _min_date(self.first_seen, other.first_seen)
        self.last_seen = _max_date(self.last_seen, other.last_seen)


@dataclass
class SourceResult:
    """Outcome of a single ``PassiveSource.discover()`` call."""

    source: str
    domain: str
    status: SourceStatus = SourceStatus.ENABLED
    hosts: List[str] = field(default_factory=list)
    observations: Dict[str, SourceObservation] = field(default_factory=dict)
    history: Dict[str, HistoricalObservation] = field(default_factory=dict)
    raw_count: int = 0
    #: every candidate string seen, including rejected ones
    raw_observations: int = 0
    #: candidates dropped by the normalization pipeline
    rejected: int = 0
    error: Optional[str] = None
    elapsed_ms: float = 0.0
    http_status: Optional[int] = None
    query_count: int = 0

    @property
    def result_count(self) -> int:
        return len(self.observations) or len(self.hosts)

    def add(
        self,
        host: str,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
        raw: Optional[str] = None,
    ) -> None:
        """Record a hostname sighting, merging duplicates inside the source.

        The candidate is normalized immediately (so URLs, wildcards and ports
        collapse to a canonical host) while the original string is preserved as
        provenance in ``observation.raw``.
        """
        if not host or not str(host).strip():
            return
        self.raw_observations += 1
        key = normalize_host(host)
        if not key:
            self.rejected += 1
            return
        # A source that only reports one timestamp is treated as "seen then".
        last_seen = last_seen or first_seen
        existing = self.observations.get(key)
        if existing is None:
            self.observations[key] = SourceObservation(
                source=self.source,
                host=key,
                first_seen=first_seen,
                last_seen=last_seen,
                raw=raw,
            )
            self.hosts.append(key)
        else:
            existing.merge(
                SourceObservation(
                    source=self.source,
                    host=key,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    raw=raw,
                )
            )

    def add_history(
        self,
        host: str,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
        observations: int = 1,
        currently_observed: bool = False,
    ) -> None:
        key = normalize_host(host)
        if not key:
            return
        rec = self.history.get(key)
        if rec is None:
            self.history[key] = HistoricalObservation(
                source=self.source,
                first_seen=first_seen,
                last_seen=last_seen,
                observations=observations,
                currently_observed=currently_observed,
            )
        else:
            rec.first_seen = _min_date(rec.first_seen, first_seen)
            rec.last_seen = _max_date(rec.last_seen, last_seen)
            rec.observations += observations
            rec.currently_observed = rec.currently_observed or currently_observed


@dataclass
class SourceHealth:
    """Aggregated health / performance metrics for one source adapter."""

    name: str
    category: str = SourceCategory.OTHER.value
    description: str = ""
    status: SourceStatus = SourceStatus.ENABLED
    results: int = 0
    success_count: int = 0
    error_count: int = 0
    rate_limit_events: int = 0
    parser_failures: int = 0
    query_count: int = 0
    total_response_time_ms: float = 0.0
    last_response_time_ms: float = 0.0
    last_http_status: Optional[int] = None
    last_error: Optional[str] = None
    last_success_at: Optional[str] = None
    last_attempt_at: Optional[str] = None

    @property
    def average_response_time_ms(self) -> float:
        if not self.query_count:
            return 0.0
        return round(self.total_response_time_ms / self.query_count, 2)

    def record_success(self, elapsed_ms: float, results: int, http_status: Optional[int]) -> None:
        self.success_count += 1
        self.query_count += 1
        self.results += results
        self.last_response_time_ms = round(elapsed_ms, 2)
        self.total_response_time_ms += elapsed_ms
        self.last_http_status = http_status
        self.last_success_at = utcnow_iso()
        self.last_attempt_at = self.last_success_at
        self.status = SourceStatus.ONLINE

    def record_failure(self, elapsed_ms: float, error: str, status: SourceStatus) -> None:
        self.error_count += 1
        self.query_count += 1
        self.total_response_time_ms += elapsed_ms
        self.last_error = error[:500]
        self.last_attempt_at = utcnow_iso()
        self.status = status

    def to_dict(self) -> Dict[str, Any]:
        data = to_dict(self)
        data["average_response_time_ms"] = self.average_response_time_ms
        return data


# ---------------------------------------------------------------------------
# enrichment models
# ---------------------------------------------------------------------------


@dataclass
class DNSInfo:
    """DNS intelligence for a single hostname."""

    host: str
    resolved: bool = False
    a: List[str] = field(default_factory=list)
    aaaa: List[str] = field(default_factory=list)
    cname: List[str] = field(default_factory=list)
    mx: List[str] = field(default_factory=list)
    ns: List[str] = field(default_factory=list)
    txt: List[str] = field(default_factory=list)
    caa: List[str] = field(default_factory=list)
    soa: List[str] = field(default_factory=list)
    dnssec: Optional[str] = None
    wildcard: bool = False
    internal_looking: bool = False
    error: Optional[str] = None
    queried_at: Optional[str] = None

    @property
    def all_ips(self) -> List[str]:
        return list(self.a) + list(self.aaaa)

    def to_dict(self) -> Dict[str, Any]:
        return to_dict(self)


@dataclass
class TLSInfo:
    """Lightweight TLS certificate metadata (asset correlation only)."""

    host: str
    subject: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    sans: List[str] = field(default_factory=list)
    serial_number: Optional[str] = None
    tls_version: Optional[str] = None
    valid: bool = False
    error: Optional[str] = None


@dataclass
class HTTPObservation:
    """Lightweight HTTP metadata for one hostname."""

    host: str
    url: Optional[str] = None
    final_url: Optional[str] = None
    scheme: Optional[str] = None
    status_code: Optional[int] = None
    category: HTTPCategory = HTTPCategory.UNKNOWN
    title: Optional[str] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    response_time_ms: float = 0.0
    redirect_count: int = 0
    redirect_chain: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    tls: Optional[TLSInfo] = None
    error: Optional[str] = None
    observed_at: Optional[str] = None

    @property
    def live(self) -> bool:
        return self.status_code is not None and self.status_code < 500


@dataclass
class Technology:
    name: str
    category: str = "unknown"
    evidence: str = ""
    confidence: int = 50


@dataclass
class CDNClassification:
    provider: Optional[str] = None
    confidence: CDNConfidence = CDNConfidence.NONE
    evidence: List[str] = field(default_factory=list)


@dataclass
class CloudAsset:
    provider: Optional[str] = None
    service: Optional[str] = None
    cname: Optional[str] = None
    evidence: str = ""
    confidence: int = 50


@dataclass
class ASNInfo:
    ip: str
    asn: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    network: Optional[str] = None
    source: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# aggregated host model
# ---------------------------------------------------------------------------


@dataclass
class Host:
    """A single discovered asset with all correlated intelligence attached."""

    host: str
    domain: str = ""
    registrable_domain: str = ""
    observations: Dict[str, SourceObservation] = field(default_factory=dict)
    history: Dict[str, HistoricalObservation] = field(default_factory=dict)

    confidence: int = 0
    confidence_label: ConfidenceLabel = ConfidenceLabel.VERY_LOW
    confidence_reasons: List[str] = field(default_factory=list)

    dns: Optional[DNSInfo] = None
    http: Optional[HTTPObservation] = None
    tls: Optional[TLSInfo] = None

    technologies: List[Technology] = field(default_factory=list)
    cdn: CDNClassification = field(default_factory=CDNClassification)
    cloud: Optional[CloudAsset] = None
    asn: List[ASNInfo] = field(default_factory=list)

    category: HostCategory = HostCategory.UNKNOWN
    interesting: bool = False
    interesting_reasons: List[str] = field(default_factory=list)
    priority: int = 0
    priority_reasons: List[str] = field(default_factory=list)

    activity: ActivityState = ActivityState.UNKNOWN
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    total_observations: int = 0

    # -- provenance -------------------------------------------------------
    @property
    def sources(self) -> List[str]:
        return sorted(self.observations)

    @property
    def source_count(self) -> int:
        return len(self.observations)

    @property
    def dns_resolved(self) -> bool:
        return bool(self.dns and self.dns.resolved)

    @property
    def http_status(self) -> Optional[int]:
        return self.http.status_code if self.http else None

    @property
    def title(self) -> Optional[str]:
        return self.http.title if self.http else None

    @property
    def technology_names(self) -> List[str]:
        return [t.name for t in self.technologies]

    @property
    def ct_present(self) -> bool:
        return bool({"crtsh", "certspotter", "entrust-ct", "google-ct"} & set(self.observations))

    def add_observation(self, observation: SourceObservation) -> None:
        """Merge a provenance record, keyed by *source* (one entry per source)."""
        key = (observation.source or "").strip().lower()
        if not key:
            return
        canon = normalize_host(observation.host) or observation.host.strip().lower().rstrip(".")
        existing = self.observations.get(key)
        if existing is None:
            merged = SourceObservation(
                source=key,
                host=canon,
                first_seen=observation.first_seen,
                last_seen=observation.last_seen,
                count=observation.count,
                raw=observation.raw,
            )
            self.observations[key] = merged
        else:
            existing.merge(observation)
        self.total_observations += observation.count
        self.first_seen = _min_date(self.first_seen, observation.first_seen)
        self.last_seen = _max_date(self.last_seen, observation.last_seen)

    def add_history(self, record: HistoricalObservation) -> None:
        self.history[record.source] = record
        self.first_seen = _min_date(self.first_seen, record.first_seen)
        self.last_seen = _max_date(self.last_seen, record.last_seen)

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        payload = to_dict(self)
        payload["sources"] = self.sources
        payload["source_count"] = self.source_count
        payload["dns_resolved"] = self.dns_resolved
        payload["http_status"] = self.http_status
        payload["ct_present"] = self.ct_present
        payload["technology"] = self.technology_names
        if not include_raw:
            for obs in payload.get("observations", {}).values():
                obs.pop("raw", None)
        return payload


@dataclass
class ScanStatistics:
    """Counter block rendered in the terminal, JSON, HTML and DB."""

    sources_total: int = 0
    sources_successful: int = 0
    sources_failed: int = 0
    sources_rate_limited: int = 0
    sources_disabled: int = 0

    raw_results: int = 0
    unique_results: int = 0
    valid_results: int = 0
    out_of_scope: int = 0
    invalid_hostnames: int = 0
    filtered_out: int = 0

    dns_resolved: int = 0
    http_probed: int = 0
    http_live: int = 0
    historical: int = 0
    interesting: int = 0
    cloud_assets: int = 0
    cdn_hosts: int = 0

    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        payload = to_dict(self)
        # Aliases kept for compatibility with the documented JSON schema.
        payload["live_hosts"] = int(self.http_live)
        payload["dns_hosts"] = int(self.dns_resolved)
        return payload


@dataclass
class ScanResult:
    """Top level result object produced by :class:`subdomainx.engine.Engine`."""

    target: str
    hosts: List[Host] = field(default_factory=list)
    statistics: ScanStatistics = field(default_factory=ScanStatistics)
    source_health: Dict[str, SourceHealth] = field(default_factory=dict)
    graph: Dict[str, Any] = field(default_factory=dict)
    changes: Optional[Dict[str, Any]] = None
    profile: str = "standard"
    errors: List[str] = field(default_factory=list)

    def hosts_by_confidence(self) -> List[Host]:
        return sorted(self.hosts, key=lambda h: (-h.confidence, h.host))

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        from subdomainx import __version__

        return {
            "tool": "SubdomainX",
            "version": __version__,
            "target": {
                "domain": self.target,
                "registrable_domain": self.hosts[0].registrable_domain if self.hosts else self.target,
            },
            "scan": {
                "started_at": self.statistics.started_at,
                "finished_at": self.statistics.finished_at,
                "duration_seconds": self.statistics.duration_seconds,
                "profile": self.profile,
            },
            "statistics": self.statistics.to_dict(),
            "source_health": {k: v.to_dict() for k, v in self.source_health.items()},
            "sources": [
                {
                    "name": name,
                    "status": health.status.value,
                    "results": health.results,
                    "success": health.success_count,
                    "errors": health.error_count,
                    "average_response_time_ms": health.average_response_time_ms,
                }
                for name, health in sorted(self.source_health.items())
            ],
            "changes": self.changes,
            "hosts": [h.to_dict(include_raw=include_raw) for h in self.hosts_by_confidence()],
            "graph": self.graph,
        }


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _min_date(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a and b:
        return a if a <= b else b
    return a or b


def _max_date(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a and b:
        return a if a >= b else b
    return a or b


def parse_iso_date(value: Optional[str]) -> Optional[str]:
    """Best-effort conversion of many timestamp shapes into ``YYYY-MM-DD``."""
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    candidates = (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%Y%m%d%H%M%S",
        "%Y%m%d",
        "%d-%m-%Y",
    )
    for fmt in candidates:
        try:
            return datetime.strptime(text, fmt).date().isoformat()
        except ValueError:
            continue
    # Fallback: keep the first 10 chars when they look like a date.
    head = text[:10]
    if len(head) == 10 and head[4] == "-" and head[7] == "-":
        return head
    return None
