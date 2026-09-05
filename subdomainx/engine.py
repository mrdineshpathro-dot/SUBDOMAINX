"""The SUBDOMAINX orchestration engine.

Pipeline::

    Collection -> Normalization -> Validation -> Deduplication -> Correlation
    -> DNS enrichment -> HTTP enrichment -> Technology detection
    -> Cloud/CDN classification -> Scoring -> Interesting host identification
    -> Historical comparison -> Export / Reporting

Every stage is isolated: a failure anywhere is recorded and the pipeline keeps
going.  A scan never aborts just because one source, one DNS query or one HTTP
probe misbehaved.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Sequence

from .config import Config
from .discovery.classify import classify_host
from .discovery.correlate import aggregate_results, build_source_graph
from .discovery.diff import (
    DiffResult,
    build_changes_payload,
    diff_host_lists,
    diff_hosts,
    load_previous_hosts,
)
from .discovery.normalize import normalize_host
from .discovery.score import compute_priority, label_for_score, rank_hosts, score_host
from .discovery.validate import (
    ExclusionMatcher,
    ScopeMatcher,
    filter_hosts,
    is_in_scope,
    registrable_domain,
)
from .enrichment.asn import ASNEnricher
from .enrichment.cdn import classify_cdn
from .enrichment.cloud import detect_cloud_asset
from .enrichment.dns import DNSOptions, DNSEngine, WildcardReport
from .enrichment.http import HTTPProbeOptions, HTTPProber
from .enrichment.technology import detect_technologies, technologies_from_dns
from .enrichment.tls import fetch_tls
from .models import (
    ActivityState,
    Host,
    ScanResult,
    ScanStatistics,
    SourceResult,
    SourceStatus,
    utcnow_iso,
)
from .sources.registry import build_registry, filter_sources
from .storage.cache import ResponseCache
from .storage.database import Database
from .utils.http import HTTPClient, RateLimiter
from .utils.logging import get_logger

#: Phases reported to the CLI progress callback.
PHASES = (
    "Loading sources",
    "Passive discovery",
    "Normalizing",
    "Correlating",
    "DNS enrichment",
    "HTTP enrichment",
    "Generating report",
)


class Engine:
    """Runs a complete passive reconnaissance scan for one target."""

    def __init__(self, config: Optional[Config] = None, logger=None) -> None:
        self.config = config or Config()
        self.logger = logger or get_logger()
        self.cache = ResponseCache(
            root=self.config.cache.path,
            ttl=self.config.cache.ttl,
            enabled=self.config.cache.enabled,
        )
        self.http = HTTPClient(
            timeout=float(self.config.general.timeout),
            retries=int(self.config.general.retries),
            user_agent=self.config.general.user_agent,
            max_body_size=max(self.config.http.max_body_size, 2_000_000),
            verify_tls=self.config.general.verify_tls,
            rate_limiter=RateLimiter(0.0),
            cache=self.cache if self.config.cache.enabled else None,
            cache_ttl=self.config.cache.ttl,
        )
        self.database = Database(self.config.storage.path, logger=self.logger)
        self._current_run_id: Optional[int] = None

    # -- public API --------------------------------------------------------
    def available_sources(self) -> List[Any]:
        """Return every registered source instance."""
        return build_registry(http=self.http, enabled=self.config.sources.enabled)

    def close(self) -> None:
        """Release HTTP connections and database handles."""
        self.http.close()
        self.database.close()

    def scan(
        self,
        target: str,
        sources: Optional[Sequence[str]] = None,
        scope: Optional[ScopeMatcher] = None,
        exclude: Optional[ExclusionMatcher] = None,
        include_regex: Optional[re.Pattern] = None,
        exclude_regex: Optional[re.Pattern] = None,
        baseline: Optional[str] = None,
        previous_hosts: Optional[Dict[str, Host]] = None,
        resolve: Optional[bool] = None,
        probe: Optional[bool] = None,
        progress: Optional[Callable[[int, int, str], None]] = None,
    ) -> ScanResult:
        """Run a full scan for ``target``.

        ``progress`` is called as ``progress(step, total_steps, phase_name)``.
        """
        started = time.monotonic()
        statistics = ScanStatistics(started_at=utcnow_iso())
        errors: List[str] = []
        total_steps = len(PHASES)
        step = 0

        def tick(message: str) -> None:
            nonlocal step
            step += 1
            if progress:
                progress(step, total_steps, message)

        domain = self._clean_target(target)
        registrable = registrable_domain(domain) or domain

        # ------------------------------------------------------------------
        # 1. sources
        # ------------------------------------------------------------------
        tick(PHASES[0])
        registry = self.available_sources()
        selected = filter_sources(registry, sources)
        global_limit = float(self.config.general.rate_limit or 0.0)
        for source in selected:
            source.http = self.http
            source.enabled = bool(self.config.sources.enabled.get(source.name, True))
            if global_limit > 0:
                # Never go faster than the operator asked for; per-source
                # defaults may be (and often are) more conservative.
                source.rate_limiter.min_interval = max(source.rate_limit_seconds, global_limit)
        statistics.sources_total = len(selected)

        # ------------------------------------------------------------------
        # 2. passive discovery (bounded concurrency, total isolation)
        # ------------------------------------------------------------------
        tick(PHASES[1])
        results = self._run_sources(selected, domain)

        # ------------------------------------------------------------------
        # 3. normalization + validation
        # ------------------------------------------------------------------
        tick(PHASES[2])
        filtered_results, counts = self._normalize_results(
            results,
            domain,
            scope=scope,
            exclude=exclude,
            include_regex=include_regex,
            exclude_regex=exclude_regex,
        )
        statistics.raw_results = counts["raw"]
        statistics.unique_results = counts["unique"]
        statistics.out_of_scope = counts["out_of_scope"]
        statistics.invalid_hostnames = counts["invalid"]
        statistics.filtered_out = counts["filtered"]
        statistics.raw_results += counts["rejected"]

        # ------------------------------------------------------------------
        # 4. correlation / deduplication
        # ------------------------------------------------------------------
        tick(PHASES[3])
        hosts = aggregate_results(filtered_results, domain)
        for host in hosts.values():
            host.registrable_domain = registrable
        statistics.valid_results = len(hosts)

        health = {name: source.health for name, source in ((s.name, s) for s in selected)}
        for name, entry in health.items():
            if entry.status.ok:
                statistics.sources_successful += 1
            elif entry.status is SourceStatus.RATE_LIMITED:
                statistics.sources_rate_limited += 1
            elif entry.status is SourceStatus.DISABLED:
                statistics.sources_disabled += 1
            else:
                statistics.sources_failed += 1
        for result in results:
            if result.error and result.status is not SourceStatus.ONLINE:
                errors.append(f"{result.source}: {result.error}")

        # ------------------------------------------------------------------
        # 5. DNS enrichment
        # ------------------------------------------------------------------
        tick(PHASES[4])
        wildcard = WildcardReport(domain=domain)
        do_resolve = self.config.dns.enabled if resolve is None else bool(resolve)
        if do_resolve and hosts:
            wildcard, dns_errors = self._enrich_dns(hosts)
            errors.extend(dns_errors)

        # ------------------------------------------------------------------
        # 6. HTTP enrichment
        # ------------------------------------------------------------------
        tick(PHASES[5])
        do_probe = self.config.http.enabled if probe is None else bool(probe)
        if do_probe and hosts:
            errors.extend(self._enrich_http(hosts, tls=self.config.http.capture_tls))

        # ------------------------------------------------------------------
        # 7. classification, scoring, reporting
        # ------------------------------------------------------------------
        tick(PHASES[6])
        ordered = self._finalize(hosts, wildcard, statistics)

        # -- diff / change detection ---------------------------------------
        changes_payload: Optional[Dict[str, Any]] = None
        diff_result: Optional[DiffResult] = None
        change_records: List[Any] = []
        try:
            if baseline:
                previous_names = load_previous_hosts(baseline)
                diff_result = diff_host_lists(previous_names, list(hosts))
                self.logger.info(
                    "Baseline diff: %d new, %d removed, %d unchanged",
                    len(diff_result.new),
                    len(diff_result.removed),
                    len(diff_result.unchanged),
                )
            if previous_hosts:
                change_records = diff_hosts(previous_hosts, hosts)
                if diff_result is None:
                    # No --baseline file: compare against the stored snapshot so
                    # that disappeared hosts are still reported.
                    diff_result = diff_host_lists(list(previous_hosts), list(hosts))
            changes_payload = build_changes_payload(
                diff_result, change_records, force=bool(previous_hosts)
            )
        except Exception as exc:  # noqa: BLE001 - diffing must never break a scan
            errors.append(f"diff: {exc}")

        finished = time.monotonic()
        statistics.finished_at = utcnow_iso()
        statistics.duration_seconds = round(finished - started, 2)

        result = ScanResult(
            target=domain,
            hosts=ordered,
            statistics=statistics,
            source_health=health,
            graph=build_source_graph(ordered),
            changes=changes_payload,
            profile=self.config.output.profile,
            errors=errors,
        )
        result.graph["wildcard"] = wildcard.to_dict()

        # -- persistence ----------------------------------------------------
        if self.config.storage.enabled:
            try:
                self._current_run_id = self.database.save_scan(result)
                self.database.finish_run(self._current_run_id, statistics)
            except Exception as exc:  # noqa: BLE001 - storage is best effort
                self.logger.warning("Could not persist results: %s", exc)
                errors.append(f"database: {exc}")

        return result

    # -- stages ------------------------------------------------------------
    def _clean_target(self, target: str) -> str:
        """Normalize the user supplied target into a bare domain."""
        host = normalize_host(target)
        if not host:
            raise ValueError(f"invalid target domain: {target!r}")
        return host

    def _run_sources(self, sources: Sequence[Any], domain: str) -> List[SourceResult]:
        """Execute all sources concurrently, isolating every failure."""
        results: List[SourceResult] = []
        if not sources:
            self.logger.warning("No sources selected - nothing to do")
            return results
        workers = max(1, min(int(self.config.general.threads), len(sources)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="source") as pool:
            futures = {pool.submit(source.run, domain): source for source in sources}
            for future, source in futures.items():
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001 - belt and braces isolation
                    result = SourceResult(
                        source=source.name,
                        domain=domain,
                        status=SourceStatus.FAILED,
                        error=f"{exc.__class__.__name__}: {exc}",
                    )
                    source.health.record_failure(0.0, str(exc), SourceStatus.FAILED)
                results.append(result)
                level = "info" if result.status.ok else "warning"
                getattr(self.logger, level)(
                    "Source %s: %s (%d results, %.0f ms)%s",
                    result.source,
                    result.status.value,
                    result.result_count,
                    result.elapsed_ms,
                    f" - {result.error}" if result.error else "",
                )
        return results

    def _normalize_results(
        self,
        results: Sequence[SourceResult],
        domain: str,
        scope: Optional[ScopeMatcher] = None,
        exclude: Optional[ExclusionMatcher] = None,
        include_regex: Optional[re.Pattern] = None,
        exclude_regex: Optional[re.Pattern] = None,
    ):
        """Normalize, validate and filter every raw source observation."""
        filtered: List[SourceResult] = []
        counts = {"raw": 0, "unique": 0, "out_of_scope": 0, "invalid": 0, "filtered": 0, "rejected": 0}
        unique_hosts: set[str] = set()

        for result in results or []:
            clean = SourceResult(
                source=result.source,
                domain=result.domain,
                status=result.status,
                error=result.error,
                elapsed_ms=result.elapsed_ms,
                http_status=result.http_status,
                query_count=result.query_count,
            )
            counts["rejected"] += int(getattr(result, "rejected", 0) or 0)
            for raw_name, observation in (result.observations or {}).items():
                counts["raw"] += int(observation.count)
                host = normalize_host(raw_name)
                if not host:
                    counts["invalid"] += 1
                    continue
                unique_hosts.add(host)
                if not is_in_scope(host, domain):
                    counts["out_of_scope"] += 1
                    continue
                if not filter_hosts([host], domain, scope, exclude, include_regex, exclude_regex):
                    counts["filtered"] += 1
                    continue
                clean.add(
                    host,
                    first_seen=observation.first_seen,
                    last_seen=observation.last_seen,
                    raw=observation.raw,
                )

            for raw_name, record in (result.history or {}).items():
                host = normalize_host(raw_name)
                if not host or not is_in_scope(host, domain):
                    continue
                if not filter_hosts([host], domain, scope, exclude, include_regex, exclude_regex):
                    continue
                clean.add_history(
                    host,
                    first_seen=record.first_seen,
                    last_seen=record.last_seen,
                    observations=record.observations,
                    currently_observed=record.currently_observed,
                )
            clean.raw_count = len(clean.observations)
            filtered.append(clean)

        counts["unique"] = len(unique_hosts)
        return filtered, counts

    def _enrich_dns(self, hosts: Dict[str, Host]):
        """Attach DNS intelligence to every host, detecting wildcards first."""
        options = DNSOptions(
            record_types=tuple(self.config.dns.record_types),
            timeout=self.config.dns.timeout,
            retries=self.config.dns.retries,
            threads=self.config.dns.threads,
            nameservers=self.config.dns.nameservers or None,
            detect_wildcard=self.config.dns.detect_wildcard,
            dnssec=self.config.dns.dnssec,
        )
        engine = DNSEngine(options, logger=self.logger)
        errors: List[str] = []
        wildcard = WildcardReport(domain=next(iter(hosts), ""))
        try:
            wildcard = engine.detect_wildcard(wildcard.domain)
            self.logger.info(
                "Wildcard DNS: %s (%d/%d probes resolved)",
                wildcard.state.value,
                wildcard.resolved_count,
                max(1, len(wildcard.probes)),
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"wildcard detection: {exc}")

        try:
            records = engine.resolve_many(list(hosts), wildcard=wildcard)
            for name, info in records.items():
                hosts[name].dns = info
                if self.config.dns.dnssec:
                    info.dnssec = engine.dnssec_status(name)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"dns enrichment: {exc}")
        return wildcard, errors

    def _enrich_http(self, hosts: Dict[str, Host], tls: bool = False) -> List[str]:
        """Probe hosts over HTTP(S) and attach observations."""
        options = HTTPProbeOptions(
            timeout=self.config.http.timeout,
            threads=self.config.http.threads,
            max_body_size=self.config.http.max_body_size,
            verify_tls=self.config.http.verify_tls,
            capture_tls=tls,
            fallback_http=self.config.http.fallback_http,
        )
        prober = HTTPProber(self.http, options, logger=self.logger)
        targets = [
            name
            for name, host in hosts.items()
            if (host.dns is None) or host.dns.resolved or host.dns.cname
        ]
        if not targets:
            targets = list(hosts)
        errors: List[str] = []
        try:
            observations = prober.probe_many(targets)
            for name, observation in observations.items():
                hosts[name].http = observation
                if observation.error:
                    errors.append(f"http {name}: {observation.error}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"http enrichment: {exc}")

        if tls:
            for name in targets:
                try:
                    hosts[name].tls = fetch_tls(name, timeout=self.config.http.timeout)
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"tls {name}: {exc}")
        self._last_bodies = getattr(prober, "bodies", {})
        return errors

    def _finalize(
        self,
        hosts: Dict[str, Host],
        wildcard: WildcardReport,
        statistics: ScanStatistics,
    ) -> List[Host]:
        """Classify, score and rank every host, then update statistics."""
        ordered: List[Host] = []
        for host in hosts.values():
            try:
                host.cdn = classify_cdn(host.host, host.dns, host.http)
                host.cloud = detect_cloud_asset(host.host, host.dns, host.http)
                if host.http is not None:
                    body = getattr(self, "_last_bodies", {}).get(host.host, "")
                    host.technologies = detect_technologies(host.http, body=body)
                if host.dns is not None:
                    for tech in technologies_from_dns(host.dns.cname):
                        if tech.name not in host.technology_names:
                            host.technologies.append(tech)

                classify_host(host)
                score, label, reasons, _factors = score_host(host, wildcard.state)
                host.confidence = score
                host.confidence_label = label
                host.confidence_reasons = reasons
                priority, priority_reasons = compute_priority(host)
                host.priority = priority
                host.priority_reasons = priority_reasons
                if not host.history and host.first_seen is None:
                    host.activity = ActivityState.CURRENT
            except Exception as exc:  # noqa: BLE001 - never lose a host to a bug
                self.logger.debug("Failed to finalize %s: %s", host.host, exc)
            ordered.append(host)

        ordered = rank_hosts(ordered)

        statistics.dns_resolved = sum(1 for h in ordered if h.dns_resolved)
        statistics.http_probed = sum(1 for h in ordered if h.http is not None and h.http.status_code)
        statistics.http_live = sum(
            1
            for h in ordered
            if h.http is not None and h.http.status_code is not None and h.http.status_code < 400
        )
        statistics.historical = sum(1 for h in ordered if h.activity is ActivityState.HISTORICAL)
        statistics.interesting = sum(1 for h in ordered if h.interesting)
        statistics.cloud_assets = sum(1 for h in ordered if h.cloud is not None)
        statistics.cdn_hosts = sum(1 for h in ordered if h.cdn and h.cdn.provider)
        return ordered

    # -- helpers -----------------------------------------------------------
    def enrich_asn(self, hosts: Sequence[Host], limit: int = 50) -> None:
        """Optional ASN enrichment (public sources only)."""
        ips: List[str] = []
        for host in hosts or []:
            if host.dns:
                ips.extend(host.dns.a[:2])
        enricher = ASNEnricher(
            self.http,
            threads=max(1, self.config.general.threads // 2 or 1),
            timeout=self.config.http.timeout,
            limit=limit,
            logger=self.logger,
        )
        lookup = enricher.lookup_many(ips)
        for host in hosts or []:
            if not host.dns:
                continue
            for ip in host.dns.a[:2]:
                info = lookup.get(ip)
                if info:
                    host.asn.append(info)

    def previous_hosts(self, target: str) -> Dict[str, Host]:
        """Load the last known state of a target's hosts from the local database.

        Used for change detection: the previous snapshot is compared with the
        freshly collected one attribute by attribute.
        """
        from .models import DNSInfo, HTTPObservation, SourceObservation

        try:
            self.database.connect()
            if self.database.get_target(target) is None:
                return {}
        except Exception:  # noqa: BLE001
            return {}

        try:
            conn = self.database.connect()
            rows = conn.execute(
                """
                SELECT h.id, h.host, h.confidence, h.category, h.interesting, h.activity,
                       (SELECT GROUP_CONCAT(d.record_type || '=' || d.value, '|')
                          FROM dns_records d WHERE d.host_id = h.id) AS dns,
                       (SELECT o2.status_code || '|' || COALESCE(o2.title,'') || '|' || COALESCE(o2.server,'')
                          FROM http_observations o2 WHERE o2.host_id = h.id
                          ORDER BY o2.id DESC LIMIT 1) AS http,
                       (SELECT GROUP_CONCAT(t.name, ',') FROM technology t WHERE t.host_id = h.id) AS tech,
                       (SELECT GROUP_CONCAT(s.name, ',') FROM observations o
                          JOIN sources s ON s.id = o.source_id WHERE o.host_id = h.id) AS sources
                FROM hosts h JOIN targets t ON t.id = h.target_id
                WHERE t.domain = ?
                """,
                (target,),
            ).fetchall()
        except Exception:  # noqa: BLE001
            return {}

        hosts: Dict[str, Host] = {}
        for row in rows:
            host = Host(host=row["host"], domain=target)
            host.confidence = int(row["confidence"] or 0)
            host.confidence_label = label_for_score(host.confidence)

            dns = DNSInfo(host=row["host"])
            for chunk in (row["dns"] or "").split("|"):
                if "=" not in chunk:
                    continue
                rtype, value = chunk.split("=", 1)
                if not value:
                    continue
                if rtype == "A":
                    dns.a.append(value)
                elif rtype == "AAAA":
                    dns.aaaa.append(value)
                elif rtype == "CNAME":
                    dns.cname.append(value)
            dns.resolved = bool(dns.a or dns.aaaa or dns.cname)
            host.dns = dns

            if row["http"]:
                parts = str(row["http"]).split("|")
                status = parts[0] if parts else ""
                host.http = HTTPObservation(
                    host=row["host"],
                    status_code=int(status) if status.isdigit() else None,
                    title=parts[1] if len(parts) > 1 and parts[1] else None,
                    server=parts[2] if len(parts) > 2 and parts[2] else None,
                )

            for name in (row["tech"] or "").split(","):
                if name.strip():
                    host.technologies.append(_tech(name.strip()))
            for name in (row["sources"] or "").split(","):
                if name.strip():
                    host.observations[name.strip()] = SourceObservation(
                        source=name.strip(), host=row["host"]
                    )

            host.category = _category_from_row(row)
            hosts[row["host"]] = host
        return hosts


def _tech(name: str):
    from .models import Technology

    return Technology(name=name, category="unknown", evidence="database", confidence=50)


def _category_from_row(row: Any) -> Any:
    from .models import HostCategory

    value = row["category"] if "category" in row.keys() else None
    for category in HostCategory:
        if category.value == value:
            return category
    return HostCategory.UNKNOWN
