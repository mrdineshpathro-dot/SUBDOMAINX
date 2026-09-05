"""SQLite persistence layer.

Tables: ``targets``, ``hosts``, ``sources``, ``observations``, ``dns_records``,
``http_observations``, ``tls_observations``, ``technology``,
``historical_observations``, ``scan_runs``, ``run_hosts``, ``source_runs`` and
``errors``.

Everything is local - there is no server, no account and no telemetry.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..models import ScanResult, utcnow_iso
from ..utils.logging import get_logger
from .migrations import apply_migrations

DEFAULT_DB_PATH = "subdomainx.db"


class Database:
    """Thin repository around the SUBDOMAINX SQLite database."""

    def __init__(self, path: str = DEFAULT_DB_PATH, logger=None) -> None:
        self.path = str(path or DEFAULT_DB_PATH)
        self.logger = logger or get_logger()
        self.conn: Optional[sqlite3.Connection] = None

    # -- lifecycle ---------------------------------------------------------
    def connect(self) -> sqlite3.Connection:
        """Open the database (creating it when needed) and migrate it."""
        if self.conn is not None:
            return self.conn
        path = Path(self.path)
        if path.parent and str(path.parent) not in ("", "."):
            path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        apply_migrations(self.conn)
        return self.conn

    def close(self) -> None:
        if self.conn is not None:
            try:
                self.conn.commit()
            except sqlite3.Error:  # pragma: no cover
                pass
            self.conn.close()
            self.conn = None

    def __enter__(self) -> "Database":
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- targets -----------------------------------------------------------
    def upsert_target(self, domain: str, registrable_domain: Optional[str] = None) -> int:
        conn = self.connect()
        now = utcnow_iso()
        conn.execute(
            "INSERT INTO targets (domain, registrable_domain, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(domain) DO UPDATE SET registrable_domain=excluded.registrable_domain",
            (domain, registrable_domain or domain, now),
        )
        conn.commit()
        row = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
        return int(row["id"])

    def get_target(self, domain: str) -> Optional[sqlite3.Row]:
        conn = self.connect()
        return conn.execute("SELECT * FROM targets WHERE domain = ?", (domain,)).fetchone()

    def list_targets(self) -> List[Dict[str, Any]]:
        conn = self.connect()
        rows = conn.execute(
            """
            SELECT t.*,
                   (SELECT COUNT(*) FROM hosts h WHERE h.target_id = t.id) AS hosts,
                   (SELECT MAX(sr.started_at) FROM scan_runs sr WHERE sr.target_id = t.id) AS last_scan
            FROM targets t ORDER BY t.domain
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_target(self, domain: str) -> bool:
        conn = self.connect()
        with conn:
            cursor = conn.execute("DELETE FROM targets WHERE domain = ?", (domain,))
        return cursor.rowcount > 0

    # -- scan runs ---------------------------------------------------------
    def start_run(self, target_id: int, profile: str = "standard") -> int:
        conn = self.connect()
        cursor = conn.execute(
            "INSERT INTO scan_runs (target_id, started_at, profile) VALUES (?, ?, ?)",
            (target_id, utcnow_iso(), profile),
        )
        conn.commit()
        return int(cursor.lastrowid)

    def finish_run(self, run_id: int, statistics: Any) -> None:
        conn = self.connect()
        with conn:
            conn.execute(
                """
                UPDATE scan_runs SET finished_at=?, duration_seconds=?, raw_results=?,
                       unique_results=?, valid_results=?, dns_hosts=?, live_hosts=?,
                       historical_hosts=?, interesting_hosts=?, sources_total=?,
                       sources_ok=?, sources_failed=?
                WHERE id=?
                """,
                (
                    utcnow_iso(),
                    float(getattr(statistics, "duration_seconds", 0) or 0),
                    int(getattr(statistics, "raw_results", 0) or 0),
                    int(getattr(statistics, "unique_results", 0) or 0),
                    int(getattr(statistics, "valid_results", 0) or 0),
                    int(getattr(statistics, "dns_resolved", 0) or 0),
                    int(getattr(statistics, "http_live", 0) or 0),
                    int(getattr(statistics, "historical", 0) or 0),
                    int(getattr(statistics, "interesting", 0) or 0),
                    int(getattr(statistics, "sources_total", 0) or 0),
                    int(getattr(statistics, "sources_successful", 0) or 0),
                    int(getattr(statistics, "sources_failed", 0) or 0),
                    run_id,
                ),
            )
            conn.execute(
                "UPDATE targets SET last_scan_at=? WHERE id=(SELECT target_id FROM scan_runs WHERE id=?)",
                (utcnow_iso(), run_id),
            )

    def latest_runs(self, target_id: int, limit: int = 2) -> List[sqlite3.Row]:
        conn = self.connect()
        return list(
            conn.execute(
                "SELECT * FROM scan_runs WHERE target_id=? ORDER BY id DESC LIMIT ?",
                (target_id, int(limit)),
            ).fetchall()
        )

    # -- persistence -------------------------------------------------------
    def save_scan(self, result: ScanResult) -> int:
        """Persist a full :class:`ScanResult`, returning the scan run id."""
        conn = self.connect()
        target_id = self.upsert_target(result.target)
        run_id = self.start_run(target_id, result.profile)

        with conn:
            for name, health in (result.source_health or {}).items():
                source_id = self._upsert_source(
                    name,
                    getattr(health, "category", ""),
                    getattr(health, "description", ""),
                )
                conn.execute(
                    """
                    INSERT INTO source_runs (scan_run_id, source_id, status, results,
                        response_time_ms, http_status, success_count, error_count,
                        rate_limit_events, parser_failures, error)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        run_id,
                        source_id,
                        health.status.value,
                        int(health.results),
                        float(health.last_response_time_ms),
                        health.last_http_status,
                        int(health.success_count),
                        int(health.error_count),
                        int(health.rate_limit_events),
                        int(health.parser_failures),
                        health.last_error,
                    ),
                )

            for host in result.hosts:
                host_id = self._upsert_host(target_id, host)
                conn.execute(
                    "INSERT OR IGNORE INTO run_hosts (scan_run_id, host_id) VALUES (?,?)",
                    (run_id, host_id),
                )
                self._save_observations(conn, host_id, host)
                self._save_history(conn, host_id, host)
                self._save_dns(conn, host_id, run_id, host)
                self._save_http(conn, host_id, run_id, host)
                self._save_technology(conn, host_id, run_id, host)

            for message in result.errors or []:
                self._record_error(conn, run_id, None, message)

        return run_id

    # -- queries -----------------------------------------------------------
    def hosts(self, domain: str, limit: int = 0) -> List[Dict[str, Any]]:
        """Return the latest known state of every host for ``domain``."""
        conn = self.connect()
        sql = """
            SELECT h.*,
                   (SELECT GROUP_CONCAT(s.name, ',') FROM observations o
                      JOIN sources s ON s.id = o.source_id WHERE o.host_id = h.id) AS sources
            FROM hosts h JOIN targets t ON t.id = h.target_id
            WHERE t.domain = ?
            ORDER BY h.confidence DESC, h.host
        """
        if limit:
            sql += " LIMIT ?"
            rows = conn.execute(sql, (domain, int(limit))).fetchall()
        else:
            rows = conn.execute(sql, (domain,)).fetchall()
        return [dict(r) for r in rows]

    def host(self, domain: str, hostname: str) -> Optional[Dict[str, Any]]:
        """Return the full record (with all child rows) for one host."""
        conn = self.connect()
        row = conn.execute(
            """
            SELECT h.* FROM hosts h JOIN targets t ON t.id = h.target_id
            WHERE t.domain = ? AND h.host = ?
            """,
            (domain, hostname),
        ).fetchone()
        if row is None:
            return None
        payload = dict(row)
        host_id = payload["id"]
        payload["observations"] = [
            dict(r)
            for r in conn.execute(
                """
                SELECT s.name AS source, o.first_seen, o.last_seen, o.count
                FROM observations o JOIN sources s ON s.id = o.source_id
                WHERE o.host_id = ? ORDER BY s.name
                """,
                (host_id,),
            ).fetchall()
        ]
        payload["dns"] = [
            dict(r) for r in conn.execute(
                "SELECT record_type, value FROM dns_records WHERE host_id=? ORDER BY record_type",
                (host_id,),
            ).fetchall()
        ]
        payload["http"] = [
            dict(r) for r in conn.execute(
                "SELECT * FROM http_observations WHERE host_id=? ORDER BY id DESC LIMIT 1",
                (host_id,),
            ).fetchall()
        ]
        payload["technology"] = [
            dict(r) for r in conn.execute(
                "SELECT name, category, evidence, confidence FROM technology WHERE host_id=? ORDER BY confidence DESC",
                (host_id,),
            ).fetchall()
        ]
        payload["history"] = [
            dict(r) for r in conn.execute(
                """
                SELECT s.name AS source, ho.first_seen, ho.last_seen, ho.observations, ho.currently_observed
                FROM historical_observations ho LEFT JOIN sources s ON s.id = ho.source_id
                WHERE ho.host_id=? ORDER BY s.name
                """,
                (host_id,),
            ).fetchall()
        ]
        return payload

    def history(self, domain: str) -> List[Dict[str, Any]]:
        """Historical view: first/last seen per host."""
        conn = self.connect()
        rows = conn.execute(
            """
            SELECT h.host, h.first_seen, h.last_seen, h.activity, h.confidence,
                   h.confidence_label, h.category, h.total_observations,
                   (SELECT COUNT(*) FROM observations o WHERE o.host_id = h.id) AS sources
            FROM hosts h JOIN targets t ON t.id = h.target_id
            WHERE t.domain = ?
            ORDER BY COALESCE(h.last_seen, h.first_seen) DESC, h.host
            """,
            (domain,),
        ).fetchall()
        return [dict(r) for r in rows]

    def new_hosts(self, domain: str) -> List[Dict[str, Any]]:
        """Hosts that appeared in the most recent run."""
        return self._run_delta(domain, newest=True)

    def removed_hosts(self, domain: str) -> List[Dict[str, Any]]:
        """Hosts present in the previous run but missing from the newest one."""
        return self._run_delta(domain, newest=False)

    def _run_delta(self, domain: str, newest: bool = True) -> List[Dict[str, Any]]:
        conn = self.connect()
        target = self.get_target(domain)
        if target is None:
            return []
        runs = self.latest_runs(target["id"], limit=2)
        if len(runs) < 2:
            # With a single run there is nothing to compare against.
            return [] if newest else []
        newest_id, previous_id = int(runs[0]["id"]), int(runs[1]["id"])
        if newest:
            sql = """
                SELECT h.* FROM hosts h
                JOIN run_hosts rh ON rh.host_id = h.id
                WHERE h.target_id = ? AND rh.scan_run_id = ?
                  AND h.id NOT IN (SELECT host_id FROM run_hosts WHERE scan_run_id = ?)
                ORDER BY h.host
            """
        else:
            sql = """
                SELECT h.* FROM hosts h
                JOIN run_hosts rh ON rh.host_id = h.id
                WHERE h.target_id = ? AND rh.scan_run_id = ?
                  AND h.id NOT IN (SELECT host_id FROM run_hosts WHERE scan_run_id = ?)
                ORDER BY h.host
            """
        params = (target["id"], newest_id, previous_id) if newest else (target["id"], previous_id, newest_id)
        return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def source_stats(self, domain: str) -> List[Dict[str, Any]]:
        """Per-source performance for the newest run of ``domain``."""
        conn = self.connect()
        target = self.get_target(domain)
        if target is None:
            return []
        runs = self.latest_runs(target["id"], limit=1)
        if not runs:
            return []
        rows = conn.execute(
            """
            SELECT s.name, s.category, sr.status, sr.results, sr.response_time_ms,
                   sr.success_count, sr.error_count, sr.rate_limit_events,
                   sr.parser_failures, sr.error, sr.http_status
            FROM source_runs sr
            JOIN sources s ON s.id = sr.source_id
            WHERE sr.scan_run_id = ?
            ORDER BY sr.results DESC, s.name
            """,
            (int(runs[0]["id"]),),
        ).fetchall()
        return [dict(r) for r in rows]

    def stats(self, domain: str) -> Dict[str, Any]:
        """Aggregate statistics for ``domain``."""
        conn = self.connect()
        target = self.get_target(domain)
        if target is None:
            return {"domain": domain, "exists": False}
        target_id = int(target["id"])
        runs = self.latest_runs(target_id, limit=1)
        hosts = conn.execute(
            "SELECT COUNT(*) AS n, COALESCE(MAX(confidence),0) AS best, "
            "COALESCE(AVG(confidence),0) AS avg FROM hosts WHERE target_id=?",
            (target_id,),
        ).fetchone()
        by_category = {
            r["category"]: r["n"]
            for r in conn.execute(
                "SELECT COALESCE(category,'Unknown') AS category, COUNT(*) AS n "
                "FROM hosts WHERE target_id=? GROUP BY category ORDER BY n DESC",
                (target_id,),
            ).fetchall()
        }
        latest = dict(runs[0]) if runs else {}
        return {
            "domain": domain,
            "exists": True,
            "registrable_domain": target["registrable_domain"],
            "hosts": int(hosts["n"]),
            "best_confidence": int(hosts["best"]),
            "average_confidence": round(float(hosts["avg"]), 2),
            "categories": by_category,
            "interesting": int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM hosts WHERE target_id=? AND interesting=1",
                    (target_id,),
                ).fetchone()["n"]
            ),
            "historical": int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM hosts WHERE target_id=? AND activity='HISTORICAL'",
                    (target_id,),
                ).fetchone()["n"]
            ),
            "dns_records": int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM dns_records d JOIN hosts h ON h.id=d.host_id "
                    "WHERE h.target_id=?",
                    (target_id,),
                ).fetchone()["n"]
            ),
            "http_observations": int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM http_observations o JOIN hosts h ON h.id=o.host_id "
                    "WHERE h.target_id=?",
                    (target_id,),
                ).fetchone()["n"]
            ),
            "scans": int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM scan_runs WHERE target_id=?", (target_id,)
                ).fetchone()["n"]
            ),
            "last_scan": latest.get("started_at"),
            "last_duration_seconds": round(float(latest.get("duration_seconds") or 0), 2),
            "sources": self.source_stats(domain),
        }

    # -- internals ---------------------------------------------------------
    def _upsert_source(self, name: str, category: str = "", description: str = "") -> int:
        conn = self.connect()
        conn.execute(
            "INSERT INTO sources (name, category, description) VALUES (?,?,?) "
            "ON CONFLICT(name) DO NOTHING",
            (name, category, description),
        )
        row = conn.execute("SELECT id FROM sources WHERE name=?", (name,)).fetchone()
        return int(row["id"])

    def _upsert_host(self, target_id: int, host: Any) -> int:
        conn = self.connect()
        now = utcnow_iso()
        conn.execute(
            """
            INSERT INTO hosts (target_id, host, registrable_domain, confidence, confidence_label,
                category, priority, interesting, activity, cdn_provider, cdn_confidence,
                cloud_provider, first_seen, last_seen, total_observations, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(target_id, host) DO UPDATE SET
                confidence=excluded.confidence,
                confidence_label=excluded.confidence_label,
                category=excluded.category,
                priority=excluded.priority,
                interesting=excluded.interesting,
                activity=excluded.activity,
                cdn_provider=excluded.cdn_provider,
                cdn_confidence=excluded.cdn_confidence,
                cloud_provider=excluded.cloud_provider,
                first_seen=COALESCE(MIN(hosts.first_seen, excluded.first_seen), excluded.first_seen),
                last_seen=COALESCE(MAX(hosts.last_seen, excluded.last_seen), excluded.last_seen),
                total_observations=MAX(hosts.total_observations, excluded.total_observations),
                updated_at=excluded.updated_at
            """,
            (
                target_id,
                host.host,
                host.registrable_domain,
                int(host.confidence),
                host.confidence_label.value,
                host.category.value,
                int(host.priority),
                1 if host.interesting else 0,
                host.activity.value,
                (host.cdn.provider if host.cdn else None),
                (host.cdn.confidence.value if host.cdn else None),
                (host.cloud.provider if host.cloud else None),
                host.first_seen,
                host.last_seen,
                int(host.total_observations),
                now,
                now,
            ),
        )
        row = conn.execute(
            "SELECT id FROM hosts WHERE target_id=? AND host=?", (target_id, host.host)
        ).fetchone()
        return int(row["id"])

    def _save_observations(self, conn: sqlite3.Connection, host_id: int, host: Any) -> None:
        now = utcnow_iso()
        for source_name, observation in (host.observations or {}).items():
            source_id = self._upsert_source(source_name)
            conn.execute(
                """
                INSERT INTO observations (host_id, source_id, first_seen, last_seen, count, updated_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(host_id, source_id) DO UPDATE SET
                    first_seen=COALESCE(MIN(observations.first_seen, excluded.first_seen), excluded.first_seen),
                    last_seen=COALESCE(MAX(observations.last_seen, excluded.last_seen), excluded.last_seen),
                    count=observations.count + excluded.count,
                    updated_at=excluded.updated_at
                """,
                (
                    host_id,
                    source_id,
                    observation.first_seen,
                    observation.last_seen,
                    int(observation.count),
                    now,
                ),
            )

    def _save_history(self, conn: sqlite3.Connection, host_id: int, host: Any) -> None:
        for source_name, record in (host.history or {}).items():
            source_id = self._upsert_source(source_name)
            conn.execute(
                """
                INSERT INTO historical_observations (host_id, source_id, first_seen, last_seen,
                    observations, currently_observed)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(host_id, source_id) DO UPDATE SET
                    first_seen=COALESCE(MIN(historical_observations.first_seen, excluded.first_seen), excluded.first_seen),
                    last_seen=COALESCE(MAX(historical_observations.last_seen, excluded.last_seen), excluded.last_seen),
                    observations=historical_observations.observations + excluded.observations,
                    currently_observed=MAX(historical_observations.currently_observed, excluded.currently_observed)
                """,
                (
                    host_id,
                    source_id,
                    record.first_seen,
                    record.last_seen,
                    int(record.observations),
                    1 if record.currently_observed else 0,
                ),
            )

    def _save_dns(self, conn: sqlite3.Connection, host_id: int, run_id: int, host: Any) -> None:
        dns = host.dns
        if dns is None:
            return
        conn.execute("DELETE FROM dns_records WHERE host_id=?", (host_id,))
        for rtype, values in (
            ("A", dns.a),
            ("AAAA", dns.aaaa),
            ("CNAME", dns.cname),
            ("MX", dns.mx),
            ("NS", dns.ns),
            ("TXT", dns.txt),
            ("CAA", dns.caa),
        ):
            for value in values or []:
                conn.execute(
                    """
                    INSERT INTO dns_records (host_id, scan_run_id, record_type, value, resolved,
                        wildcard, internal, dnssec, observed_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        host_id,
                        run_id,
                        rtype,
                        str(value)[:500],
                        1 if dns.resolved else 0,
                        1 if dns.wildcard else 0,
                        1 if dns.internal_looking else 0,
                        dns.dnssec,
                        dns.queried_at,
                    ),
                )
        if not (dns.a or dns.aaaa or dns.cname or dns.mx or dns.ns or dns.txt or dns.caa):
            conn.execute(
                """
                INSERT INTO dns_records (host_id, scan_run_id, record_type, value, resolved,
                    wildcard, internal, dnssec, observed_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (host_id, run_id, "NONE", "", 0, 0, 0, dns.dnssec, dns.queried_at),
            )

    def _save_http(self, conn: sqlite3.Connection, host_id: int, run_id: int, host: Any) -> None:
        observation = host.http
        if observation is None:
            return
        conn.execute(
            """
            INSERT INTO http_observations (host_id, scan_run_id, url, final_url, scheme,
                status_code, category, title, server, content_type, content_length,
                response_time_ms, redirect_count, error, observed_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                host_id,
                run_id,
                observation.url,
                observation.final_url,
                observation.scheme,
                observation.status_code,
                observation.category.value,
                (observation.title or "")[:500] or None,
                (observation.server or "")[:200] or None,
                observation.content_type,
                observation.content_length,
                float(observation.response_time_ms),
                int(observation.redirect_count),
                (observation.error or "")[:300] or None,
                observation.observed_at,
            ),
        )
        tls = observation.tls or host.tls
        if tls is not None:
            conn.execute(
                """
                INSERT INTO tls_observations (host_id, scan_run_id, subject, issuer, valid_from,
                    valid_until, sans, serial, tls_version, observed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    host_id,
                    run_id,
                    tls.subject,
                    tls.issuer,
                    tls.valid_from,
                    tls.valid_until,
                    json.dumps(tls.sans[:50]),
                    tls.serial_number,
                    tls.tls_version,
                    utcnow_iso(),
                ),
            )

    def _save_technology(self, conn: sqlite3.Connection, host_id: int, run_id: int, host: Any) -> None:
        for tech in host.technologies or []:
            conn.execute(
                """
                INSERT INTO technology (host_id, scan_run_id, name, category, evidence, confidence)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(host_id, name) DO UPDATE SET
                    category=excluded.category,
                    evidence=excluded.evidence,
                    confidence=excluded.confidence,
                    scan_run_id=excluded.scan_run_id
                """,
                (host_id, run_id, tech.name, tech.category, tech.evidence[:300], int(tech.confidence)),
            )

    def _record_error(
        self,
        conn: sqlite3.Connection,
        run_id: Optional[int],
        source: Optional[str],
        message: str,
    ) -> None:
        conn.execute(
            "INSERT INTO errors (scan_run_id, source, message, created_at) VALUES (?,?,?,?)",
            (run_id, source, str(message)[:500], utcnow_iso()),
        )

    def record_error(self, run_id: Optional[int], source: Optional[str], message: str) -> None:
        """Public helper used by the engine for non-fatal errors."""
        conn = self.connect()
        with conn:
            self._record_error(conn, run_id, source, message)

    def export_json(self, domain: str) -> Dict[str, Any]:
        """Return a JSON-serialisable snapshot of everything known about a target."""
        hosts = self.hosts(domain)
        return {
            "tool": "SubdomainX",
            "target": {"domain": domain},
            "stats": self.stats(domain),
            "history": self.history(domain),
            "hosts": hosts,
        }


def open_database(path: str = DEFAULT_DB_PATH, logger=None) -> Database:
    """Open (and migrate) a database file."""
    db = Database(path, logger=logger)
    db.connect()
    return db


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> List[Dict[str, Any]]:
    """Convert sqlite rows into plain dictionaries."""
    return [dict(row) for row in rows]


def _unused(*args: Sequence[Any]) -> None:  # pragma: no cover
    return None
