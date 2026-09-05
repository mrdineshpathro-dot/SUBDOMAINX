"""SQLite schema and migrations.

The database is created lazily and upgraded in place.  Every statement is
idempotent so an existing ``subdomainx.db`` keeps working across versions.
"""

from __future__ import annotations

import sqlite3
from typing import List, Tuple

SCHEMA_VERSION = 1

#: Ordered list of ``(version, sql)`` migration steps.
MIGRATIONS: List[Tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS targets (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            domain             TEXT NOT NULL UNIQUE,
            registrable_domain TEXT,
            created_at         TEXT NOT NULL,
            last_scan_at       TEXT
        );

        CREATE TABLE IF NOT EXISTS sources (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            name             TEXT NOT NULL UNIQUE,
            category         TEXT,
            description      TEXT,
            requires_api_key INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS scan_runs (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id          INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            started_at         TEXT NOT NULL,
            finished_at        TEXT,
            duration_seconds   REAL NOT NULL DEFAULT 0,
            profile            TEXT,
            raw_results        INTEGER NOT NULL DEFAULT 0,
            unique_results     INTEGER NOT NULL DEFAULT 0,
            valid_results      INTEGER NOT NULL DEFAULT 0,
            dns_hosts          INTEGER NOT NULL DEFAULT 0,
            live_hosts         INTEGER NOT NULL DEFAULT 0,
            historical_hosts   INTEGER NOT NULL DEFAULT 0,
            interesting_hosts  INTEGER NOT NULL DEFAULT 0,
            sources_total      INTEGER NOT NULL DEFAULT 0,
            sources_ok         INTEGER NOT NULL DEFAULT 0,
            sources_failed     INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id           INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
            host                TEXT NOT NULL,
            registrable_domain  TEXT,
            confidence          INTEGER NOT NULL DEFAULT 0,
            confidence_label    TEXT,
            category            TEXT,
            priority            INTEGER NOT NULL DEFAULT 0,
            interesting         INTEGER NOT NULL DEFAULT 0,
            activity            TEXT,
            cdn_provider        TEXT,
            cdn_confidence      TEXT,
            cloud_provider      TEXT,
            first_seen          TEXT,
            last_seen           TEXT,
            total_observations  INTEGER NOT NULL DEFAULT 0,
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL,
            UNIQUE (target_id, host)
        );

        CREATE TABLE IF NOT EXISTS run_hosts (
            scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            PRIMARY KEY (scan_run_id, host_id)
        );

        CREATE TABLE IF NOT EXISTS observations (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            source_id  INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            first_seen TEXT,
            last_seen  TEXT,
            count      INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL,
            UNIQUE (host_id, source_id)
        );

        CREATE TABLE IF NOT EXISTS source_runs (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id        INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
            source_id          INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
            status             TEXT,
            results            INTEGER NOT NULL DEFAULT 0,
            response_time_ms   REAL NOT NULL DEFAULT 0,
            http_status        INTEGER,
            success_count      INTEGER NOT NULL DEFAULT 0,
            error_count        INTEGER NOT NULL DEFAULT 0,
            rate_limit_events  INTEGER NOT NULL DEFAULT 0,
            parser_failures    INTEGER NOT NULL DEFAULT 0,
            error              TEXT
        );

        CREATE TABLE IF NOT EXISTS dns_records (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id        INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            scan_run_id    INTEGER REFERENCES scan_runs(id) ON DELETE CASCADE,
            record_type    TEXT NOT NULL,
            value          TEXT NOT NULL,
            resolved       INTEGER NOT NULL DEFAULT 0,
            wildcard       INTEGER NOT NULL DEFAULT 0,
            internal       INTEGER NOT NULL DEFAULT 0,
            dnssec         TEXT,
            observed_at    TEXT
        );

        CREATE TABLE IF NOT EXISTS http_observations (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id           INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            scan_run_id       INTEGER REFERENCES scan_runs(id) ON DELETE CASCADE,
            url               TEXT,
            final_url         TEXT,
            scheme            TEXT,
            status_code       INTEGER,
            category          TEXT,
            title             TEXT,
            server            TEXT,
            content_type      TEXT,
            content_length    INTEGER,
            response_time_ms  REAL NOT NULL DEFAULT 0,
            redirect_count    INTEGER NOT NULL DEFAULT 0,
            error             TEXT,
            observed_at       TEXT
        );

        CREATE TABLE IF NOT EXISTS tls_observations (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            scan_run_id  INTEGER REFERENCES scan_runs(id) ON DELETE CASCADE,
            subject      TEXT,
            issuer       TEXT,
            valid_from   TEXT,
            valid_until  TEXT,
            sans         TEXT,
            serial       TEXT,
            tls_version  TEXT,
            observed_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS technology (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            scan_run_id INTEGER REFERENCES scan_runs(id) ON DELETE CASCADE,
            name       TEXT NOT NULL,
            category   TEXT,
            evidence   TEXT,
            confidence INTEGER NOT NULL DEFAULT 50,
            UNIQUE (host_id, name)
        );

        CREATE TABLE IF NOT EXISTS historical_observations (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id            INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            source_id          INTEGER REFERENCES sources(id) ON DELETE CASCADE,
            first_seen         TEXT,
            last_seen          TEXT,
            observations       INTEGER NOT NULL DEFAULT 0,
            currently_observed INTEGER NOT NULL DEFAULT 0,
            UNIQUE (host_id, source_id)
        );

        CREATE TABLE IF NOT EXISTS errors (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER REFERENCES scan_runs(id) ON DELETE CASCADE,
            source      TEXT,
            message     TEXT,
            created_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_hosts_target ON hosts(target_id);
        CREATE INDEX IF NOT EXISTS idx_hosts_confidence ON hosts(confidence DESC);
        CREATE INDEX IF NOT EXISTS idx_dns_host ON dns_records(host_id);
        CREATE INDEX IF NOT EXISTS idx_http_host ON http_observations(host_id);
        CREATE INDEX IF NOT EXISTS idx_obs_host ON observations(host_id);
        CREATE INDEX IF NOT EXISTS idx_run_hosts_run ON run_hosts(scan_run_id);
        """,
    ),
]


def current_version(conn: sqlite3.Connection) -> int:
    """Return the applied schema version (0 when the DB is brand new)."""
    try:
        row = conn.execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row and row[0] else 0
    except sqlite3.Error:
        return 0


def apply_migrations(conn: sqlite3.Connection) -> int:
    """Apply all pending migrations and return the resulting version."""
    version = current_version(conn)
    for target, statement in MIGRATIONS:
        if target <= version:
            continue
        with conn:
            conn.executescript(statement)
            conn.execute(f"PRAGMA user_version = {target}")
        version = target
    return version
