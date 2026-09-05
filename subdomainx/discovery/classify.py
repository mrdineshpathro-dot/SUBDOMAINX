"""Hostname classification and "interesting host" detection.

!!! important
    Nothing in this module is a vulnerability statement.  A host flagged as
    ``INTERESTING`` simply means "a human researcher should probably look at
    this first", with the reason spelled out in plain language, e.g.::

        INTERESTING HOST
        REASON: Administrative-looking hostname
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from ..models import ActivityState, Host, HostCategory

# ---------------------------------------------------------------------------
# interesting host rules:  keyword -> human readable reason
# ---------------------------------------------------------------------------

INTERESTING_RULES: List[Tuple[Tuple[str, ...], str]] = [
    (
        ("admin", "administrator", "adm", "admins", "wp-admin", "cpanel", "whm", "webmin", "plesk", "backend", "backoffice", "manage", "management", "manager"),
        "Administrative-looking hostname",
    ),
    (
        ("portal", "dashboard", "console", "panel", "control", "controlpanel", "cockpit"),
        "Administrative or portal interface",
    ),
    (
        ("login", "logon", "signin", "sign-in", "signon", "auth", "authn", "authentication", "sso", "oauth", "saml", "idp", "identity", "account", "accounts", "passport", "session", "keycloak", "okta"),
        "Authentication-related hostname",
    ),
    (
        ("vpn", "remote", "rdp", "citrix", "ssh", "bastion", "jump", "jumpbox", "anyconnect", "openvpn", "wireguard", "gateway-vpn"),
        "Remote access hostname",
    ),
    (
        ("dev", "develop", "developer", "development", "devel", "dev-api", "devapi", "sandbox", "scratch"),
        "Development hostname",
    ),
    (
        ("test", "testing", "tests", "qa", "qc", "uat", "sit", "stage", "staging", "stg", "preprod", "pre-prod", "preview", "beta", "alpha", "demo", "canary", "nightly"),
        "Testing / staging hostname",
    ),
    (
        ("api", "apis", "api-dev", "api-test", "api2", "graphql", "rest", "restapi", "grpc", "gateway", "gw", "edge", "soap", "webhook", "webhooks", "openapi", "swagger"),
        "API hostname",
    ),
    (
        ("git", "gitlab", "github", "gitea", "svn", "bitbucket", "repo", "jira", "confluence", "stash", "fisheye", "crucible", "wiki"),
        "Source control / collaboration hostname",
    ),
    (
        ("jenkins", "ci", "cd", "build", "builds", "bamboo", "teamcity", "drone", "argo", "argocd", "gitlab-runner", "runner", "pipeline", "pipelines", "travis", "circleci", "sonar", "nexus", "artifactory", "registry", "harbor"),
        "CI/CD or build infrastructure hostname",
    ),
    (
        ("monitor", "monitoring", "grafana", "kibana", "prometheus", "nagios", "zabbix", "sentry", "status", "statuspage", "health", "healthcheck", "pingdom", "datadog", "newrelic", "elk", "logstash", "observability", "uptime"),
        "Monitoring / observability hostname",
    ),
    (
        ("mail", "smtp", "smtps", "imap", "pop", "pop3", "webmail", "mx", "mx1", "mx2", "exchange", "owa", "outlook", "postfix", "sendgrid", "mailer", "newsletter", "email"),
        "Mail infrastructure hostname",
    ),
    (
        ("db", "database", "sql", "mysql", "mariadb", "postgres", "postgresql", "mongo", "mongodb", "redis", "memcached", "elastic", "elasticsearch", "cassandra", "oracle", "mssql", "couchdb", "dynamo", "datastore"),
        "Database hostname",
    ),
    (
        ("backup", "backups", "bak", "archive", "archives", "snapshot", "snapshots", "dump", "storage", "s3", "blob", "nas", "files", "file", "ftp", "sftp", "share", "shares", "docs"),
        "Backup / storage hostname",
    ),
    (
        ("internal", "intranet", "intra", "corp", "corporate", "lan", "private", "priv", "office", "hq", "staff", "employee"),
        "Internal-looking hostname",
    ),
    (
        ("support", "helpdesk", "help", "ticket", "tickets", "crm", "erp", "billing", "invoice", "payment", "pay", "payments", "checkout", "check-out", "order", "orders", "customer", "client", "partner", "vendor", "affiliate"),
        "Business application hostname",
    ),
    (
        ("cdn", "static", "assets", "asset", "media", "img", "images", "image", "css", "js", "upload", "uploads", "download", "downloads", "cache", "edge-cache"),
        "Static / asset delivery hostname",
    ),
    (
        ("ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "resolver", "ns01"),
        "DNS infrastructure hostname",
    ),
    (
        ("old", "legacy", "deprecated", "archive", "historic", "retired", "unused", "abandoned", "orphan", "forgotten"),
        "Legacy / possibly forgotten hostname",
    ),
]

# ---------------------------------------------------------------------------
# category rules (first match wins, order matters)
# ---------------------------------------------------------------------------

CATEGORY_RULES: List[Tuple[Tuple[str, ...], HostCategory]] = [
    (
        ("admin", "administrator", "adm", "cpanel", "webmin", "plesk", "backend", "backoffice", "manage", "management", "manager", "console", "panel"),
        HostCategory.ADMIN,
    ),
    (
        ("login", "signin", "auth", "sso", "oauth", "saml", "idp", "identity", "account", "passport", "keycloak", "okta"),
        HostCategory.AUTHENTICATION,
    ),
    (
        ("api", "graphql", "rest", "grpc", "gateway", "gw", "webhook", "openapi", "swagger"),
        HostCategory.API,
    ),
    (
        ("stage", "staging", "stg", "preprod", "pre-prod", "uat", "sit", "canary", "preview"),
        HostCategory.STAGING,
    ),
    (
        ("dev", "develop", "developer", "development", "devel", "sandbox", "scratch"),
        HostCategory.DEVELOPMENT,
    ),
    (
        ("test", "testing", "tests", "qa", "qc", "beta", "alpha", "demo", "nightly"),
        HostCategory.TESTING,
    ),
    (
        ("mail", "smtp", "imap", "pop", "webmail", "mx", "exchange", "owa", "outlook", "postfix"),
        HostCategory.MAIL,
    ),
    (
        ("monitor", "monitoring", "grafana", "kibana", "prometheus", "nagios", "zabbix", "sentry", "status", "health", "datadog", "newrelic", "uptime"),
        HostCategory.MONITORING,
    ),
    (
        ("cdn", "static", "assets", "media", "img", "images", "cache", "edge"),
        HostCategory.CDN,
    ),
    (
        ("ns", "dns", "resolver", "vpn", "remote", "rdp", "bastion", "jump", "ssh", "jenkins", "ci", "build", "git", "gitlab", "jira", "registry", "nexus", "artifactory", "db", "database", "sql", "mongo", "redis", "elastic"),
        HostCategory.INFRASTRUCTURE,
    ),
    (
        ("www", "home", "app", "apps", "shop", "store", "site", "web", "main", "portal", "dashboard", "blog", "news", "marketing"),
        HostCategory.PRODUCTION,
    ),
]

_CLOUD_HINTS = (
    "s3",
    "blob",
    "storage",
    "cloud",
    "aws",
    "azure",
    "gcp",
    "cloudfront",
    "akamai",
    "fastly",
)


def _labels(host: str) -> List[str]:
    """Return the meaningful labels of a hostname (TLD and apex removed)."""
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) <= 2:
        return []
    return parts[:-2]


def _tokens(host: str) -> List[str]:
    """Split every sub-label into keyword tokens."""
    tokens: List[str] = []
    for label in _labels(host):
        for piece in re.split(r"[-_.]", label):
            piece = piece.strip()
            if piece:
                tokens.append(piece)
        tokens.append(label)
    return tokens


def classify_category(host: str) -> HostCategory:
    """Classify a hostname into a coarse functional category."""
    tokens = set(_tokens(host))
    if not tokens:
        return HostCategory.PRODUCTION  # apex host
    for keywords, category in CATEGORY_RULES:
        if tokens & set(keywords):
            return category
    return HostCategory.UNKNOWN


def find_interesting_reasons(host: str) -> List[str]:
    """Return plain-language reasons why a hostname is worth a human look."""
    tokens = set(_tokens(host))
    reasons: List[str] = []
    for keywords, reason in INTERESTING_RULES:
        if tokens & set(keywords) and reason not in reasons:
            reasons.append(reason)
    return reasons


def classify_host(host: Host) -> Host:
    """Attach category, interesting flags and activity state to a host."""
    host.category = classify_category(host.host)
    # Only hostname semantics drive "interesting"; CDN/cloud evidence is
    # reported separately so it does not dilute the interesting-host signal.
    reasons = find_interesting_reasons(host.host)
    host.interesting_reasons = reasons
    host.interesting = bool(reasons)

    # Activity: current vs historical.
    if host.dns_resolved or (host.http and host.http.status_code is not None):
        host.activity = ActivityState.CURRENT
    elif host.history:
        host.activity = ActivityState.HISTORICAL
    else:
        host.activity = ActivityState.UNKNOWN
    return host


def summarize_categories(hosts: List[Host]) -> Dict[str, int]:
    """Count hosts per category (used by reports and the HTML dashboard)."""
    summary: Dict[str, int] = {}
    for host in hosts:
        summary[host.category.value] = summary.get(host.category.value, 0) + 1
    return dict(sorted(summary.items(), key=lambda kv: (-kv[1], kv[0])))
