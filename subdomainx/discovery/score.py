"""Confidence engine.

The confidence score answers a single question: **how much independent
evidence do we have that this hostname is a real asset of the target?**

Positive factors
    source diversity, certificate-transparency presence, several independent
    observation categories, valid DNS, live HTTP, repeated historical sightings.

Negative factors
    wildcard DNS (the host may be an artefact), malformed / random looking
    labels, weak single-source discovery, no current DNS while only historical.

Bands
    ``95-100 VERY HIGH``  ``80-94 HIGH``  ``60-79 MEDIUM``  ``30-59 LOW``
    ``0-29 VERY LOW``
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Tuple

from ..models import ConfidenceLabel, Host, WildcardState

MAX_SCORE = 100
MIN_SCORE = 0

# Sources that are considered "strong" evidence on their own: cryptographically
# signed public logs and authoritative-ish passive DNS collections.
STRONG_SOURCES = {
    "crtsh",
    "certspotter",
    "hackertarget",
    "urlscan",
    "commoncrawl",
    "wayback",
    "otx",
}

_RANDOM_LABEL = re.compile(r"^(?=.*\d)(?=.*[a-z])[a-z0-9-]{18,}$")


@dataclass(frozen=True)
class ScoreFactor:
    """A single, explainable contribution to the confidence score."""

    name: str
    delta: int
    reason: str


def label_for_score(score: int) -> ConfidenceLabel:
    """Map a numeric score to its qualitative band."""
    if score >= 95:
        return ConfidenceLabel.VERY_HIGH
    if score >= 80:
        return ConfidenceLabel.HIGH
    if score >= 60:
        return ConfidenceLabel.MEDIUM
    if score >= 30:
        return ConfidenceLabel.LOW
    return ConfidenceLabel.VERY_LOW


def clamp(score: int) -> int:
    """Keep a score inside ``[0, 100]``."""
    return max(MIN_SCORE, min(MAX_SCORE, int(score)))


def _source_count_factor(count: int) -> int:
    if count >= 4:
        return 32
    if count == 3:
        return 26
    if count == 2:
        return 18
    if count == 1:
        return 8
    return 0


def score_host(
    host: Host,
    wildcard: WildcardState = WildcardState.UNKNOWN,
) -> Tuple[int, ConfidenceLabel, List[str], List[ScoreFactor]]:
    """Compute the confidence score for a host.

    Returns ``(score, label, human readable reasons, structured factors)``.
    """
    factors: List[ScoreFactor] = []
    score = 20  # any normalised, in-scope sighting starts with a small base

    # -- source evidence --------------------------------------------------
    count = host.source_count
    delta = _source_count_factor(count)
    if delta:
        factors.append(
            ScoreFactor(
                "source_diversity",
                delta,
                f"{count} independent source(s) reported this host",
            )
        )
        score += delta

    strength = len(STRONG_SOURCES & set(host.sources))
    if strength:
        factors.append(
            ScoreFactor("strong_sources", strength * 3, f"{strength} high-trust source(s)")
        )
        score += strength * 3

    # -- certificate transparency -----------------------------------------
    if host.ct_present:
        factors.append(ScoreFactor("ct_presence", 12, "present in certificate transparency logs"))
        score += 12

    # -- DNS --------------------------------------------------------------
    if host.dns and host.dns.resolved:
        if host.dns.a or host.dns.aaaa:
            factors.append(ScoreFactor("dns_resolved", 20, "resolves to A/AAAA records"))
            score += 20
        elif host.dns.cname:
            factors.append(ScoreFactor("dns_cname", 12, "resolves through a CNAME"))
            score += 12
        if host.dns.dnssec:
            factors.append(ScoreFactor("dnssec", 3, f"DNSSEC: {host.dns.dnssec}"))
            score += 3

    # -- HTTP -------------------------------------------------------------
    if host.http:
        status = host.http.status_code
        if status is not None and status < 400:
            factors.append(ScoreFactor("http_live", 12, f"HTTP {status}"))
            score += 12
        elif status is not None and 400 <= status < 500:
            factors.append(ScoreFactor("http_client_error", 8, f"HTTP {status} (host exists)"))
            score += 8
        elif status is not None and status >= 500:
            factors.append(ScoreFactor("http_server_error", 4, f"HTTP {status}"))
            score += 4

    # -- historical -------------------------------------------------------
    historical_hits = sum(max(0, h.observations) for h in host.history.values())
    if historical_hits >= 3:
        factors.append(ScoreFactor("historical", 6, f"{historical_hits} historical sightings"))
        score += 6
    elif historical_hits >= 1:
        factors.append(ScoreFactor("historical", 3, f"{historical_hits} historical sighting(s)"))
        score += 3

    # -- penalties --------------------------------------------------------
    if wildcard is WildcardState.WILDCARD and host.dns and host.dns.wildcard:
        factors.append(
            ScoreFactor("wildcard", -25, "answer matches a wildcard DNS record")
        )
        score -= 25
    elif wildcard is WildcardState.PARTIAL and host.dns and host.dns.wildcard:
        factors.append(ScoreFactor("wildcard", -10, "partial wildcard DNS detected"))
        score -= 10

    if count == 1 and not host.ct_present and not (host.dns and host.dns.resolved):
        factors.append(
            ScoreFactor("weak_single_source", -8, "single source, no DNS or CT corroboration")
        )
        score -= 8

    if _looks_suspicious(host.host):
        factors.append(ScoreFactor("suspicious_label", -5, "unusually long / random looking label"))
        score -= 5

    if host.history and not host.dns_resolved and not host.http_status:
        factors.append(
            ScoreFactor("historical_only", -10, "only historical evidence, no current DNS/HTTP")
        )
        score -= 10

    final = clamp(score)
    label = label_for_score(final)
    reasons = [f"{f.delta:+d} {f.reason}" for f in factors]
    return final, label, reasons, factors


def _looks_suspicious(host: str) -> bool:
    """Heuristic: labels that look auto-generated rather than real assets."""
    labels = (host or "").split(".")
    if len(labels) > 6:
        return True
    for label in labels[:-2]:
        if len(label) > 40:
            return True
        if _RANDOM_LABEL.match(label):
            return True
    return False


# ---------------------------------------------------------------------------
# priority queue
# ---------------------------------------------------------------------------

_PRIORITY_RULES = (
    (lambda h, r: h.interesting and "Administrative-looking hostname" in h.interesting_reasons and h.http_status is not None and h.http_status < 500, 100, "live administrative-looking host"),
    (lambda h, r: h.interesting and "Administrative-looking hostname" in h.interesting_reasons, 90, "administrative-looking host"),
    (lambda h, r: h.category.value == "API" and (h.http_status or 599) < 500, 85, "live API host"),
    (lambda h, r: h.category.value == "Authentication" and (h.http_status or 599) < 500, 80, "live authentication host"),
    (lambda h, r: h.category.value in {"Development", "Testing", "Staging"} and (h.http_status or 599) < 500, 70, "live development/staging host"),
    (lambda h, r: h.category.value in {"Development", "Testing", "Staging"}, 60, "development/staging host"),
    (lambda h, r: h.cloud is not None, 50, "cloud asset"),
    (lambda h, r: h.activity.value == "HISTORICAL", 35, "historical host"),
    (lambda h, r: (h.http_status or 599) < 400, 30, "live host"),
)


def compute_priority(host: Host) -> Tuple[int, List[str]]:
    """Return a reconnaissance-priority value (higher = look here first).

    This is *prioritisation only*; it is never a vulnerability statement.
    """
    priority = 10
    reasons: List[str] = []
    for predicate, value, reason in _PRIORITY_RULES:
        if predicate(host, reasons):
            priority = max(priority, value)
            reasons.append(reason)
    priority += min(10, host.source_count)
    return priority, reasons


def rank_hosts(hosts: List[Host]) -> List[Host]:
    """Sort hosts by priority, then confidence, then name."""
    return sorted(hosts, key=lambda h: (-h.priority, -h.confidence, h.host))
