"""Scope enforcement and hostname validation.

SUBDOMAINX must never report a host that does not belong to the target's
registrable domain.  This module implements strict, registrable-domain aware
scope checks using ``tldextract`` (with a built-in offline suffix snapshot and a
conservative fallback so the tool also works when the snapshot is missing).

Examples (target ``example.com``)::

    example.com            -> in scope
    www.example.com        -> in scope
    dev.api.example.com    -> in scope
    example.com.evil.com   -> OUT of scope
    evil-example.com       -> OUT of scope
    example.org            -> OUT of scope
    fooexample.com         -> OUT of scope

Multi-part suffixes such as ``co.uk``, ``com.au``, ``co.in`` and ``org.uk`` are
handled correctly.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List, Optional, Sequence, Set

from ..utils.helpers import is_local_name
from .normalize import normalize_host

# Regex used when the offline suffix list is unavailable.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")

# Conservative fallback table of common multi-label public suffixes.
_FALLBACK_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "me.uk",
    "net.uk",
    "sch.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "id.au",
    "co.in",
    "net.in",
    "org.in",
    "gen.in",
    "firm.in",
    "ind.in",
    "nic.in",
    "res.in",
    "edu.in",
    "ac.in",
    "gov.in",
    "mil.in",
    "co.nz",
    "net.nz",
    "org.nz",
    "govt.nz",
    "ac.nz",
    "co.za",
    "org.za",
    "net.za",
    "web.za",
    "co.jp",
    "or.jp",
    "ne.jp",
    "ac.jp",
    "go.jp",
    "co.kr",
    "or.kr",
    "ne.kr",
    "go.kr",
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    "com.mx",
    "com.ar",
    "com.tr",
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "com.sg",
    "com.hk",
    "com.tw",
    "com.pl",
    "com.ua",
    "co.il",
    "org.il",
    "net.il",
    "com.es",
    "com.co",
    "com.pe",
    "com.ng",
    "co.id",
    "or.id",
    "web.id",
    "com.ph",
    "com.my",
    "com.vn",
    "com.pk",
    "com.sa",
    "com.ec",
    "com.uy",
    "com.ve",
}

_extractor = None
_extractor_ready = False


def _get_extractor():  # noqa: ANN201
    """Return a lazily created, offline ``tldextract`` extractor (or ``None``)."""
    global _extractor, _extractor_ready
    if _extractor_ready:
        return _extractor
    _extractor_ready = True
    try:
        import tldextract  # type: ignore

        # ``suffix_list_urls=()`` forces the bundled snapshot: no network access.
        _extractor = tldextract.TLDExtract(suffix_list_urls=())
    except Exception:  # noqa: BLE001 - tldextract is optional at runtime
        _extractor = None
    return _extractor


def is_ip_address(value: str) -> bool:
    """True when the string is a literal IP address."""
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def is_valid_hostname(host: object, allow_underscore: bool = True) -> bool:
    """Strict syntactic validation of an already normalised hostname."""
    if not isinstance(host, str) or not host:
        return False
    candidate = host.strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253 or ".." in candidate:
        return False
    if is_ip_address(candidate):
        return False
    if is_local_name(candidate):
        return False
    if "." not in candidate:
        return False
    labels = candidate.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        allowed = re.compile(r"^[a-z0-9_-]+$")
        if not allowed.match(label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not allow_underscore and "_" in label:
            return False
    tld = labels[-1]
    if tld.isdigit():
        return False
    if not re.match(r"^[a-z]{2,63}$", tld) and not tld.startswith("xn--"):
        return False
    return True


def registrable_domain(host: str) -> str:
    """Return the registrable (eTLD+1) domain for ``host``."""
    if not host:
        return ""
    candidate = normalize_host(host) or host.strip().lower().rstrip(".")
    extractor = _get_extractor()
    if extractor is not None:
        try:
            extracted = extractor(candidate)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}".lower()
        except Exception:  # noqa: BLE001
            pass
    return _fallback_registrable_domain(candidate)


def _fallback_registrable_domain(host: str) -> str:
    """Offline fallback used when ``tldextract`` cannot be used."""
    labels = host.strip().lower().rstrip(".").split(".")
    if len(labels) < 2:
        return host
    if len(labels) >= 3 and ".".join(labels[-2:]) in _FALLBACK_SUFFIXES:
        return ".".join(labels[-3:])
    if len(labels) >= 3 and ".".join(labels[-3:]) in _FALLBACK_SUFFIXES:
        return ".".join(labels[-4:])
    return ".".join(labels[-2:])


def is_subdomain_of(host: str, domain: str) -> bool:
    """True when ``host`` is ``domain`` or lives strictly beneath it."""
    host = (host or "").strip().lower().rstrip(".")
    domain = (domain or "").strip().lower().rstrip(".")
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)


def is_in_scope(host: str, target: str) -> bool:
    """Strict scope check for a discovered hostname against the target."""
    host = (host or "").strip().lower().rstrip(".")
    target = (target or "").strip().lower().rstrip(".")
    if not host or not target:
        return False
    if not is_valid_hostname(host):
        return False
    if registrable_domain(host) != registrable_domain(target):
        return False
    return is_subdomain_of(host, target)


class ScopeMatcher:
    """Restrict results using an allow-list of scope patterns.

    Supported patterns::

        example.com         -> example.com and *.example.com
        *.example.com       -> any subdomain (not the apex)
        api.example.com     -> exact host and its subdomains
        .example.com        -> same as *.example.com
    """

    def __init__(self, patterns: Optional[Iterable[str]] = None) -> None:
        self.patterns: List[str] = []
        self.exact: Set[str] = set()
        self.subtree: Set[str] = set()
        self.registrable: Set[str] = set()
        for pattern in patterns or []:
            self.add(pattern)

    def add(self, pattern: str) -> None:
        cleaned = (pattern or "").strip().lower().rstrip(".")
        if not cleaned or cleaned.startswith("#"):
            return
        cleaned = cleaned.replace("https://", "").replace("http://", "").split("/")[0]
        if not cleaned:
            return
        self.patterns.append(cleaned)
        if cleaned.startswith("*."):
            self.subtree.add(cleaned[2:])
        elif cleaned.startswith("."):
            self.subtree.add(cleaned[1:])
        else:
            self.exact.add(cleaned)
        try:
            self.registrable.add(registrable_domain(cleaned))
        except Exception:  # noqa: BLE001
            pass

    @property
    def empty(self) -> bool:
        return not (self.exact or self.subtree)

    def matches(self, host: str) -> bool:
        """True when ``host`` satisfies the scope allow-list."""
        if self.empty:
            return True
        candidate = (host or "").strip().lower().rstrip(".")
        if not candidate:
            return False
        if candidate in self.exact:
            return True
        for apex in self.subtree:
            if candidate.endswith("." + apex):
                return True
        return False

    def __len__(self) -> int:  # pragma: no cover - convenience
        return len(self.patterns)


class ExclusionMatcher:
    """Drop results matching an exclusion list (exact host, wildcard or regex)."""

    def __init__(self, patterns: Optional[Iterable[str]] = None) -> None:
        self.exact: Set[str] = set()
        self.subtree: Set[str] = set()
        self.regexes: List[re.Pattern] = []
        for pattern in patterns or []:
            self.add(pattern)

    def add(self, pattern: str) -> None:
        cleaned = (pattern or "").strip().lower().rstrip(".")
        if not cleaned or cleaned.startswith("#"):
            return
        cleaned = cleaned.replace("https://", "").replace("http://", "").split("/")[0]
        if not cleaned:
            return
        if cleaned.startswith("*."):
            self.subtree.add(cleaned[2:])
        elif cleaned.startswith("."):
            self.subtree.add(cleaned[1:])
        elif cleaned.startswith("re:"):
            try:
                self.regexes.append(re.compile(cleaned[3:], re.IGNORECASE))
            except re.error:
                pass
        else:
            self.exact.add(cleaned)

    @property
    def empty(self) -> bool:
        return not (self.exact or self.subtree or self.regexes)

    def matches(self, host: str) -> bool:
        candidate = (host or "").strip().lower().rstrip(".")
        if not candidate:
            return False
        if candidate in self.exact:
            return True
        for apex in self.subtree:
            if candidate == apex or candidate.endswith("." + apex):
                return True
        return any(rx.search(candidate) for rx in self.regexes)


def read_pattern_file(path: str) -> List[str]:
    """Read a newline separated scope/exclusion file, ignoring comments."""
    lines: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
    except OSError:
        return []
    return lines


def filter_hosts(
    hosts: Sequence[str],
    target: str,
    scope: Optional[ScopeMatcher] = None,
    exclude: Optional[ExclusionMatcher] = None,
    include_regex: Optional[re.Pattern] = None,
    exclude_regex: Optional[re.Pattern] = None,
) -> List[str]:
    """Apply scope, exclusion and regex filters to a list of hostnames."""
    kept: List[str] = []
    for host in hosts:
        if not is_in_scope(host, target):
            continue
        if scope is not None and not scope.matches(host):
            continue
        if exclude is not None and exclude.matches(host):
            continue
        if include_regex is not None and not include_regex.search(host):
            continue
        if exclude_regex is not None and exclude_regex.search(host):
            continue
        kept.append(host)
    return kept
