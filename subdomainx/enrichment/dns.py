"""DNS intelligence and wildcard detection.

Reads public DNS only - no zone transfers are attempted, no exploitation of any
kind is performed.  A bounded ``ThreadPoolExecutor`` keeps concurrency sane.
"""

from __future__ import annotations

import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import dns.exception
import dns.flags
import dns.rdatatype
import dns.resolver

from ..models import DNSInfo, WildcardState
from ..utils.helpers import random_hostnames
from ..utils.logging import get_logger

DEFAULT_RECORD_TYPES: Tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA")

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_INTERNAL_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".intranet", ".home.arpa")


@dataclass
class DNSOptions:
    """Configuration for :class:`DNSEngine`."""

    record_types: Sequence[str] = DEFAULT_RECORD_TYPES
    timeout: float = 5.0
    retries: int = 1
    threads: int = 10
    nameservers: Optional[List[str]] = None
    detect_wildcard: bool = True
    dnssec: bool = False
    probes: int = 3


@dataclass
class WildcardReport:
    """Outcome of the wildcard detection routine."""

    domain: str
    state: WildcardState = WildcardState.UNKNOWN
    probes: List[str] = field(default_factory=list)
    answers: Dict[str, List[str]] = field(default_factory=dict)
    resolved_count: int = 0

    @property
    def signature(self) -> Set[str]:
        """Normalised answer signature shared by the wildcard probes."""
        return set(self.answers.get("_wildcard", []))

    def to_dict(self) -> Dict[str, object]:
        return {
            "domain": self.domain,
            "state": self.state.value,
            "probes": self.probes,
            "resolved_count": self.resolved_count,
            "answers": {k: v for k, v in self.answers.items() if not k.startswith("_")},
        }


class DNSEngine:
    """Resolve DNS metadata for a set of hostnames."""

    def __init__(
        self,
        options: Optional[DNSOptions] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.options = options or DNSOptions()
        self.logger = logger or get_logger()
        self.resolver = self._build_resolver()

    # -- setup ------------------------------------------------------------
    def _build_resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.timeout = float(self.options.timeout)
        resolver.lifetime = float(self.options.timeout) * (self.options.retries + 1)
        if self.options.nameservers:
            resolver.nameservers = list(self.options.nameservers)
        return resolver

    # -- public API -------------------------------------------------------
    def detect_wildcard(self, domain: str) -> WildcardReport:
        """Detect wildcard DNS behaviour for ``domain``.

        Several random labels that cannot exist are resolved and their answers
        compared:

        * no probe resolves                 -> ``NO WILDCARD``
        * only some probes resolve          -> ``PARTIAL WILDCARD``
        * all probes resolve to same answer -> ``WILDCARD DETECTED``
        """
        report = WildcardReport(domain=domain)
        if not self.options.detect_wildcard:
            report.state = WildcardState.UNKNOWN
            return report

        probes = random_hostnames(domain, self.options.probes)
        report.probes = probes
        signatures: List[Set[str]] = []
        for probe in probes:
            info = self.resolve(probe, record_types=("A", "AAAA", "CNAME"))
            if info.resolved:
                report.resolved_count += 1
                signatures.append(set(info.a) | set(info.aaaa) | set(info.cname))
                report.answers[probe] = info.a + info.aaaa + info.cname

        if not signatures:
            report.state = WildcardState.NONE
        elif len(signatures) == len(probes):
            intersection = set.intersection(*signatures) if signatures else set()
            if intersection:
                report.answers["_wildcard"] = sorted(intersection)
                report.state = WildcardState.WILDCARD
            else:
                report.state = WildcardState.PARTIAL
        else:
            report.state = WildcardState.PARTIAL
        return report

    def resolve(
        self,
        host: str,
        record_types: Optional[Sequence[str]] = None,
    ) -> DNSInfo:
        """Resolve ``host`` and return a :class:`DNSInfo` record."""
        from ..models import utcnow_iso

        info = DNSInfo(host=host, queried_at=utcnow_iso())
        types = tuple(record_types or self.options.record_types)
        errors: List[str] = []

        for rtype in types:
            try:
                answer = self.resolver.resolve(host, rtype)
            except dns.resolver.NXDOMAIN:
                errors.append(f"{rtype}:NXDOMAIN")
                continue
            except dns.resolver.NoAnswer:
                continue
            except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
                errors.append(f"{rtype}:{exc.__class__.__name__}")
                continue
            except Exception as exc:  # noqa: BLE001 - never break enrichment
                self.logger.debug("DNS query failed for %s %s: %s", host, rtype, exc)
                continue

            values = self._extract(rtype, answer)
            if not values:
                continue
            target = {
                "A": info.a,
                "AAAA": info.aaaa,
                "CNAME": info.cname,
                "MX": info.mx,
                "NS": info.ns,
                "TXT": info.txt,
                "CAA": info.caa,
                "SOA": info.soa,
            }.get(rtype)
            if target is not None:
                target.extend(values)
            info.resolved = True

        info.a = sorted(set(info.a))
        info.aaaa = sorted(set(info.aaaa))
        info.cname = sorted(set(c.rstrip(".").lower() for c in info.cname))
        info.mx = sorted(set(info.mx))
        info.ns = sorted(set(n.rstrip(".").lower() for n in info.ns))
        info.txt = sorted(set(info.txt))[:10]
        info.caa = sorted(set(info.caa))
        info.internal_looking = self._looks_internal(info)
        if errors:
            info.error = "; ".join(errors)[:300]
        return info

    def resolve_many(
        self,
        hosts: Sequence[str],
        wildcard: Optional[WildcardReport] = None,
        callback=None,
    ) -> Dict[str, DNSInfo]:
        """Resolve many hosts concurrently, optionally flagging wildcard hits."""
        results: Dict[str, DNSInfo] = {}
        hosts = list(dict.fromkeys(hosts or []))
        if not hosts:
            return results

        threads = max(1, min(int(self.options.threads), 64))
        with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="dns") as pool:
            futures = {pool.submit(self.resolve, host): host for host in hosts}
            for future, host in futures.items():
                try:
                    info = future.result()
                except Exception as exc:  # noqa: BLE001
                    self.logger.debug("DNS resolution crashed for %s: %s", host, exc)
                    info = DNSInfo(host=host, error=str(exc))
                results[host] = info
                if callback:
                    callback(info)

        if wildcard is not None and wildcard.state is not WildcardState.NONE:
            signature = wildcard.signature
            if signature:
                for info in results.values():
                    answers = set(info.a) | set(info.aaaa) | set(info.cname)
                    if answers and answers <= signature:
                        info.wildcard = True
        return results

    def dnssec_status(self, host: str) -> Optional[str]:
        """Best effort DNSSEC status for the zone owning ``host``."""
        if not self.options.dnssec:
            return None
        try:
            from ..discovery.validate import registrable_domain

            zone = registrable_domain(host) or host
            answer = self.resolver.resolve(zone, "DNSKEY", want_dnssec=True)
            response = getattr(answer, "response", None)
            if response is None:
                return None
            if dns.flags.Flag.AD & response.flags:
                return "signed (AD flag)"
            rrsig = any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer)
            return "signed" if rrsig else "unsigned"
        except Exception:  # noqa: BLE001 - DNSSEC probing is best effort only
            return None

    # -- internals --------------------------------------------------------
    @staticmethod
    def _extract(rtype: str, answer) -> List[str]:  # noqa: ANN001
        """Convert a dnspython answer into a list of strings."""
        values: List[str] = []
        try:
            for record in answer:
                text = record.to_text()
                if rtype == "TXT":
                    text = text.strip('"')[:300]
                elif rtype == "CAA":
                    text = text.replace('"', "").strip()[:300]
                values.append(text.strip().rstrip(".").lower())
        except Exception:  # noqa: BLE001
            return []
        return values

    @staticmethod
    def _looks_internal(info: DNSInfo) -> bool:
        """True when the name points at private/internal infrastructure."""
        for ip_text in info.a + info.aaaa:
            try:
                address = ipaddress.ip_address(ip_text.split("%")[0])
            except ValueError:
                continue
            if any(address in network for network in _PRIVATE_NETWORKS):
                return True
        for cname in info.cname:
            if cname.endswith(_INTERNAL_SUFFIXES):
                return True
        return False


def summarize_dns(records: Iterable[DNSInfo]) -> Dict[str, int]:
    """Small counter block used by reports."""
    resolved = cnames = internal = 0
    for record in records or []:
        resolved += 1 if record.resolved else 0
        cnames += 1 if record.cname else 0
        internal += 1 if record.internal_looking else 0
    return {"resolved": resolved, "cnames": cnames, "internal": internal}
