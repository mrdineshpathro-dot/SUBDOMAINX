"""Optional ASN / IP metadata enrichment.

Disabled by default (``--asn``).  Only public, keyless sources are used and the
module never becomes a hard dependency: if every source fails the host simply
keeps no ASN information.
"""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, List, Optional, Sequence

from ..models import ASNInfo
from ..utils.http import HTTPClient
from ..utils.logging import get_logger

BGPVIEW_URL = "https://api.bgpview.io/ip/{ip}"
IPAPI_URL = "http://ip-api.com/json/{ip}"


class ASNEnricher:
    """Look up ASN / organisation / country metadata for resolved IPs."""

    def __init__(
        self,
        client: HTTPClient,
        threads: int = 5,
        timeout: float = 8.0,
        limit: int = 50,
        logger=None,
    ) -> None:
        self.client = client
        self.threads = max(1, min(int(threads), 16))
        self.timeout = timeout
        self.limit = max(1, int(limit))
        self.logger = logger or get_logger()

    def lookup(self, ip: str) -> ASNInfo:
        """Resolve metadata for a single IP address."""
        info = ASNInfo(ip=ip)
        if not _is_public_ip(ip):
            info.error = "private or invalid address"
            return info

        payload = self._bgpview(ip)
        if not payload:
            payload = self._ipapi(ip)
        if not payload:
            info.error = "no public ASN source answered"
            return info
        return payload

    def lookup_many(self, ips: Iterable[str]) -> Dict[str, ASNInfo]:
        """Resolve metadata for several IPs using bounded concurrency."""
        unique_ips = list(dict.fromkeys(i for i in ips if i))[: self.limit]
        results: Dict[str, ASNInfo] = {}
        if not unique_ips:
            return results
        with ThreadPoolExecutor(max_workers=self.threads, thread_name_prefix="asn") as pool:
            for ip, info in zip(unique_ips, pool.map(self.lookup, unique_ips)):
                results[ip] = info
        return results

    # -- sources -----------------------------------------------------------
    def _bgpview(self, ip: str) -> Optional[ASNInfo]:
        response = self.client.get(
            BGPVIEW_URL.format(ip=ip),
            timeout=self.timeout,
            allowed_content_types=("application/json", "text/json", "text/plain"),
        )
        data = response.json() if response.ok else None
        if not isinstance(data, dict) or data.get("status") != "ok":
            return None
        payload = data.get("data") or {}
        asn = payload.get("asn") or {}
        prefixes = payload.get("prefixes") or []
        network = prefixes[0].get("prefix") if prefixes else None
        return ASNInfo(
            ip=ip,
            asn=f"AS{asn.get('asn')}" if asn.get("asn") else None,
            organization=asn.get("name") or asn.get("description"),
            country=(asn.get("country_code") or (payload.get("geo") or {}).get("country_code")),
            network=network,
            source="bgpview",
        )

    def _ipapi(self, ip: str) -> Optional[ASNInfo]:
        response = self.client.get(
            IPAPI_URL.format(ip=ip),
            timeout=self.timeout,
            allowed_content_types=("application/json", "text/json", "text/plain"),
        )
        data = response.json() if response.ok else None
        if not isinstance(data, dict) or data.get("status") != "success":
            return None
        return ASNInfo(
            ip=ip,
            asn=data.get("as"),
            organization=data.get("org") or data.get("isp"),
            country=data.get("countryCode"),
            network=None,
            source="ip-api",
        )


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return address.is_global


def enrich_ips(ips: Sequence[str], client: HTTPClient, **kwargs) -> List[ASNInfo]:
    """Convenience wrapper returning a list instead of a mapping."""
    enricher = ASNEnricher(client, **kwargs)
    return list(enricher.lookup_many(ips).values())
