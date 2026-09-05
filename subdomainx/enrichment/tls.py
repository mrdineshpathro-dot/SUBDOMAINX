"""Lightweight TLS certificate metadata.

Used purely for asset correlation (issuer, validity window, SANs).  No cipher
downgrade, no vulnerability probing and no offensive testing is performed.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models import TLSInfo

_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def fetch_certificate_dict(host: str, port: int = 443, timeout: float = 6.0) -> Optional[Dict[str, Any]]:
    """Return the raw peer certificate dictionary for ``host:port``."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                if isinstance(cert, dict):
                    cert = dict(cert)
                    cert["_tls_version"] = tls_sock.version()
                return cert
    except Exception:  # noqa: BLE001 - TLS enrichment is optional and best effort
        return None


def fetch_tls(host: str, port: int = 443, timeout: float = 6.0) -> Optional[TLSInfo]:
    """Collect TLS metadata for ``host``; returns ``None`` when unavailable."""
    raw = fetch_certificate_dict(host, port, timeout)
    if not raw:
        return None
    return parse_certificate(host, raw)


def parse_certificate(host: str, cert: Dict[str, Any]) -> TLSInfo:
    """Convert an ``SSLSocket.getpeercert()`` dict into a :class:`TLSInfo`."""
    sans: List[str] = []
    for kind, value in cert.get("subjectAltName", []) or []:
        if kind.lower() == "dns":
            sans.append(str(value).lower().strip())
    common_name = _rdn_value(cert.get("subject"), "commonName")
    if common_name and common_name.lower() not in sans:
        sans.append(common_name.lower())

    info = TLSInfo(
        host=host,
        subject=common_name,
        issuer=_rdn_value(cert.get("issuer"), "commonName")
        or _rdn_value(cert.get("issuer"), "organizationName"),
        valid_from=_parse_cert_date(cert.get("notBefore")),
        valid_until=_parse_cert_date(cert.get("notAfter")),
        sans=sorted(set(sans)),
        serial_number=str(cert.get("serialNumber")) if cert.get("serialNumber") else None,
        tls_version=cert.get("_tls_version"),
        valid=True,
    )
    return info


def _rdn_value(rdn: Any, key: str) -> Optional[str]:  # noqa: ANN401
    """Extract a value from a getpeercert subject/issuer structure."""
    if not rdn:
        return None
    try:
        for group in rdn:
            for name, value in group:
                if name.lower() == key.lower():
                    return str(value)
    except (TypeError, ValueError):
        return None
    return None


def _parse_cert_date(value: Optional[str]) -> Optional[str]:
    """Convert ``Jun  1 12:00:00 2024 GMT`` into ``2024-06-01``."""
    if not value:
        return None
    try:
        return datetime.strptime(str(value), _CERT_DATE_FORMAT).date().isoformat()
    except ValueError:
        return str(value)[:10] or None


def certificate_matches_host(info: Optional[TLSInfo], host: str) -> bool:
    """True when the certificate covers ``host`` (exact or wildcard SAN)."""
    if not info:
        return False
    host = (host or "").lower().strip(".")
    for san in info.sans:
        san = san.lower().strip(".")
        if san == host:
            return True
        if san.startswith("*.") and host.endswith(san[2:]):
            return True
    return False
