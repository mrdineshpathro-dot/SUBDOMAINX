"""Hostname normalization pipeline.

Every string that arrives from a remote source is treated as untrusted input.
The pipeline turns a wide variety of shapes (URLs, ports, wildcard notation,
uppercase, percent encoding, IDN, trailing dots, ...) into a single canonical
hostname, or rejects it.

Examples
--------
``HTTPS://API.Example.com:443/``  ->  ``api.example.com``
``*.API.Example.com.``            ->  ``api.example.com``
``http://api.example.com/path``   ->  ``api.example.com``
``javascript:alert(1)``           ->  rejected
``169.254.169.254``               ->  rejected
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import List, Optional, Tuple
from urllib.parse import unquote, urlparse

from ..utils.helpers import clean_text, is_forbidden_ip, is_local_name

# Schemes we accept in raw source output.  Anything else (`javascript:`, `data:`,
# `file:`, `ftp:`, ...) is discarded because it can never describe a host.
ALLOWED_SCHEMES = {"http", "https"}

# Characters frequently wrapped around hostnames in scraped output.
_WRAPPERS = "\"'`‘’“”<>()[]{},;|\\\t\r\n"

# ``host:port`` where the port is numeric.
_PORT_RE = re.compile(r"^(?P<host>.+?):(?P<port>\d{1,5})$")

# A bracketed IPv6 literal, optionally carrying a port.
_IPV6_RE = re.compile(r"^\[(?P<addr>[0-9A-Fa-f:.]+)\](?::\d{1,5})?$")

# Valid (IDNA encoded) hostname.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")

MAX_HOSTNAME_LENGTH = 253


def normalize_host(value: object) -> Optional[str]:
    """Normalise ``value`` to a canonical hostname, or return ``None``.

    The function never raises.  Anything that cannot be turned into a plausible
    public hostname is rejected.
    """
    host, _notes = normalize_detailed(value)
    return host


def normalize_detailed(value: object) -> Tuple[Optional[str], List[str]]:
    """Like :func:`normalize_host` but also returns a list of notes."""
    notes: List[str] = []
    if value is None:
        return None, notes
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return None, notes
    if not isinstance(value, str):
        return None, notes

    text = value.strip()
    if not text:
        return None, notes

    # 1. Unicode normalisation + control character removal.
    text = clean_text(text, limit=2048)
    if not text:
        return None, notes
    if len(text) > 2048:
        notes.append("input too long")

    # 2. Strip wrapper characters.
    text = text.strip(_WRAPPERS)
    if not text:
        return None, notes

    # 3. Percent decoding (bounded: at most two rounds).
    for _ in range(2):
        if "%" not in text:
            break
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded.strip()
        notes.append("percent-decoded")

    text = text.strip().strip(_WRAPPERS)

    # 4. Scheme handling.
    lowered = text.lower()
    if "://" in lowered:
        scheme = lowered.split("://", 1)[0]
        if scheme not in ALLOWED_SCHEMES:
            notes.append(f"rejected scheme: {scheme}")
            return None, notes
        parsed = urlparse(text)
        candidate = parsed.hostname or ""
        if parsed.username or parsed.password:
            notes.append("stripped userinfo")
        if parsed.port:
            notes.append("stripped port")
    else:
        if re.match(r"^[a-z][a-z0-9+.\-]*:", lowered) and not _PORT_RE.match(text):
            # An explicit non-HTTP scheme (`mailto:`, `javascript:`, `data:`...).
            scheme = lowered.split(":", 1)[0]
            if scheme not in ALLOWED_SCHEMES:
                notes.append(f"rejected scheme: {scheme}")
                return None, notes
        # Protocol relative URLs ("//cdn.example.com/x").
        if text.startswith("//"):
            text = text[2:]
            notes.append("stripped protocol-relative prefix")
        # Drop path / query / fragment.
        text = text.split("#", 1)[0].split("?", 1)[0]
        if "/" in text:
            text = text.split("/", 1)[0]
        # Strip a trailing numeric port.
        match = _PORT_RE.match(text)
        if match:
            text = match.group("host")
            notes.append("stripped port")
        candidate = text

    candidate = candidate.strip().strip(_WRAPPERS)
    if not candidate:
        return None, notes

    # 5. Reject bare IP literals (IPv4 / IPv6).  They are metadata, not targets.
    if _IPV6_RE.match(candidate):
        addr = _IPV6_RE.match(candidate).group("addr")  # type: ignore[union-attr]
        candidate = addr
    try:
        ipaddress.ip_address(candidate)
        notes.append("rejected IP literal")
        return None, notes
    except ValueError:
        pass

    # 6. Whitespace inside the value means it was never a hostname.
    if any(ch.isspace() for ch in candidate):
        notes.append("rejected embedded whitespace")
        return None, notes

    # 7. Structural cleanup: wildcards, dots, case.
    candidate = candidate.rstrip(".").lstrip(".")
    while True:
        original = candidate
        candidate = candidate.replace("..", ".")
        candidate = candidate.lstrip(".").rstrip(".")
        if candidate == original:
            break
    # Wildcard notation (`*.example.com`, `*.a.example.com`, `*.*.example.com`).
    if "*" in candidate:
        notes.append("stripped wildcard notation")
        candidate = re.sub(r"\*\.?", "", candidate)
        candidate = candidate.replace("..", ".").strip(".")
    if "\\" in candidate:
        notes.append("rejected backslash in hostname")
        return None, notes
    candidate = candidate.split("/")[0].split("?")[0].split("#")[0]

    if not candidate:
        return None, notes

    # 8. IDNA handling and lowercasing.
    candidate = unicodedata.normalize("NFKC", candidate)
    candidate = _idna_encode(candidate)
    if candidate is None:
        notes.append("rejected invalid IDN")
        return None
    candidate = candidate.lower()

    # 9. Final syntax validation.
    if len(candidate) > MAX_HOSTNAME_LENGTH:
        notes.append("hostname too long")
        return None, notes
    if not _HOSTNAME_RE.match(candidate):
        notes.append("rejected invalid hostname syntax")
        return None, notes
    if is_local_name(candidate):
        notes.append("rejected local name")
        return None, notes
    if candidate in {"127.0.0.1", "169.254.169.254"}:
        notes.append("rejected reserved address")
        return None, notes
    if is_forbidden_ip(candidate):
        notes.append("rejected reserved address")
        return None, notes
    if candidate.split(".")[-1].isdigit():
        notes.append("rejected numeric TLD")
        return None, notes
    if "." not in candidate:
        notes.append("rejected single label name")
        return None, notes
    for label in candidate.split("."):
        if len(label) > 63:
            notes.append("label too long")
            return None, notes
        if label.startswith("-") or label.endswith("-"):
            notes.append("invalid label hyphenation")
            return None, notes
        if not label:
            notes.append("empty label")
            return None, notes

    return candidate, notes


def normalize_many(values) -> List[str]:  # noqa: ANN001
    """Normalise an iterable of raw strings, dropping duplicates and rejects."""
    seen = set()
    out: List[str] = []
    for value in values or []:
        host = normalize_host(value)
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def _idna_encode(host: str) -> Optional[str]:
    """Convert an internationalised hostname into its ASCII (punycode) form.

    Returns ``None`` when the name cannot be encoded safely.
    """
    try:
        host.encode("ascii")
        return host
    except UnicodeEncodeError:
        pass

    labels: List[str] = []
    for label in host.split("."):
        if not label:
            return None
        try:
            import idna  # type: ignore

            labels.append(idna.encode(label, uts46=True).decode("ascii"))
            continue
        except Exception:  # noqa: BLE001 - fall through to the stdlib codec
            pass
        try:
            encoded = label.encode("idna").decode("ascii")
        except Exception:  # noqa: BLE001
            return None
        if not encoded:
            return None
        labels.append(encoded)
    return ".".join(labels)


def is_ip(value: str) -> bool:
    """True when ``value`` is a literal IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False
