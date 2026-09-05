"""Small, dependency-free helpers shared across SUBDOMAINX."""

from __future__ import annotations

import hashlib
import random
import re
import string
import unicodedata
from typing import Any, Iterable, Iterator, List, Optional, Sequence, Set

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")

# Anything that is definitely not a hostname we want to keep.
_LOCAL_NAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
    "local",
}

# Metadata endpoints / link-local addresses are never valid *targets*.
_FORBIDDEN_IPS = {
    "0.0.0.0",
    "127.0.0.1",
    "169.254.169.254",
    "::1",
    "::",
    "fe80::1",
}


def sha256(value: str) -> str:
    """Return the hex SHA-256 digest of ``value``."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def clean_text(value: Optional[str], limit: int = 4096) -> str:
    """Strip control characters, collapse whitespace and truncate."""
    if value is None:
        return ""
    text = unicodedata.normalize("NFKC", str(value))
    text = text.replace("\x00", "")
    text = _CONTROL_CHARS.sub(" ", text)
    text = _WHITESPACE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return text


def collapse_whitespace(value: Optional[str]) -> str:
    """Collapse all whitespace runs into single spaces."""
    return _WHITESPACE.sub(" ", value or "").strip()


def random_label(length: int = 12) -> str:
    """Generate a random DNS-safe label used for wildcard probing."""
    alphabet = string.ascii_lowercase + string.digits
    first = random.choice(string.ascii_lowercase)
    return first + "".join(random.choice(alphabet) for _ in range(max(1, length - 1)))


def random_hostnames(domain: str, count: int = 3) -> List[str]:
    """Return ``count`` random, highly unlikely hostnames under ``domain``."""
    return [f"{random_label()}-{random_label(6)}.{domain.lstrip('.')}" for _ in range(max(1, count))]


def chunked(items: Sequence[Any], size: int) -> Iterator[Sequence[Any]]:
    """Yield successive ``size``-sized chunks from ``items``."""
    size = max(1, int(size))
    for i in range(0, len(items), size):
        yield items[i : i + size]


def unique(iterable: Iterable[Any]) -> List[Any]:
    """Order preserving de-duplication."""
    seen: Set[Any] = set()
    out: List[Any] = []
    for item in iterable:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def safe_int(value: Any, default: int = 0) -> int:  # noqa: ANN401
    """Best effort int conversion that never raises."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:  # noqa: ANN401
    """Best effort float conversion that never raises."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def humanize_count(value: int) -> str:
    """Render large counters compactly (e.g. ``1.2k``)."""
    if value < 1000:
        return str(value)
    if value < 1_000_000:
        return f"{value / 1000:.1f}k"
    return f"{value / 1_000_000:.1f}M"


def truncate(value: Optional[str], width: int) -> str:
    """Truncate a string to ``width`` characters with an ellipsis."""
    text = str(value or "")
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "…"


def is_local_name(host: str) -> bool:
    """True for localhost-style names that must never become targets."""
    return host.lower().strip(".") in _LOCAL_NAMES


def is_forbidden_ip(ip: str) -> bool:
    """True for loopback / link-local / metadata addresses."""
    return ip.lower().strip() in _FORBIDDEN_IPS


def dict_merge(a: dict, b: dict) -> dict:
    """Shallow merge returning a new dict (``b`` wins)."""
    merged = dict(a or {})
    merged.update(b or {})
    return merged


def ensure_scheme(url: str, scheme: str = "https") -> str:
    """Prefix ``url`` with ``scheme`` when it has none."""
    if "://" in url:
        return url
    return f"{scheme}://{url.lstrip('/')}"
