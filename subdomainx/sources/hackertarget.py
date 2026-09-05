"""HackerTarget - free host search API (no API key, rate limited)."""

from __future__ import annotations

from ..models import SourceCategory, SourceResult
from .base import PassiveSource, SourceUnavailableError

# Human readable errors returned by the public endpoint.
_KNOWN_ERRORS = (
    "error check your search parameter",
    "api count exceeded",
    "invalid request",
    "no records found",
    "error",
)


class HackerTargetSource(PassiveSource):
    """Query HackerTarget's public ``hostsearch`` endpoint."""

    name = "hackertarget"
    description = "HackerTarget public host search (passive DNS)"
    category = SourceCategory.DNS.value
    homepage = "https://hackertarget.com"
    rate_limit_seconds = 2.0
    timeout = 25
    allowed_content_types = ("text/plain", "text/html", "application/octet-stream")

    URL = "https://api.hackertarget.com/hostsearch/"

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        body = self.fetch_text(self.URL, params={"q": domain})

        lines = [line.strip() for line in body.splitlines() if line.strip()]
        if not lines:
            raise SourceUnavailableError("empty response from hackertarget")

        lowered = body.lower()
        if any(err in lowered for err in _KNOWN_ERRORS):
            raise SourceUnavailableError(f"hackertarget: {lines[0][:120]}")

        result.raw_count = len(lines)
        for line in lines:
            # Format:  hostname,ip  (ip may be missing)
            host = line.split(",", 1)[0].strip()
            if host:
                result.add(host, raw=line)
        return result
