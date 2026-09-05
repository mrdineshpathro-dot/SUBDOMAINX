"""Wayback Machine (Internet Archive CDX API) - historical URL observations."""

from __future__ import annotations

from typing import Any, Dict, List

from ..models import SourceCategory, SourceResult, parse_iso_date
from .base import ParserError, PassiveSource, SourceUnavailableError

_CDX = "https://web.archive.org/cdx/search/cdx"


class WaybackSource(PassiveSource):
    """Query the Internet Archive CDX API for archived hostnames.

    This is the primary historical source: it tells us when a hostname was
    *first* and *last* seen on the public web.
    """

    name = "wayback"
    description = "Internet Archive CDX historical URL index"
    category = SourceCategory.ARCHIVE.value
    homepage = "https://archive.org"
    rate_limit_seconds = 1.0
    timeout = 60
    allowed_content_types = ("application/json", "text/plain", "text/x-ndjson")
    max_body_size = 24_000_000

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        params: Dict[str, Any] = {
            "url": f"*.{domain}",
            "output": "json",
            "fl": "original,timestamp,statuscode",
            "collapse": "urlkey",
            "filter": "statuscode:200",
            "limit": 20000,
        }
        try:
            payload = self.fetch_json(_CDX, params=params, timeout=self.timeout)
        except ParserError as exc:
            raise SourceUnavailableError(f"wayback CDX parse failure: {exc}") from exc

        if not isinstance(payload, list) or len(payload) < 2:
            raise SourceUnavailableError("wayback CDX returned no rows")

        rows: List[List[Any]] = [row for row in payload[1:] if isinstance(row, list) and row]
        result.raw_count = len(rows)
        for row in rows:
            original = str(row[0]) if len(row) > 0 else ""
            timestamp = str(row[1]) if len(row) > 1 else ""
            if not original:
                continue
            seen = parse_iso_date(timestamp)
            result.add(original, first_seen=seen, last_seen=seen, raw=original)
            result.add_history(original, first_seen=seen, last_seen=seen, currently_observed=True)
        return result
