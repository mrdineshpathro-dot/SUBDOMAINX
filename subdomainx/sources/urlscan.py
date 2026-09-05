"""URLScan.io - public search API for observed URLs (no API key required)."""

from __future__ import annotations

from typing import Any, Dict

from ..models import SourceCategory, SourceResult, parse_iso_date
from .base import PassiveSource, SourceUnavailableError

_SEARCH = "https://urlscan.io/api/v1/search/"


class URLScanSource(PassiveSource):
    """Query the public URLScan.io search endpoint."""

    name = "urlscan"
    description = "URLScan.io public URL observations"
    category = SourceCategory.WEB.value
    homepage = "https://urlscan.io"
    rate_limit_seconds = 2.0
    timeout = 30
    allowed_content_types = ("application/json", "text/json", "text/plain")

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        params: Dict[str, Any] = {
            "q": f"domain:{domain}",
            "size": 10000,
        }
        payload = self.fetch_json(_SEARCH, params=params)

        if not isinstance(payload, dict):
            raise SourceUnavailableError("unexpected urlscan payload shape")
        if payload.get("status") == 429 or payload.get("message", "").lower().startswith("rate"):
            raise SourceUnavailableError("urlscan rate limited the request")

        results = payload.get("results") or []
        result.raw_count = len(results)
        for entry in results:
            if not isinstance(entry, dict):
                continue
            page = entry.get("page") or {}
            task = entry.get("task") or {}
            candidate = page.get("domain") or page.get("hostname") or page.get("url")
            if not candidate:
                continue
            if "://" in str(candidate):
                candidate = str(candidate).split("://", 1)[1].split("/")[0]
            seen = parse_iso_date(task.get("time"))
            result.add(str(candidate), first_seen=seen, last_seen=seen, raw=str(candidate))
            result.add_history(str(candidate), first_seen=seen, last_seen=seen)
        return result
