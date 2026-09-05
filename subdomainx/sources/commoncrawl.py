"""Common Crawl - public URL index (columnar index, no API key)."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..models import SourceCategory, SourceResult
from .base import ParserError, PassiveSource, SourceUnavailableError

_COLLINFO = "https://index.commoncrawl.org/collinfo.json"


class CommonCrawlSource(PassiveSource):
    """Query the newest public Common Crawl URL index for a domain."""

    name = "commoncrawl"
    description = "Common Crawl public URL index"
    category = SourceCategory.ARCHIVE.value
    homepage = "https://commoncrawl.org"
    rate_limit_seconds = 1.0
    timeout = 60
    allowed_content_types = ("application/json", "text/plain", "text/x-ndjson")
    max_body_size = 24_000_000

    #: How many index collections to try before giving up.
    max_collections = 2

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        collections = self._collections()
        if not collections:
            raise SourceUnavailableError("no Common Crawl index collections available")

        for collection in collections[: self.max_collections]:
            index_url = f"https://index.commoncrawl.org/{collection}-index"
            params: Dict[str, Any] = {
                "url": f"*.{domain}/*",
                "output": "json",
            }
            body = self.fetch_text(index_url, params=params, timeout=self.timeout)
            if not body.strip():
                continue
            parsed = 0
            for line in body.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record: Any = json.loads(line)
                except ValueError:
                    self.mark_parser_failure("non-JSON line in Common Crawl index")
                    continue
                if not isinstance(record, dict):
                    continue
                url = record.get("url")
                if not url:
                    continue
                parsed += 1
                result.add(str(url), raw=str(url))
            if parsed:
                result.raw_count = parsed
                return result

        if not result.observations:
            raise SourceUnavailableError("Common Crawl index returned no records")
        return result

    def _collections(self) -> List[str]:
        """Return the identifiers of the newest Common Crawl index collections."""
        try:
            payload = self.fetch_json(_COLLINFO, timeout=30)
        except ParserError:
            return []
        if not isinstance(payload, list):
            return []
        ids: List[str] = []
        for entry in payload:
            if isinstance(entry, dict) and entry.get("id"):
                ids.append(str(entry["id"]))
        return ids
