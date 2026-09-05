"""ThreatMiner - public passive DNS / subdomain API (no API key)."""

from __future__ import annotations

from typing import Any, Dict

from ..models import SourceCategory, SourceResult
from .base import PassiveSource, SourceUnavailableError

_URL = "https://api.threatminer.org/v2/domain.php"


class ThreatMinerSource(PassiveSource):
    """Query ThreatMiner's public domain report (subdomain resource type 5)."""

    name = "threatminer"
    description = "ThreatMiner public passive DNS API"
    category = SourceCategory.OSINT.value
    homepage = "https://www.threatminer.org"
    rate_limit_seconds = 2.0
    timeout = 30
    allowed_content_types = ("application/json", "text/json", "text/plain")

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        params: Dict[str, Any] = {"q": domain, "rt": 5}
        payload = self.fetch_json(_URL, params=params)

        if not isinstance(payload, dict):
            raise SourceUnavailableError("unexpected ThreatMiner payload shape")
        status = str(payload.get("status_code", "200"))
        if status not in {"200", "0"}:
            raise SourceUnavailableError(f"ThreatMiner status: {payload.get('status_message', status)}")

        records = payload.get("results") or []
        result.raw_count = len(records)
        for entry in records:
            if isinstance(entry, str):
                result.add(entry, raw=entry)
            elif isinstance(entry, dict):
                candidate = entry.get("domain") or entry.get("hostname")
                if candidate:
                    result.add(str(candidate), raw=str(candidate))
        return result
