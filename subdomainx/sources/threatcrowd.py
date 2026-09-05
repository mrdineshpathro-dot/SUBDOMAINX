"""ThreatCrowd - community OSINT API.

ThreatCrowd has been intermittently unavailable for years.  The adapter is kept
because the endpoint is public and keyless, but it degrades to ``UNAVAILABLE``
whenever the service does not answer - SUBDOMAINX never pretends otherwise.
"""

from __future__ import annotations

from typing import Any, Dict

from ..models import SourceCategory, SourceResult
from .base import PassiveSource, SourceUnavailableError

_URL = "https://threatcrowd.org/searchApi/v2/domain/report/"


class ThreatCrowdSource(PassiveSource):
    """Query the ThreatCrowd domain report API."""

    name = "threatcrowd"
    description = "ThreatCrowd community OSINT API (often offline)"
    category = SourceCategory.OSINT.value
    homepage = "https://www.threatcrowd.org"
    rate_limit_seconds = 3.0
    timeout = 30
    allowed_content_types = ("application/json", "text/json", "text/plain")

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        params: Dict[str, Any] = {"domain": domain}
        payload = self.fetch_json(_URL, params=params)

        if not isinstance(payload, dict):
            raise SourceUnavailableError("unexpected ThreatCrowd payload shape")
        if str(payload.get("response_code", "1")) not in {"1", "0"}:
            raise SourceUnavailableError("ThreatCrowd reported an error")

        records = payload.get("subdomains") or []
        result.raw_count = len(records)
        for entry in records:
            if isinstance(entry, str):
                result.add(entry, raw=entry)
        return result
