"""AlienVault OTX - public passive DNS (no API key for passive_dns)."""

from __future__ import annotations

from typing import Any, Dict

from ..models import SourceCategory, SourceResult, parse_iso_date
from .base import PassiveSource, SourceUnavailableError

_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"


class OTXSource(PassiveSource):
    """Query AlienVault OTX passive DNS for the target domain."""

    name = "otx"
    description = "AlienVault OTX public passive DNS"
    category = SourceCategory.OSINT.value
    homepage = "https://otx.alienvault.com"
    rate_limit_seconds = 2.0
    timeout = 45
    allowed_content_types = ("application/json", "text/json", "text/plain")

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        payload = self.fetch_json(_URL.format(domain=domain))

        if not isinstance(payload, dict):
            raise SourceUnavailableError("unexpected OTX payload shape")

        records = payload.get("passive_dns") or []
        result.raw_count = len(records)
        for entry in records:
            if not isinstance(entry, dict):
                continue
            candidate = entry.get("hostname") or entry.get("indicator")
            if not candidate:
                continue
            first_seen = parse_iso_date(entry.get("first"))
            last_seen = parse_iso_date(entry.get("last"))
            result.add(str(candidate), first_seen=first_seen, last_seen=last_seen, raw=str(candidate))
            result.add_history(str(candidate), first_seen=first_seen, last_seen=last_seen)

        if not result.observations:  # keep the signature explicit for tests
            result.raw_count = 0
        return result


def _params_probe() -> Dict[str, Any]:  # pragma: no cover - documentation helper
    """Return the (empty) query parameters used by the OTX passive DNS API."""
    return {}
