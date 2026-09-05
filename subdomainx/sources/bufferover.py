"""BufferOver.run - public passive DNS dataset.

Note: this service has been intermittent historically.  When it is unreachable
the adapter reports ``UNAVAILABLE`` and the scan continues with other sources.
"""

from __future__ import annotations

from typing import Any, Dict

from ..models import SourceCategory, SourceResult
from .base import PassiveSource, SourceUnavailableError

_URL = "https://dns.bufferover.run/dns"


class BufferOverSource(PassiveSource):
    """Query the public BufferOver.run passive DNS API."""

    name = "bufferover"
    description = "BufferOver.run public passive DNS dataset"
    category = SourceCategory.DNS.value
    homepage = "https://bufferover.run"
    rate_limit_seconds = 2.0
    timeout = 30
    allowed_content_types = ("application/json", "text/json", "text/plain")

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        params: Dict[str, Any] = {"q": f".{domain}"}
        payload = self.fetch_json(_URL, params=params)

        if not isinstance(payload, dict):
            raise SourceUnavailableError("unexpected bufferover payload shape")
        if payload.get("Error"):
            raise SourceUnavailableError(f"bufferover: {payload['Error']}")

        records = []
        for key in ("FDNS_A", "RDNS", "FDNS_A_Response", "RDNS_Response"):
            values = payload.get(key)
            if isinstance(values, list):
                records.extend(str(v) for v in values if v)

        result.raw_count = len(records)
        for record in records:
            # Records look like "1.2.3.4,api.example.com" or "api.example.com,1.2.3.4".
            parts = [part.strip() for part in record.split(",") if part.strip()]
            for part in parts:
                if "." in part and not part.replace(".", "").isdigit():
                    result.add(part, raw=record)
        return result
