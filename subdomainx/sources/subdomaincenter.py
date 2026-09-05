"""Subdomain Center - public, keyless subdomain API."""

from __future__ import annotations

from typing import Any

from ..models import SourceCategory, SourceResult
from .base import ParserError, PassiveSource, SourceUnavailableError

_URL = "https://api.subdomain.center/"


class SubdomainCenterSource(PassiveSource):
    """Query the public ``api.subdomain.center`` endpoint."""

    name = "subdomaincenter"
    description = "Subdomain Center public certificate/DNS dataset"
    category = SourceCategory.OSINT.value
    homepage = "https://www.subdomain.center"
    rate_limit_seconds = 2.0
    timeout = 30
    allowed_content_types = ("application/json", "text/json", "text/plain")

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        try:
            payload = self.fetch_json(_URL, params={"domain": domain})
        except ParserError as exc:
            raise SourceUnavailableError(f"subdomain.center unavailable: {exc}") from exc

        names: Any = []
        if isinstance(payload, list):
            names = payload
        elif isinstance(payload, dict):
            names = payload.get("subdomains") or payload.get("domains") or []
        else:
            raise SourceUnavailableError("unexpected subdomain.center payload shape")

        result.raw_count = len(names)
        for entry in names:
            if isinstance(entry, str):
                result.add(entry, raw=entry)
        return result
