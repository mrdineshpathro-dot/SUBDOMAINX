"""Anubis (jldc.me) - public subdomain dataset.

Like several community services this endpoint is frequently offline.  When it
does not answer with the documented JSON payload the source is reported as
``UNAVAILABLE``.
"""

from __future__ import annotations

from typing import Any, List

from ..models import SourceCategory, SourceResult
from .base import ParserError, PassiveSource, SourceUnavailableError

_URL = "https://jldc.me/anubis/subdomains/{domain}"


class AnubisSource(PassiveSource):
    """Query the public Anubis subdomain dataset."""

    name = "anubis"
    description = "Anubis (jldc.me) public subdomain dataset"
    category = SourceCategory.OSINT.value
    homepage = "https://jldc.me"
    rate_limit_seconds = 2.0
    timeout = 30
    allowed_content_types = ("application/json", "text/json", "text/plain")

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        try:
            payload = self.fetch_json(_URL.format(domain=domain))
        except ParserError as exc:
            raise SourceUnavailableError(f"anubis unavailable: {exc}") from exc

        names: List[Any] = []
        if isinstance(payload, list):
            names = payload
        elif isinstance(payload, dict):
            names = payload.get("subdomains") or payload.get("domains") or []
        else:
            raise SourceUnavailableError("unexpected anubis payload shape")

        result.raw_count = len(names)
        for entry in names:
            if isinstance(entry, str):
                result.add(entry, raw=entry)
            elif isinstance(entry, dict):
                candidate = entry.get("hostname") or entry.get("domain")
                if candidate:
                    result.add(str(candidate), raw=str(candidate))
        return result
