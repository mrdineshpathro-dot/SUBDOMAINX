"""Cert Spotter - public certificate issuance API (no API key for basic use)."""

from __future__ import annotations

from typing import Any, Dict, List

from ..models import SourceCategory, SourceResult, parse_iso_date
from .base import PassiveSource, SourceUnavailableError


class CertSpotterSource(PassiveSource):
    """Query the Cert Spotter public issuance API."""

    name = "certspotter"
    description = "SSLMate Cert Spotter public CT issuance API"
    category = SourceCategory.CERTIFICATE.value
    homepage = "https://sslmate.com/certspotter"
    rate_limit_seconds = 2.0
    timeout = 30
    allowed_content_types = ("application/json", "text/json", "text/plain")

    # The public endpoint only exposes issuances for hosts the caller can prove
    # control over; we therefore fall back to the documented public search form.
    SEARCH_URL = "https://api.certspotter.com/v1/issuances"

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        params: Dict[str, Any] = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
        payload = self.fetch_json(self.SEARCH_URL, params=params)

        if isinstance(payload, dict) and payload.get("error"):
            raise SourceUnavailableError(f"certspotter error: {payload['error']}")
        if not isinstance(payload, list):
            raise SourceUnavailableError("unexpected certspotter payload shape")

        result.raw_count = len(payload)
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            names: List[str] = []
            for key in ("dns_names", "domains"):
                values = entry.get(key)
                if isinstance(values, list):
                    names.extend(str(v) for v in values if v)
            first_seen = parse_iso_date(entry.get("not_before"))
            last_seen = parse_iso_date(entry.get("not_after"))
            for candidate in names:
                result.add(candidate, first_seen=first_seen, last_seen=last_seen, raw=candidate)
                result.add_history(candidate, first_seen=first_seen, last_seen=last_seen)
        return result
