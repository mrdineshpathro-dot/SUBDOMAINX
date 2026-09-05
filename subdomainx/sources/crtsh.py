"""crt.sh - public Certificate Transparency log search (no API key)."""

from __future__ import annotations

import json
from typing import Any, List

from ..models import SourceCategory, SourceResult, parse_iso_date
from .base import ParserError, PassiveSource, SourceUnavailableError


class CrtShSource(PassiveSource):
    """Query the public crt.sh certificate search interface."""

    name = "crtsh"
    description = "Certificate Transparency log search (crt.sh)"
    category = SourceCategory.CERTIFICATE.value
    homepage = "https://crt.sh"
    rate_limit_seconds = 1.5
    timeout = 45
    allowed_content_types = ("application/json", "text/json", "text/plain", "text/html")

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        url = "https://crt.sh/"
        params = {"q": f"%.{domain}", "output": "json"}
        body = self.fetch_text(url, params=params)

        if not body.strip():
            raise SourceUnavailableError("empty response from crt.sh")

        try:
            payload: Any = json.loads(body)
        except ValueError as exc:
            raise ParserError(f"crt.sh returned non-JSON output: {exc}") from exc

        if not isinstance(payload, list):
            if isinstance(payload, dict) and payload.get("error"):
                raise SourceUnavailableError(f"crt.sh error: {payload['error']}")
            raise ParserError("unexpected crt.sh payload shape")

        result.raw_count = len(payload)
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            names: List[str] = []
            name_value = entry.get("name_value") or ""
            if name_value:
                names.extend(str(name_value).splitlines())
            common_name = entry.get("common_name")
            if common_name:
                names.append(str(common_name))

            first_seen = parse_iso_date(entry.get("not_before"))
            last_seen = parse_iso_date(entry.get("entry_timestamp")) or first_seen

            for candidate in names:
                cleaned = candidate.strip()
                if not cleaned:
                    continue
                result.add(cleaned, first_seen=first_seen, last_seen=last_seen, raw=cleaned)
                result.add_history(
                    cleaned,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    currently_observed=True,
                )
        return result
