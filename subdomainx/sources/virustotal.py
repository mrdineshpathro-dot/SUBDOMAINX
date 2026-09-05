"""VirusTotal - *requires an API key*, therefore disabled in SUBDOMAINX.

This adapter exists to document and exercise the "source became authenticated"
path: because :attr:`PassiveSource.requires_api_key` is ``True`` the registry
never runs it and the source-health dashboard reports ``UNSUPPORTED``.

SUBDOMAINX is a keyless tool; it will not silently degrade into a
credential-requiring design.
"""

from __future__ import annotations

from typing import Any, Dict

from ..models import SourceCategory, SourceResult
from .base import PassiveSource


class VirusTotalSource(PassiveSource):
    """VirusTotal subdomain enumeration (API key required - not used)."""

    name = "virustotal"
    description = "VirusTotal domain report (API key required - disabled)"
    category = SourceCategory.OSINT.value
    homepage = "https://www.virustotal.com"
    requires_api_key = True

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        result.status = result.status.__class__.UNSUPPORTED
        result.error = "VirusTotal requires an API key; SUBDOMAINX is keyless"
        return result

    def headers(self) -> Dict[str, Any]:  # pragma: no cover - never executed
        return {}
