"""SecurityTrails - *requires an API key*, therefore disabled in SUBDOMAINX.

Kept as a documented example of a source that moved behind authentication.  It
is registered but never executed: :meth:`PassiveSource.run` short-circuits with
``UNSUPPORTED``.
"""

from __future__ import annotations

from ..models import SourceCategory, SourceResult
from .base import PassiveSource


class SecurityTrailsSource(PassiveSource):
    """SecurityTrails subdomain API (API key required - disabled)."""

    name = "securitytrails"
    description = "SecurityTrails subdomain API (API key required - disabled)"
    category = SourceCategory.DNS.value
    homepage = "https://securitytrails.com"
    requires_api_key = True

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        result.error = "SecurityTrails requires an API key; SUBDOMAINX is keyless"
        return result
