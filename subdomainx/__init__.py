"""SUBDOMAINX - Passive Subdomain Discovery & Asset Intelligence Aggregator.

SUBDOMAINX performs *passive* reconnaissance only.  It never brute-forces
names, never attempts to bypass authentication, CAPTCHAs, WAFs or rate limits,
and never exploits anything.  Every source adapter is strictly read-only and
uses publicly accessible, unauthenticated endpoints.

Design guarantees:

* No API keys, no credentials, no paid services.
* Every source is isolated: a failing source never aborts the scan.
* Every result carries provenance (which source saw it, and when).
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "SUBDOMAINX contributors"
__license__ = "MIT"

__all__ = ["__version__", "__author__", "__license__"]
