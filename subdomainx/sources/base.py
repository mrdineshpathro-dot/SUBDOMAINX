"""Source adapter interface (the "source SDK").

Adding a new passive source is deliberately trivial: create a module inside
``subdomainx/sources/`` containing a :class:`PassiveSource` subclass and it is
discovered and registered automatically.  See ``docs/adding-source.md``.

Contract
--------

* One class = one source.
* ``discover(domain)`` returns a :class:`SourceResult`.
* ``discover`` may raise; the base class catches everything and converts it
  into a failed/unavailable/rate-limited :class:`SourceResult`, so a broken
  source can never break a scan.
* Sources must remain passive and unauthenticated.  If a source starts
  requiring a key, set ``requires_api_key = True`` and it is skipped
  automatically.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Sequence

from ..models import SourceCategory, SourceHealth, SourceResult, SourceStatus
from ..utils.http import HTTPClient, HTTPResponse, RateLimiter
from ..utils.logging import get_logger


class SourceError(Exception):
    """Base class for all source adapter failures."""


class RateLimitedError(SourceError):
    """The remote endpoint signalled rate limiting (HTTP 429 / 503)."""


class SourceUnavailableError(SourceError):
    """The source is offline, blocked, or no longer publicly accessible."""


class ParserError(SourceError):
    """The remote payload could not be parsed safely."""


class PassiveSource(ABC):
    """Abstract base class every SUBDOMAINX source implements."""

    # -- metadata (override in subclasses) --------------------------------
    name: str = "unnamed"
    description: str = ""
    category: str = SourceCategory.OTHER.value
    homepage: str = ""
    requires_api_key: bool = False
    enabled_by_default: bool = True

    # -- behaviour ---------------------------------------------------------
    rate_limit_seconds: float = 1.0
    timeout: int = 20
    retries: int = 2
    max_body_size: int = 8_000_000
    allowed_content_types: Optional[Sequence[str]] = None

    def __init__(
        self,
        http: Optional[HTTPClient] = None,
        enabled: bool = True,
        logger: Optional[Any] = None,
    ) -> None:
        self.http = http
        self.enabled = bool(enabled) and self.enabled_by_default and not self.requires_api_key
        self.logger = logger or get_logger()
        self.rate_limiter = RateLimiter(self.rate_limit_seconds)
        self.health = SourceHealth(
            name=self.name,
            category=self.category,
            description=self.description,
            status=SourceStatus.ENABLED if self.enabled else SourceStatus.DISABLED,
        )
        self.last_response: Optional[HTTPResponse] = None

    # -- SDK ---------------------------------------------------------------
    @abstractmethod
    def discover(self, domain: str) -> SourceResult:
        """Query the source and return discovered hostnames.

        Implementations should call :meth:`result.add` / :meth:`add_history`
        for every candidate.  Candidate strings may be raw (URLs, wildcards,
        uppercase, ...) - the normalization pipeline cleans them up.
        """

    # -- optional hooks ----------------------------------------------------
    def is_supported(self) -> bool:
        """Override to signal that the upstream API no longer supports us."""
        return not self.requires_api_key

    def headers(self) -> Dict[str, str]:
        """Extra request headers for this source."""
        return {}

    # -- execution wrapper -------------------------------------------------
    def run(self, domain: str) -> SourceResult:
        """Execute :meth:`discover` with full isolation and health tracking."""
        started = time.monotonic()
        result = SourceResult(source=self.name, domain=domain)

        if self.requires_api_key:
            self.health.status = SourceStatus.UNSUPPORTED
            result.status = SourceStatus.UNSUPPORTED
            result.error = "source requires an API key; skipped (SUBDOMAINX is keyless)"
            return result

        if not self.enabled:
            self.health.status = SourceStatus.DISABLED
            result.status = SourceStatus.DISABLED
            result.error = "disabled by configuration"
            return result

        try:
            if not self.is_supported():
                raise SourceUnavailableError("source reports itself as unsupported")

            result = self.discover(domain)
            if result is None:  # defensive: a broken adapter returning None
                raise ParserError("source returned no result object")
            result.source = self.name
            result.domain = domain
            elapsed = (time.monotonic() - started) * 1000
            result.elapsed_ms = round(elapsed, 2)
            result.raw_count = result.raw_count or len(result.observations)
            result.http_status = getattr(self.last_response, "status_code", None)

            if result.status in (SourceStatus.ENABLED, SourceStatus.ONLINE):
                result.status = SourceStatus.ONLINE
            self.health.record_success(elapsed, result.result_count, result.http_status)
            return result

        except RateLimitedError as exc:
            elapsed = (time.monotonic() - started) * 1000
            self.health.rate_limit_events += 1
            self.health.record_failure(elapsed, str(exc), SourceStatus.RATE_LIMITED)
            result.status = SourceStatus.RATE_LIMITED
            result.error = str(exc)
        except SourceUnavailableError as exc:
            elapsed = (time.monotonic() - started) * 1000
            self.health.record_failure(elapsed, str(exc), SourceStatus.UNAVAILABLE)
            result.status = SourceStatus.UNAVAILABLE
            result.error = str(exc)
        except ParserError as exc:
            elapsed = (time.monotonic() - started) * 1000
            self.health.parser_failures += 1
            self.health.record_failure(elapsed, str(exc), SourceStatus.FAILED)
            result.status = SourceStatus.FAILED
            result.error = f"parser failure: {exc}"
        except Exception as exc:  # noqa: BLE001 - isolation is the whole point
            elapsed = (time.monotonic() - started) * 1000
            self.health.record_failure(elapsed, f"{exc.__class__.__name__}: {exc}", SourceStatus.FAILED)
            result.status = SourceStatus.FAILED
            result.error = f"{exc.__class__.__name__}: {exc}"

        result.elapsed_ms = round((time.monotonic() - started) * 1000, 2)
        result.http_status = getattr(self.last_response, "status_code", None)
        return result

    # -- helpers for subclasses -------------------------------------------
    def _request(self, url: str, **kwargs: Any) -> HTTPResponse:
        """Perform a GET through the shared HTTP client, honouring rate limits."""
        if self.http is None:
            raise SourceUnavailableError("no HTTP client configured")
        self.rate_limiter.wait(self.name)
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("rate_key", self.name)
        kwargs.setdefault("allowed_content_types", self.allowed_content_types)
        kwargs.setdefault("max_body_size", self.max_body_size)
        headers = self.headers()
        if headers:
            merged = dict(kwargs.get("headers") or {})
            merged.update(headers)
            kwargs["headers"] = merged
        response = self.http.get(url, **kwargs)
        self.last_response = response
        return response

    def fetch_text(self, url: str, **kwargs: Any) -> str:
        """GET ``url`` and return the body, or raise a typed source error."""
        response = self._request(url, **kwargs)
        if response.rate_limited:
            raise RateLimitedError(f"HTTP {response.status_code} from {self.name}")
        if response.error and not response.text:
            raise SourceUnavailableError(f"{self.name}: {response.error}")
        if response.status_code >= 400:
            raise SourceUnavailableError(f"HTTP {response.status_code} from {self.name}")
        return response.text or ""

    def fetch_json(self, url: str, **kwargs: Any) -> Any:  # noqa: ANN401
        """GET ``url`` and parse JSON, raising typed errors on any problem."""
        text = self.fetch_text(url, **kwargs)
        try:
            import json

            return json.loads(text)
        except ValueError as exc:
            raise ParserError(f"invalid JSON from {self.name}: {exc}") from exc

    def mark_parser_failure(self, message: str) -> None:
        """Count a parser failure without aborting the source."""
        self.health.parser_failures += 1
        self.logger.warning("Parser warning in %s: %s", self.name, message)

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<{self.__class__.__name__} name={self.name!r} status={self.health.status.value}>"
