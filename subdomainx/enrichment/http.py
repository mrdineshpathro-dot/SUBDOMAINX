"""HTTP probe engine.

Collects only lightweight, passive metadata: status code, redirect chain,
title, server header, content type, size, timing and (optionally) TLS data.
No exploit, no fuzzing, no authentication attempts.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from ..models import HTTPCategory, HTTPObservation
from ..utils.helpers import collapse_whitespace
from ..utils.http import HTTPClient
from ..utils.logging import get_logger

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_MAX_TITLE = 200


@dataclass
class HTTPProbeOptions:
    """Configuration for :class:`HTTPProber`."""

    timeout: float = 8.0
    threads: int = 10
    max_body_size: int = 262_144
    verify_tls: bool = True
    https_first: bool = True
    fallback_http: bool = True
    capture_tls: bool = False
    collect_headers: bool = True


def classify_status(status: Optional[int], error: Optional[str] = None) -> HTTPCategory:
    """Map a status code (or transport error) onto an :class:`HTTPCategory`."""
    if error:
        lowered = error.lower()
        if "tls" in lowered or "ssl" in lowered:
            return HTTPCategory.TLS_ERROR
        if "timed out" in lowered or "timeout" in lowered or "read timed" in lowered:
            return HTTPCategory.TIMEOUT
        if "name or service not known" in lowered or "nodename" in lowered or "dns" in lowered:
            return HTTPCategory.DNS_FAILURE
        return HTTPCategory.UNKNOWN
    if status is None:
        return HTTPCategory.UNKNOWN
    if 200 <= status < 300:
        return HTTPCategory.LIVE
    if 300 <= status < 400:
        return HTTPCategory.REDIRECT
    if status in (401, 403):
        return HTTPCategory.FORBIDDEN
    if status == 404 or status == 410:
        return HTTPCategory.NOT_FOUND
    if 400 <= status < 500:
        return HTTPCategory.NOT_FOUND
    if status >= 500:
        return HTTPCategory.SERVER_ERROR
    return HTTPCategory.UNKNOWN


def extract_title(body: str) -> Optional[str]:
    """Extract and normalise the HTML ``<title>`` (never raises)."""
    if not body:
        return None
    match = _TITLE_RE.search(body)
    if not match:
        return None
    raw = match.group(1)
    try:
        from bs4 import BeautifulSoup  # type: ignore

        text = BeautifulSoup(raw, "html.parser").get_text(" ", strip=True)
    except Exception:  # noqa: BLE001 - bs4 is optional; fall back to regex
        text = _TAG_RE.sub(" ", raw)
    text = collapse_whitespace(text)
    if not text:
        return None
    return text[:_MAX_TITLE]


class HTTPProber:
    """Probe hosts over HTTPS (with HTTP fallback) using bounded concurrency."""

    def __init__(
        self,
        client: HTTPClient,
        options: Optional[HTTPProbeOptions] = None,
        logger=None,
    ) -> None:
        self.client = client
        self.options = options or HTTPProbeOptions()
        self.logger = logger or get_logger()
        # Response bodies are kept only in memory (and only while a scan runs)
        # so that technology detection can inspect them.  They are never
        # persisted and can be released with :meth:`clear_bodies`.
        self.bodies: Dict[str, str] = {}

    def clear_bodies(self) -> None:
        """Release retained response bodies."""
        self.bodies.clear()

    def probe(self, host: str) -> HTTPObservation:
        """Probe a single host, returning an :class:`HTTPObservation`."""
        schemes = ["https", "http"] if self.options.https_first else ["http", "https"]
        last: Optional[HTTPObservation] = None

        for scheme in schemes:
            url = f"{scheme}://{host}"
            response = self.client.probe(
                url,
                timeout=self.options.timeout,
                max_body_size=self.options.max_body_size,
                verify_tls=self.options.verify_tls,
                capture_cert=self.options.capture_tls,
            )
            if response.error and response.status_code == 0:
                last = self._observation_from_error(host, url, scheme, response)
                if scheme == schemes[0] and not self.options.fallback_http:
                    return last
                continue

            observation = self._observation_from_response(host, url, scheme, response)
            return observation

        return last or HTTPObservation(host=host, category=HTTPCategory.UNKNOWN, error="no response")

    def probe_many(self, hosts: Sequence[str], callback=None) -> Dict[str, HTTPObservation]:
        """Probe many hosts concurrently.  Failures are contained per host."""
        results: Dict[str, HTTPObservation] = {}
        hosts = list(dict.fromkeys(hosts or []))
        if not hosts:
            return results
        threads = max(1, min(int(self.options.threads), 64))
        with ThreadPoolExecutor(max_workers=threads, thread_name_prefix="http") as pool:
            futures = {pool.submit(self.probe, host): host for host in hosts}
            for future, host in futures.items():
                try:
                    observation = future.result()
                except Exception as exc:  # noqa: BLE001 - isolate per-host crashes
                    observation = HTTPObservation(
                        host=host,
                        category=HTTPCategory.UNKNOWN,
                        error=f"{exc.__class__.__name__}: {exc}",
                    )
                results[host] = observation
                if callback:
                    callback(observation)
        return results

    # -- internals --------------------------------------------------------
    def _observation_from_response(self, host: str, url: str, scheme: str, response) -> HTTPObservation:
        headers = dict(response.headers or {})
        body = response.text or ""
        if body:
            self.bodies[host] = body[: self.options.max_body_size]
        title = extract_title(body)
        observation = HTTPObservation(
            host=host,
            url=url,
            final_url=(response.history[-1] if response.history else url),
            scheme=scheme,
            status_code=response.status_code,
            category=classify_status(response.status_code),
            title=title,
            server=headers.get("Server") or headers.get("server"),
            powered_by=headers.get("X-Powered-By") or headers.get("x-powered-by"),
            content_type=(headers.get("Content-Type") or headers.get("content-type") or "").split(";")[0] or None,
            content_length=_safe_length(headers.get("Content-Length") or headers.get("content-length"))
            or len(response.text or ""),
            response_time_ms=response.elapsed_ms,
            redirect_count=len(response.history),
            redirect_chain=list(response.history),
            headers={k: v for k, v in headers.items()} if self.options.collect_headers else {},
            cookies=_cookie_names(headers),
            observed_at=_now(),
        )
        if response.error:
            observation.error = response.error
        if response.peer_cert:
            from .tls import parse_certificate

            try:
                observation.tls = parse_certificate(host, response.peer_cert)
            except Exception:  # noqa: BLE001
                observation.tls = None
        return observation

    def _observation_from_error(self, host: str, url: str, scheme: str, response) -> HTTPObservation:
        return HTTPObservation(
            host=host,
            url=url,
            scheme=scheme,
            category=classify_status(None, response.error),
            response_time_ms=response.elapsed_ms,
            error=response.error,
            redirect_chain=list(response.history or []),
            observed_at=_now(),
        )


def _safe_length(value) -> Optional[int]:  # noqa: ANN001
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _cookie_names(headers: Dict[str, str]) -> List[str]:
    """Return cookie *names* only (never values - they can carry secrets)."""
    raw = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    names: List[str] = []
    for chunk in raw.split(","):
        name = chunk.split("=", 1)[0].strip()
        if name and name.lower() != "set-cookie":
            names.append(name)
    return sorted(set(names))[:15]


def _now() -> str:
    from ..models import utcnow_iso

    return utcnow_iso()


def summarize_http(observations: Sequence[HTTPObservation]) -> Dict[str, int]:
    """Counter block for reports (live / redirect / errors ...)."""
    summary: Dict[str, int] = {}
    for observation in observations or []:
        key = observation.category.value
        summary[key] = summary.get(key, 0) + 1
    return summary
