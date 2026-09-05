"""Reusable HTTP layer for SUBDOMAINX.

Every outbound request in the project goes through :class:`HTTPClient`.  It
provides:

* connection pooling / session reuse (one :class:`requests.Session`)
* hard timeouts and bounded retries with exponential backoff
* an honest, identifiable ``User-Agent`` (never disguised)
* response size limits and encoding hardening
* per-source rate limiting (a defensive courtesy, never an evasion technique)
* optional on-disk caching
* total error isolation: failures are returned, never raised
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter

DEFAULT_USER_AGENT = "SubdomainX/1.0 (authorized security reconnaissance)"

# Status codes that mean "try again later".
RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}


@dataclass
class HTTPResponse:
    """Normalised, always-safe HTTP response object."""

    url: str
    status_code: int = 0
    text: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    from_cache: bool = False
    attempts: int = 0
    truncated: bool = False
    history: List[str] = field(default_factory=list)
    peer_cert: Optional[Dict[str, Any]] = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 300

    @property
    def rate_limited(self) -> bool:
        return self.status_code in (429, 503)

    def json(self) -> Any:  # noqa: ANN401
        """Parse the body as JSON, returning ``None`` on any failure."""
        import json

        try:
            return json.loads(self.text)
        except (ValueError, TypeError):
            return None


class RateLimiter:
    """Simple thread-safe minimum-interval limiter (token free, no evasion)."""

    def __init__(self, min_interval: float = 0.0) -> None:
        self.min_interval = max(0.0, float(min_interval))
        self._last: Dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, key: str = "default") -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            last = self._last.get(key, 0.0)
            delta = self.min_interval - (now - last)
            if delta > 0:
                time.sleep(delta)
            self._last[key] = time.monotonic()


class HTTPClient:
    """One shared HTTP client used by all sources and enrichment modules."""

    def __init__(
        self,
        timeout: float = 10.0,
        retries: int = 2,
        backoff: float = 0.8,
        user_agent: str = DEFAULT_USER_AGENT,
        max_body_size: int = 2_000_000,
        pool_size: int = 32,
        verify_tls: bool = True,
        rate_limiter: Optional[RateLimiter] = None,
        cache: Optional[Any] = None,
        cache_ttl: int = 86_400,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.timeout = float(timeout)
        self.retries = max(0, int(retries))
        self.backoff = float(backoff)
        self.max_body_size = int(max_body_size)
        self.verify_tls = bool(verify_tls)
        self.rate_limiter = rate_limiter or RateLimiter()
        self.cache = cache
        self.cache_ttl = int(cache_ttl)

        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=0)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )
        if extra_headers:
            self.session.headers.update(extra_headers)

    # -- public API -------------------------------------------------------
    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        rate_key: Optional[str] = None,
        allowed_content_types: Optional[Sequence[str]] = None,
        max_body_size: Optional[int] = None,
    ) -> HTTPResponse:
        """Perform a GET request.  Never raises."""
        return self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            timeout=timeout,
            rate_key=rate_key,
            allowed_content_types=allowed_content_types,
            max_body_size=max_body_size,
        )

    def probe(
        self,
        url: str,
        timeout: Optional[float] = None,
        max_body_size: int = 262_144,
        verify_tls: bool = True,
        capture_cert: bool = False,
    ) -> HTTPResponse:
        """Lightweight metadata probe used by the HTTP enrichment engine.

        Unlike :meth:`get` this keeps the redirect chain and, optionally, the
        peer certificate.  It never retries and never raises.
        """
        started = time.monotonic()
        history: List[str] = []
        try:
            response = self.session.get(
                url,
                timeout=float(timeout or self.timeout),
                allow_redirects=True,
                stream=True,
                verify=verify_tls and self.verify_tls,
            )
            history = [str(item.url) for item in response.history]
            body, truncated = self._read_limited(response, int(max_body_size))
            elapsed = (time.monotonic() - started) * 1000
            headers = {str(k): str(v) for k, v in response.headers.items()}
            peer_cert = None
            if capture_cert and url.lower().startswith("https://"):
                peer_cert = self._peer_certificate(url)
            response.close()
            return HTTPResponse(
                url=url,
                status_code=response.status_code,
                text=body,
                headers=headers,
                elapsed_ms=round(elapsed, 2),
                attempts=1,
                truncated=truncated,
                history=history,
                peer_cert=peer_cert,
            )
        except requests.exceptions.SSLError as exc:
            return HTTPResponse(
                url=url,
                error=f"tls error: {exc.__class__.__name__}",
                elapsed_ms=round((time.monotonic() - started) * 1000, 2),
                attempts=1,
                history=history,
            )
        except requests.exceptions.Timeout:
            return HTTPResponse(
                url=url,
                error="timeout",
                elapsed_ms=round((time.monotonic() - started) * 1000, 2),
                attempts=1,
                history=history,
            )
        except requests.exceptions.RequestException as exc:
            return HTTPResponse(
                url=url,
                error=f"{exc.__class__.__name__}: {exc}",
                elapsed_ms=round((time.monotonic() - started) * 1000, 2),
                attempts=1,
                history=history,
            )
        except Exception as exc:  # noqa: BLE001
            return HTTPResponse(
                url=url,
                error=f"{exc.__class__.__name__}: {exc}",
                elapsed_ms=round((time.monotonic() - started) * 1000, 2),
                attempts=1,
                history=history,
            )

    def _peer_certificate(self, url: str) -> Optional[Dict[str, Any]]:
        """Return the peer certificate dictionary for an HTTPS URL (best effort)."""
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port or 443
            from ..enrichment.tls import fetch_certificate_dict

            return fetch_certificate_dict(host, port, timeout=self.timeout)
        except Exception:  # noqa: BLE001
            return None

    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        rate_key: Optional[str] = None,
    ) -> HTTPResponse:
        """Perform a POST request.  Never raises."""
        return self.request(
            "POST",
            url,
            params=None,
            data=data,
            json_body=json_body,
            headers=headers,
            timeout=timeout,
            rate_key=rate_key,
        )

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        rate_key: Optional[str] = None,
        allowed_content_types: Optional[Sequence[str]] = None,
        max_body_size: Optional[int] = None,
    ) -> HTTPResponse:
        """Perform an HTTP request with retries, limits and error isolation."""
        full_url = url
        if params:
            full_url = f"{url}{'&' if '?' in url else '?'}{urlencode(params, doseq=True)}"

        cache_key = f"{method}:{full_url}:{sorted((headers or {}).items())}"
        if method == "GET" and self.cache is not None:
            cached = self._cache_get(cache_key)
            if cached is not None:
                cached.from_cache = True
                return cached

        limit = int(max_body_size or self.max_body_size)
        timeout_value = float(timeout or self.timeout)
        attempts = 0
        last_error = "unknown error"
        last_status = 0

        for attempt in range(self.retries + 1):
            attempts = attempt + 1
            self.rate_limiter.wait(rate_key or url)
            started = time.monotonic()
            try:
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    json=json_body,
                    headers=headers,
                    timeout=timeout_value,
                    allow_redirects=True,
                    stream=True,
                    verify=self.verify_tls,
                )
                last_status = response.status_code
                body, truncated = self._read_limited(response, limit)
                elapsed = (time.monotonic() - started) * 1000
                resp_headers = {str(k): str(v) for k, v in response.headers.items()}

                if response.status_code in RETRY_STATUS and attempt < self.retries:
                    last_error = f"HTTP {response.status_code}"
                    response.close()
                    self._sleep_backoff(attempt)
                    continue

                wrapped = HTTPResponse(
                    url=full_url,
                    status_code=response.status_code,
                    text=body,
                    headers=resp_headers,
                    elapsed_ms=round(elapsed, 2),
                    attempts=attempts,
                    truncated=truncated,
                )
                if not wrapped.ok and response.status_code >= 400:
                    wrapped.error = f"HTTP {response.status_code}"
                response.close()

                if allowed_content_types:
                    ctype = (resp_headers.get("Content-Type") or "").split(";")[0].strip().lower()
                    if ctype and not any(ctype.startswith(a.lower()) for a in allowed_content_types):
                        wrapped.error = f"unexpected content-type: {ctype}"

                if method == "GET" and self.cache is not None and wrapped.ok:
                    self._cache_put(cache_key, wrapped)
                return wrapped

            except requests.exceptions.Timeout as exc:
                last_error = f"timeout: {exc.__class__.__name__}"
            except requests.exceptions.SSLError as exc:
                last_error = f"tls error: {exc.__class__.__name__}"
                break  # retrying a TLS failure is pointless
            except requests.exceptions.TooManyRedirects:
                last_error = "too many redirects"
                break
            except requests.exceptions.RequestException as exc:
                last_error = f"{exc.__class__.__name__}: {exc}"
            except Exception as exc:  # noqa: BLE001 - defensive: never crash a scan
                last_error = f"{exc.__class__.__name__}: {exc}"
                break

            if attempt < self.retries:
                self._sleep_backoff(attempt)

        return HTTPResponse(
            url=full_url,
            status_code=last_status,
            text="",
            elapsed_ms=0.0,
            error=last_error,
            attempts=attempts,
        )

    # -- internals --------------------------------------------------------
    def _read_limited(self, response: requests.Response, limit: int):  # noqa: ANN201
        """Read at most ``limit`` bytes, decoding defensively."""
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                if total + len(chunk) > limit:
                    chunks.append(chunk[: limit - total])
                    total = limit
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
        except Exception:  # noqa: BLE001 - truncated/unreadable body
            return "", True
        raw = b"".join(chunks)
        encoding = response.encoding or response.apparent_encoding or "utf-8"
        try:
            text = raw.decode(encoding, errors="replace")
        except (LookupError, TypeError):
            text = raw.decode("utf-8", errors="replace")
        return text.replace("\x00", ""), truncated

    def _sleep_backoff(self, attempt: int) -> None:
        delay = self.backoff * (2**attempt) + random.uniform(0, 0.25)
        time.sleep(min(delay, 8.0))

    def _cache_get(self, key: str) -> Optional[HTTPResponse]:
        try:
            payload = self.cache.get(key)
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(payload, dict):
            return None
        try:
            return HTTPResponse(**payload)
        except TypeError:
            return None

    def _cache_put(self, key: str, response: HTTPResponse) -> None:
        try:
            self.cache.put(
                key,
                {
                    "url": response.url,
                    "status_code": response.status_code,
                    "text": response.text,
                    "headers": response.headers,
                    "elapsed_ms": response.elapsed_ms,
                    "attempts": response.attempts,
                    "truncated": response.truncated,
                    "error": response.error,
                },
                ttl=self.cache_ttl,
            )
        except Exception:  # noqa: BLE001
            pass

    def close(self) -> None:
        """Close the underlying session and release pooled connections."""
        try:
            self.session.close()
        except Exception:  # noqa: BLE001
            pass


def build_headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return the default SUBDOMAINX request headers plus ``extra``."""
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    if extra:
        headers.update(extra)
    return headers


def merge_params(base: Optional[Dict[str, Any]], extra: Optional[Iterable[Any]]) -> Dict[str, Any]:
    """Utility used by sources building query strings from tuples."""
    merged: Dict[str, Any] = dict(base or {})
    for item in extra or []:
        if isinstance(item, (tuple, list)) and len(item) == 2:
            merged[item[0]] = item[1]
    return merged
