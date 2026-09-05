"""DNSDumpster - public (unauthenticated) workflow.

DNSDumpster exposes an HTML form protected by a per-session CSRF token.  The
workflow below is the documented public one: fetch the page, read the token and
cookie from the response, then submit the form.  No account, no login and no
CAPTCHA interaction is performed; if the site changes or blocks the request the
adapter simply reports ``UNAVAILABLE``.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from ..models import SourceCategory, SourceResult
from .base import PassiveSource, SourceUnavailableError

_BASE = "https://dnsdumpster.com"
_TOKEN_RE = re.compile(r"name=['\"]csrfmiddlewaretoken['\"]\s+value=['\"]([^'\"]+)['\"]")
_HOST_RE = re.compile(r"([A-Za-z0-9_.*-]+\.[A-Za-z0-9_.*-]+\.[A-Za-z]{2,})")


class DNSDumpsterSource(PassiveSource):
    """Use the public DNSDumpster form workflow (no credentials)."""

    name = "dnsdumpster"
    description = "DNSDumpster public DNS reconstruction workflow"
    category = SourceCategory.DNS.value
    homepage = "https://dnsdumpster.com"
    rate_limit_seconds = 3.0
    timeout = 40
    allowed_content_types = ("text/html", "text/plain")

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        if self.http is None:
            raise SourceUnavailableError("no HTTP client configured")

        token, cookies = self._open_session()
        if not token:
            raise SourceUnavailableError("could not obtain DNSDumpster CSRF token")

        response = self._submit(domain, token, cookies)
        if response.status_code >= 400 or (response.error and not response.text):
            raise SourceUnavailableError(f"DNSDumpster rejected the request ({response.error})")

        body = response.text or ""
        if "csrfmiddlewaretoken" in body and "Host Records" not in body:
            raise SourceUnavailableError("DNSDumpster returned the form instead of results")

        hosts = {match.group(1).lower().rstrip(".") for match in _HOST_RE.finditer(body)}
        result.raw_count = len(hosts)
        for host in sorted(hosts):
            result.add(host, raw=host)
        return result

    # -- internals --------------------------------------------------------
    def _open_session(self):  # noqa: ANN201
        self.rate_limiter.wait(self.name)
        response = self.http.get(_BASE + "/", timeout=self.timeout, rate_key=self.name)
        self.last_response = response
        if response.error and not response.text:
            return None, {}
        match = _TOKEN_RE.search(response.text or "")
        token = match.group(1) if match else None
        cookie_header: Optional[str] = response.headers.get("Set-Cookie")
        cookies = {"csrftoken": _cookie_value(cookie_header, "csrftoken")} if cookie_header else {}
        if token and cookies.get("csrftoken"):
            cookies["csrftoken"] = token
        return token, cookies

    def _submit(self, domain: str, token: str, cookies: Dict[str, str]):  # noqa: ANN201
        self.rate_limiter.wait(self.name)
        headers = {
            "Referer": _BASE + "/",
            "Origin": _BASE,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "SubdomainX/1.0 (authorized security reconnaissance)",
        }
        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items() if v)
        response = self.http.request(
            "POST",
            _BASE + "/",
            data={"csrfmiddlewaretoken": token, "targetip": domain, "user": "free"},
            headers=headers,
            timeout=self.timeout,
            rate_key=self.name,
        )
        self.last_response = response
        return response

    def is_supported(self) -> bool:  # noqa: D102
        return True


def _cookie_value(header: str, name: str) -> Optional[str]:
    for part in (header or "").split(","):
        chunk = part.split(";", 1)[0].strip()
        if chunk.startswith(f"{name}="):
            return chunk.split("=", 1)[1]
    return None


def _unused(*args: Any) -> None:  # pragma: no cover - keeps linters quiet
    return None
