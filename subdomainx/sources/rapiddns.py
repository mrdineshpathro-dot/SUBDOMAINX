"""RapidDNS - public passive DNS HTML interface."""

from __future__ import annotations

import re
from html.parser import HTMLParser

from ..models import SourceCategory, SourceResult
from .base import PassiveSource, SourceUnavailableError

_HOST_RE = re.compile(
    r"<td[^>]*>\s*<a[^>]*href=\"https?://([^\"/?#]+)[^\"]*\"[^>]*>.*?</a>\s*</td>",
    re.IGNORECASE | re.DOTALL,
)
_ANY_HOST_RE = re.compile(r"^\*?[A-Za-z0-9_.-]+\.[A-Za-z]{2,}$")


class _TableTextParser(HTMLParser):
    """Collect text content of ``<td>`` cells from a RapidDNS result table."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._capture = False
        self.cells: list[str] = []

    def handle_starttag(self, tag, attrs):  # noqa: ANN001, ANN201
        if tag == "td":
            self._capture = True

    def handle_endtag(self, tag):  # noqa: ANN001
        if tag == "td":
            self._capture = False

    def handle_data(self, data):  # noqa: ANN001
        if self._capture:
            text = data.strip()
            if text:
                self.cells.append(text)


class RapidDNSSource(PassiveSource):
    """Scrape the public RapidDNS subdomain listing page."""

    name = "rapiddns"
    description = "RapidDNS public passive DNS subdomain listing"
    category = SourceCategory.DNS.value
    homepage = "https://rapiddns.io"
    rate_limit_seconds = 2.0
    timeout = 30
    allowed_content_types = ("text/html", "text/plain")
    max_body_size = 12_000_000

    URL = "https://rapiddns.io/subdomain/{domain}?full=1"

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        body = self.fetch_text(self.URL.format(domain=domain))
        if not body.strip():
            raise SourceUnavailableError("empty response from rapiddns")
        if "<table" not in body.lower():
            raise SourceUnavailableError("rapiddns returned no result table")

        hosts: list[str] = []
        for match in _HOST_RE.finditer(body):
            hosts.append(match.group(1))
        if not hosts:
            parser = _TableTextParser()
            try:
                parser.feed(body)
            except Exception:  # noqa: BLE001 - malformed HTML is expected here
                pass
            hosts = [cell for cell in parser.cells if _ANY_HOST_RE.match(cell)]

        result.raw_count = len(hosts)
        for host in hosts:
            result.add(host, raw=host)
        return result
