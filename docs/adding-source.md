# Adding a passive source

Sources are auto-discovered: drop a module into `subdomainx/sources/` and it is
registered on the next run. No central list to edit.

## 1. Create the module

```python
# subdomainx/sources/example_source.py
"""ExampleSource - public passive source (no API key)."""

from __future__ import annotations

from ..models import SourceCategory, SourceResult
from .base import PassiveSource


class ExampleSource(PassiveSource):
    name = "example"                                   # unique, lowercase
    description = "Public passive source"
    category = SourceCategory.OSINT.value
    homepage = "https://example.com"
    rate_limit_seconds = 2.0                           # courtesy delay
    timeout = 30
    allowed_content_types = ("application/json",)

    def discover(self, domain: str) -> SourceResult:
        result = SourceResult(source=self.name, domain=domain)
        payload = self.fetch_json("https://api.example.com/subdomains", params={"domain": domain})
        for entry in payload or []:
            result.add(str(entry), raw=str(entry))     # normalization happens later
        return result
```

That is the whole contract. `PassiveSource.run()` wraps `discover()` and
converts any exception into a `FAILED` / `UNAVAILABLE` / `RATE_LIMITED` result,
so a broken source can never break a scan.

## 2. Rules a source must follow

1. **No credentials.** If the endpoint needs a key, set
   `requires_api_key = True` - the registry will then skip the source and report
   it as `UNSUPPORTED`.
2. **No control bypass.** Do not solve CAPTCHAs, do not rotate identities, do
   not fake headers, do not hammer an endpoint.
3. **Honest failure.** Raise `SourceUnavailableError`, `RateLimitedError` or
   `ParserError` (all defined in `sources/base.py`) so the health dashboard can
   classify the problem.
4. **Return raw candidates.** URLs, wildcards, uppercase and ports are all
   fine - the normalization pipeline cleans them up. Pass the original string
   to `result.add(..., raw=...)` for provenance.
5. **Add dates when you have them.** `result.add(host, first_seen="2024-01-01",
   last_seen="2024-05-01")` and `result.add_history(...)` feed the historical
   engine.

## 3. Helper API available to sources

| Helper | Purpose |
|---|---|
| `self.fetch_text(url, **kw)` | GET and return the body, typed errors on failure |
| `self.fetch_json(url, **kw)` | GET + `json.loads`, `ParserError` on bad JSON |
| `self._request(url, **kw)` | raw `HTTPResponse` (status, headers, timing) |
| `self.headers()` | extra headers for this source |
| `self.mark_parser_failure(msg)` | count a non-fatal parsing problem |
| `self.rate_limiter` | per-source minimum interval |

## 4. Test it

```python
# tests/test_sources.py
from .conftest import FakeHTTPClient, make_response

def test_example_source():
    from subdomainx.sources.example_source import ExampleSource

    client = FakeHTTPClient([("api.example.com", make_response('["a.target.test"]'))])
    result = ExampleSource(http=client).run("target.test")
    assert "a.target.test" in result.observations
```

Tests must never touch the network - use `FakeHTTPClient`.

## 5. Document it

Add a row to [`docs/sources.md`](sources.md) and, if the source is historical in
nature, mention it in the README.
