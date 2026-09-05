# SUBDOMAINX architecture

SUBDOMAINX is a layered, defensive reconnaissance tool. Every layer is
independently testable and every layer is allowed to fail without taking the
scan down with it.

## Pipeline

```text
Collection            sources/*           14 unauthenticated passive sources
    ↓
Normalization         discovery/normalize URLs, ports, wildcards, IDN, case
    ↓
Validation            discovery/validate  syntax + strict registrable-domain scope
    ↓
Deduplication         discovery/dedupe    canonical keys, provenance preserved
    ↓
Source Correlation    discovery/correlate host ↔ source graph, first/last seen
    ↓
DNS Enrichment        enrichment/dns      A/AAAA/CNAME/MX/NS/TXT/CAA, wildcard
    ↓
HTTP Enrichment       enrichment/http     status, title, headers, redirects, TLS
    ↓
Technology Detection  enrichment/technology + cdn + cloud + asn
    ↓
Classification        discovery/classify  category + "interesting" hosts
    ↓
Confidence Scoring    discovery/score     explainable 0-100 score + priority
    ↓
Historical Comparison discovery/diff      first/last seen, change detection
    ↓
Storage               storage/*           SQLite + local HTTP cache
    ↓
Export / Reporting    reporting/*         terminal, JSON, CSV, HTML
```

## Module map

| Package | Responsibility |
|---|---|
| `subdomainx/cli.py` | argument parsing, database sub-commands, interactive & watch mode |
| `subdomainx/engine.py` | orchestrates the pipeline, owns the HTTP client, cache and DB |
| `subdomainx/config.py` | dataclass config, TOML loading, FAST/BALANCED/DEEP profiles |
| `subdomainx/models.py` | dataclasses for hosts, observations, health, statistics |
| `subdomainx/sources/` | one module per passive source + registry/base (the source SDK) |
| `subdomainx/discovery/` | normalize, validate, dedupe, correlate, classify, score, diff |
| `subdomainx/enrichment/` | dns, http, tls, technology, cdn, cloud, asn |
| `subdomainx/storage/` | SQLite repository, file cache, migrations |
| `subdomainx/reporting/` | terminal, JSON, CSV, HTML renderers |
| `subdomainx/utils/` | HTTP client, structured logging, helpers |

## Data model

```text
targets 1───* scan_runs 1───* run_hosts *───1 hosts
                  │                            │
                  │                            ├──* observations            (source provenance)
                  │                            ├──* historical_observations (archive sightings)
                  │                            ├──* dns_records
                  │                            ├──* http_observations
                  │                            ├──* tls_observations
                  │                            └──* technology
                  ├──* source_runs *───1 sources
                  └──* errors
```

`run_hosts` is the join table that makes the ``new`` / ``removed`` queries
possible: a host belongs to every run in which it was observed, so the delta
between the two newest runs is computed with a single SQL statement.

## Concurrency model

* **Sources** run in a `ThreadPoolExecutor` sized `min(threads, len(sources))`.
  Each source has its own `RateLimiter` and its own timeout.
* **DNS** uses a second bounded pool (`dns.threads`, default 10).
* **HTTP probing** uses a third bounded pool (`http.threads`, default 10).
* The shared `requests.Session` keeps a connection pool of 32 sockets, so
  hundreds of probes reuse a handful of TCP/TLS handshakes.

No stage ever creates more than `threads` workers and no stage creates threads
per host.

## Failure isolation

| Failure | Handling |
|---|---|
| Source raises an exception | caught in `PassiveSource.run`, recorded as `FAILED`, scan continues |
| Source returns 429/503 | `RateLimitedError` → `RATE_LIMITED`, events counted |
| Source returns malformed JSON/HTML | `ParserError` → `FAILED`, parser-failure counter |
| Source starts requiring an API key | `requires_api_key = True` → `UNSUPPORTED`, never executed |
| DNS query fails | per-record try/except; host keeps whatever resolved |
| HTTP probe fails | `HTTPObservation` carries the error and the classified category |
| Database unavailable | warning logged, results still printed and exported |
| Cache unwritable | silently skipped |

## Confidence scoring

The score is a sum of explainable factors (see `discovery/score.py`), clamped to
`0..100`:

| Factor | Weight |
|---|---|
| base | +20 |
| ≥4 independent sources | +32 (3 → +26, 2 → +18, 1 → +8) |
| high-trust source | +3 each |
| certificate transparency | +12 |
| A/AAAA resolves | +20 (CNAME only: +12) |
| DNSSEC | +3 |
| HTTP 2xx/3xx | +12 (4xx: +8, 5xx: +4) |
| ≥3 historical sightings | +6 (1-2: +3) |
| wildcard DNS match | −25 (partial: −10) |
| single uncorroborated source | −8 |
| random-looking label | −5 |
| historical evidence only | −10 |

Bands: `95-100 VERY HIGH`, `80-94 HIGH`, `60-79 MEDIUM`, `30-59 LOW`,
`0-29 VERY LOW`.

## Security boundaries

SUBDOMAINX contains **no** brute forcer, no exploitation module, no credential
testing, no CAPTCHA/WAF evasion and no stealth option. The HTTP client sends a
fixed, honest `User-Agent` and honours per-source rate limits. See
[`SECURITY.md`](../SECURITY.md) and section 50 of the specification.
