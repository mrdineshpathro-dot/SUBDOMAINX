# SUBDOMAINX

**Passive Subdomain Discovery & Asset Intelligence Aggregator**

```text
╔══════════════════════════════════════════════════════════╗
║                    SUBDOMAINX v1.0                       ║
║        Passive Subdomain Discovery & Intelligence        ║
╚══════════════════════════════════════════════════════════╝
```

SUBDOMAINX discovers, normalizes, validates, correlates, enriches, scores and
exports subdomains for a target domain using **only publicly accessible,
unauthenticated passive intelligence sources**.

```text
API KEYS REQUIRED:        NONE
AUTHENTICATION REQUIRED:  NONE
```

---

## Table of contents

1. [Quick start](#quick-start)
2. [What it does](#what-it-does)
3. [Command reference](#command-reference)
4. [Passive sources](#passive-sources)
5. [Confidence scoring](#confidence-scoring)
6. [Output formats](#output-formats)
7. [Local database & history](#local-database--history)
8. [Diff, baseline and watch mode](#diff-baseline-and-watch-mode)
9. [Interactive mode](#interactive-mode)
10. [Configuration](#configuration)
11. [Performance profiles](#performance-profiles)
12. [Project layout](#project-layout)
13. [Running the tests](#running-the-tests)
14. [Responsible use & security boundaries](#responsible-use--security-boundaries)
15. [Troubleshooting](#troubleshooting)

---

## Quick start

```bash
git clone https://github.com/mrdineshpathro-dot/SUBDOMAINX.git
cd SUBDOMAINX
pip install -r requirements.txt

python subdomainx.py example.com
```

There is nothing to configure: **no API keys, no accounts, no `.env` file.**

```bash
# Deep passive run with DNS + HTTP + technology detection
python subdomainx.py example.com --sources all --resolve --probe --tech

# Authorized-research view + standalone HTML report
python subdomainx.py example.com --bugbounty --resolve --probe \
    --output report.html --format html

# Historical / database queries
python subdomainx.py history example.com
python subdomainx.py new example.com
python subdomainx.py removed example.com
python subdomainx.py sources example.com
python subdomainx.py stats example.com

# Compare against a previous export
python subdomainx.py example.com --diff previous.json

# Several targets
python subdomainx.py --input domains.txt --resolve --probe
```

---

## What it does

```text
Collection → Normalization → Validation → Deduplication → Source correlation
→ DNS enrichment → HTTP enrichment → Technology detection → Cloud/CDN
classification → Risk & confidence scoring → Interesting host identification
→ Historical comparison → Export / reporting
```

* **Collection** — 14 unauthenticated passive source adapters, executed
  concurrently with per-source rate limiting.
* **Normalization** — collapses URLs, ports, schemes, trailing dots, wildcard
  notation, uppercase, percent-encoding, duplicate separators and IDN into one
  canonical hostname. Rejects `javascript:`, `data:`, `file:`, `localhost`,
  IP literals and metadata addresses.
* **Validation** — strict registrable-domain scope enforcement with correct
  handling of `co.uk`, `com.au`, `co.in`, `org.uk`, … (`example.com.evil.com`
  and `fooexample.com` are rejected).
* **Deduplication** — across case, trailing dot, scheme, port, wildcard
  notation and source duplication, while preserving provenance.
* **Correlation** — every host knows which sources saw it, how often, and when
  it was first and last observed.
* **DNS enrichment** — A, AAAA, CNAME, MX, NS, TXT, CAA, DNSSEC (optional),
  internal-looking detection and reliable wildcard detection.
* **HTTP enrichment** — status, redirect chain, title, server, content type,
  size, timing and TLS certificate metadata.
* **Fingerprinting** — technology, CDN and cloud provider classification with
  explicit evidence and honest confidence levels.
* **Scoring** — an explainable 0–100 confidence score plus a reconnaissance
  priority ordering.
* **History** — first seen / last seen, current vs historical, and change
  detection between runs.
* **Reporting** — terminal dashboard, JSON, CSV, TXT and a standalone offline
  HTML report.

---

## Command reference

```
subdomainx <domain> [options]
subdomainx <history|new|removed|sources|stats|targets|show> <domain> [--db FILE]
```

### Targets

| Flag | Description |
|---|---|
| `domain` | root domain (positional) |
| `--input FILE` | file with one domain per line (`#` comments allowed) |
| `--scope FILE` | restrict results to the listed patterns (`*.example.com`) |
| `--exclude FILE` | drop hosts matching the listed patterns |

### Discovery

| Flag | Description |
|---|---|
| `--sources all` / `--sources crtsh,urlscan` | select sources |
| `--list-sources` | show the source catalogue and exit |
| `--filter REGEX` | keep only hosts matching the regex |
| `--exclude-regex REGEX` | drop hosts matching the regex |
| `--history` | include archive sources and mark historical hosts |

### Enrichment

| Flag | Description |
|---|---|
| `--resolve` / `--no-resolve` | DNS enrichment on/off |
| `--probe` / `--no-probe` | HTTP probing on/off |
| `--tech` | technology detection (implies HTTP probing) |
| `--tls` | capture TLS certificate metadata |
| `--asn` | enrich resolved IPs with public ASN metadata |
| `--profile fast\|balanced\|deep` | performance profile |

### Engine

| Flag | Description |
|---|---|
| `--threads N` | global concurrency (default 10) |
| `--timeout N` | per-request timeout in seconds (default 10) |
| `--retries N` | retries per request (default 2) |
| `--rate-limit SECONDS` | minimum interval between requests to one source |

### Cache & storage

| Flag | Description |
|---|---|
| `--cache` / `--no-cache` | enable/disable the local response cache |
| `--cache-ttl SECONDS` | cache TTL (default 86400) |
| `--clear-cache` | delete cached responses and exit |
| `--db FILE` | SQLite path (default `subdomainx.db`) |
| `--no-db` | do not write to the database |

### Output

| Flag | Description |
|---|---|
| `--output FILE`, `-o` | write the report to a file |
| `--format txt\|json\|csv\|html` | report format |
| `--output-profile minimal\|standard\|detailed` | terminal layout |
| `--bugbounty` | authorized-research view |
| `--quiet`, `--verbose`, `--debug` | verbosity |
| `--no-color` | disable colour |
| `--log-format json` | structured JSON logging |
| `--log-file FILE` | also write logs to a file |

### Diff & monitoring

| Flag | Description |
|---|---|
| `--diff FILE` / `--baseline FILE` | compare against a previous export |
| `--watch` | rerun discovery periodically |
| `--interval SECONDS` | watch interval (default 21600) |

### Misc

| Flag | Description |
|---|---|
| `--interactive` | menu driven mode |
| `--import FILE` | load a previous JSON export |
| `--config FILE` | load `config.toml` |
| `--write-config FILE` | write an example configuration and exit |
| `--version`, `--help` | version / help |

---

## Passive sources

| Name | Type | Name | Type |
|---|---|---|---|
| `crtsh` | Certificate Transparency | `otx` | AlienVault OTX passive DNS |
| `certspotter` | CT issuance API | `threatminer` | OSINT passive DNS |
| `hackertarget` | passive DNS | `threatcrowd` | OSINT (often offline) |
| `rapiddns` | passive DNS | `anubis` | community dataset |
| `dnsdumpster` | public DNS workflow | `subdomaincenter` | public API |
| `bufferover` | passive DNS | `urlscan` | URL observations |
| `wayback` | Internet Archive CDX | `commoncrawl` | Common Crawl index |

`securitytrails` and `virustotal` are registered but **never executed** because
they require an API key — the health dashboard shows them as `UNSUPPORTED`.

See [`docs/sources.md`](docs/sources.md) for endpoints and honest caveats.

### Source health dashboard

```text
SOURCE HEALTH
────────────────────────────────────────────────────────
SOURCE                STATUS         RESULTS  LATENCY  ERRORS
crtsh                 ONLINE              142     820ms       0
hackertarget          ONLINE               37     310ms       0
rapiddns              ONLINE               68    1240ms       0
urlscan               RATE LIMITED         42     980ms       1
commoncrawl           ONLINE               19    4100ms       0
virustotal            UNSUPPORTED           0       0ms       0
────────────────────────────────────────────────────────
```

Tracked per source: results, successes, errors, rate-limit events, parser
failures, last HTTP status, average response time and last successful query.

---

## Confidence scoring

| Band | Score |
|---|---|
| VERY HIGH | 95–100 |
| HIGH | 80–94 |
| MEDIUM | 60–79 |
| LOW | 30–59 |
| VERY LOW | 0–29 |

Positive evidence: source diversity, certificate-transparency presence, high
trust sources, resolving DNS, live HTTP, repeated historical sightings,
DNSSEC.

Negative evidence: wildcard DNS matches, an uncorroborated single source,
random-looking labels, historical-only evidence.

Every score comes with the list of factors that produced it, e.g.

```text
+32 4 independent sources reported this host
+12 present in certificate transparency logs
+20 resolves to A/AAAA records
+12 HTTP 200
```

---

## Output formats

```bash
python subdomainx.py example.com --output hosts.txt   --format txt
python subdomainx.py example.com --output hosts.csv   --format csv
python subdomainx.py example.com --output report.json --format json
python subdomainx.py example.com --output report.html --format html
```

* **TXT** — one host per line (`--output-profile detailed` adds score/label/category).
* **CSV** — 24 columns including IP, CNAME, status, title, technology, CDN,
  cloud, category, first/last seen.
* **JSON** — the documented schema (`tool`, `version`, `target`, `scan`,
  `statistics`, `source_health`, `changes`, `hosts`), importable again with
  `--import`.
* **HTML** — a single self-contained file (embedded CSS/JS, no external
  resources) with overview cards, a sortable/filterable discovery table, source
  performance, interesting hosts, changes, asset intelligence and a source
  correlation graph.

---

## Local database & history

Everything is stored locally in `subdomainx.db` (SQLite, no server):

```bash
python subdomainx.py history example.com   # first/last seen per host
python subdomainx.py new example.com       # hosts that appeared in the last run
python subdomainx.py removed example.com   # hosts missing from the last run
python subdomainx.py sources example.com   # per-source performance
python subdomainx.py stats example.com     # aggregate statistics
python subdomainx.py targets               # every known target
python subdomainx.py show example.com api.example.com
```

Add `--format json` to any of them for machine-readable output.

Schema: `targets`, `hosts`, `sources`, `observations`, `dns_records`,
`http_observations`, `tls_observations`, `technology`,
`historical_observations`, `scan_runs`, `run_hosts`, `source_runs`, `errors`.

---

## Diff, baseline and watch mode

```bash
python subdomainx.py example.com --diff previous.json
```

```text
NEW SUBDOMAINS
────────────────────────────────────────────────────────
admin-new.example.com
api-v3.example.com

REMOVED SUBDOMAINS
────────────────────────────────────────────────────────
old-api.example.com

UNCHANGED
────────────────────────────────────────────────────────
127 hosts
```

Changes are also detected **without** a baseline file: the previous run is read
from `subdomainx.db` and compared host by host (DNS answers, CNAME, HTTP
status, title, technology, sources, confidence).

```bash
python subdomainx.py example.com --watch --interval 21600
```

```text
==================================================
SUBDOMAINX WATCH MODE
==================================================

Target: example.com
Interval: 21600 seconds

Previous: 184
Current: 187

NEW:
new-api.example.com
preview.example.com
```

---

## Interactive mode

```bash
python subdomainx.py --interactive
```

```text
SUBDOMAINX Interactive Mode

Target domain: example.com

  [1] Passive discovery
  [2] DNS enrichment
  [3] HTTP probing
  [4] Technology detection
  [5] Historical analysis
  [6] Export results
  [7] Exit
```

---

## Configuration

`config.toml` in the working directory is picked up automatically
(`--config` selects another file, `--write-config` writes an example).
Every value is optional.

```toml
[general]
threads = 10
timeout = 10
retries = 2
profile = "balanced"

[dns]
enabled = true

[http]
enabled = true
max_body_size = 1000000

[cache]
enabled = true
ttl = 86400

[sources]
crtsh = true
hackertarget = true
rapiddns = true
urlscan = true
commoncrawl = true
```

Priority: **defaults < config.toml < command line flags**.
No secrets are ever read or stored.

---

## Performance profiles

| Profile | Behaviour |
|---|---|
| `fast` | passive discovery only (no DNS, no HTTP, no wildcard detection) |
| `balanced` | passive + DNS + lightweight HTTP (default) |
| `deep` | passive + DNS + HTTP + TLS + technology + DNSSEC + historical analysis |

---

## Project layout

```text
subdomainx.py              launcher (run from the project root)
pyproject.toml
requirements.txt

subdomainx/
├── cli.py                 CLI, database commands, interactive & watch mode
├── config.py              dataclass config + TOML loading + profiles
├── engine.py              pipeline orchestration
├── models.py              dataclasses (Host, ScanResult, SourceHealth, ...)
├── sources/               one module per passive source + registry/base (SDK)
├── discovery/             normalize, validate, dedupe, correlate, classify,
│                          score, diff
├── enrichment/            dns, http, tls, technology, cdn, cloud, asn
├── storage/               database, cache, migrations
├── reporting/             terminal, json, csv, html
└── utils/                 http, logging, helpers

tests/                     340+ unit tests, all network mocked
docs/                      architecture, sources, adding-source
examples/                  domains.txt, config.example.toml
```

---

## Running the tests

```bash
pip install -r requirements.txt
python -m pytest
```

All tests are offline: HTTP is served by `FakeHTTPClient`, DNS by an in-memory
stub resolver and SQLite by temporary files. **No test requires internet
access.**

---

## Responsible use & security boundaries

SUBDOMAINX is intended for authorized bug bounty reconnaissance, defensive
asset inventory, security assessments and OSINT research.

The project explicitly **does not** implement:

```text
subdomain brute forcing      credential attacks        password spraying
exploitation                 RCE                       SQL injection
XSS                          SSRF attacks              authentication bypass
CAPTCHA solving/bypass       WAF bypass                stealth scanning
evasion                      malware                   persistence
destructive actions
```

Additional guarantees:

* Only read-only, publicly accessible endpoints are queried.
* A fixed, honest `User-Agent` identifies the tool.
* Per-source rate limiting is applied as a courtesy to upstream providers.
* Only lightweight HTTP metadata is collected; response bodies are size-limited
  and kept in memory only.
* Cookie *names* may be recorded, never cookie values.
* "Interesting" hosts describe reconnaissance priority, **not** vulnerabilities.

Only run SUBDOMAINX against domains you own or are explicitly authorized to
assess.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| All sources report `FAILED` | no outbound internet access, or a corporate proxy; check with `curl https://crt.sh` |
| A source reports `RATE LIMITED` | the provider throttled us; wait, or raise `--rate-limit` |
| `UNSUPPORTED` for a source | the source requires an API key, so SUBDOMAINX refuses to run it |
| Results look out of scope | verify the target's registrable domain; use `--scope` to narrow further |
| Everything is `HISTORICAL` | the host was only seen in archives; DNS/HTTP enrichment found nothing |
| Database locked | another scan is running; use `--db` to point at a different file |

Enable `--debug` (or `--log-format json --log-file scan.log`) for detailed
diagnostics.

---

## Requirements

* Python 3.11+
* `requests`, `dnspython`, `tldextract`, `beautifulsoup4`, `pydantic`, `rich`

## License

MIT — see [LICENSE](LICENSE).
