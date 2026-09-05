# Passive source catalogue

All sources below are **public and unauthenticated**. SUBDOMAINX sends a fixed
`User-Agent` (`SubdomainX/1.0 (authorized security reconnaissance)`) and applies
a per-source minimum interval between requests. Nothing here bypasses a rate
limit, a CAPTCHA or an authentication wall.

Run `subdomainx --list-sources` to see the live catalogue.

| Name | Category | Endpoint | Notes |
|---|---|---|---|
| `crtsh` | certificate | `https://crt.sh/?q=%.DOMAIN&output=json` | Certificate Transparency search; wildcard and multi-name certificates are expanded |
| `certspotter` | certificate | `https://api.certspotter.com/v1/issuances` | SSLMate public CT issuance API |
| `hackertarget` | dns | `https://api.hackertarget.com/hostsearch/?q=DOMAIN` | Free tier, quota-limited without an account |
| `rapiddns` | dns | `https://rapiddns.io/subdomain/DOMAIN?full=1` | HTML result table |
| `dnsdumpster` | dns | `https://dnsdumpster.com/` | Public form workflow (CSRF token + cookie, no login) |
| `bufferover` | dns | `https://dns.bufferover.run/dns?q=.DOMAIN` | Intermittent service; reported `UNAVAILABLE` when down |
| `otx` | osint | `https://otx.alienvault.com/api/v1/indicators/domain/DOMAIN/passive_dns` | AlienVault OTX passive DNS |
| `threatminer` | osint | `https://api.threatminer.org/v2/domain.php?q=DOMAIN&rt=5` | Public passive DNS |
| `threatcrowd` | osint | `https://threatcrowd.org/searchApi/v2/domain/report/` | Frequently offline - degrades to `UNAVAILABLE` |
| `anubis` | osint | `https://jldc.me/anubis/subdomains/DOMAIN` | Community dataset, intermittent |
| `subdomaincenter` | osint | `https://api.subdomain.center/?domain=DOMAIN` | Keyless public API |
| `urlscan` | web | `https://urlscan.io/api/v1/search/?q=domain:DOMAIN` | Public URL observations |
| `wayback` | archive | `https://web.archive.org/cdx/search/cdx` | Internet Archive CDX; primary historical source |
| `commoncrawl` | archive | `https://index.commoncrawl.org/<collection>-index` | Newest public URL index discovered via `collinfo.json` |
| `securitytrails` | dns | — | **Requires an API key** - registered but never executed (`UNSUPPORTED`) |
| `virustotal` | osint | — | **Requires an API key** - registered but never executed (`UNSUPPORTED`) |

## Source states

| State | Meaning |
|---|---|
| `ONLINE` | the source answered and produced results |
| `RATE_LIMITED` | HTTP 429/503 received; the events counter is incremented |
| `FAILED` | transport error, parser failure or unexpected exception |
| `UNAVAILABLE` | the service answered but no longer supports the public workflow |
| `UNSUPPORTED` | the source requires credentials, so SUBDOMAINX refuses to run it |
| `DISABLED` | turned off in `config.toml` |

## Deliberately not implemented

* **Search-engine scraping.** Google, Bing and DuckDuckGo all protect their
  result pages with bot detection. Scraping them would mean evading that
  protection, which the project explicitly refuses to do. Rather than ship a
  source that silently returns nothing, SUBDOMAINX does not ship one at all.
* **Sources behind authentication.** Riddler, Censys, Shodan and similar
  services moved behind API keys. They are either omitted or registered with
  `requires_api_key = True` so their status is visible and honest.

## Adding a source

See [adding-source.md](adding-source.md).
