# Security policy & scope boundaries

## Supported use

SUBDOMAINX is a defensive security and OSINT tool. Legitimate uses include:

* authorized bug bounty reconnaissance,
* defensive asset inventory and attack-surface management,
* internal security assessments,
* OSINT research on domains you control.

Only run it against targets you own or have written permission to assess.

## Out of scope (by design)

The following are **deliberately not implemented** and pull requests adding
them will be rejected:

```text
subdomain brute forcing        credential attacks / password spraying
exploitation of any kind       RCE / SQLi / XSS / SSRF payloads
authentication bypass          CAPTCHA solving or bypass
WAF bypass                     rate-limit evasion / stealth scanning
IP spoofing / identity rotation malware / persistence / destructive actions
```

## Technical guarantees

| Guarantee | Implementation |
|---|---|
| No API keys | every source sets `requires_api_key = False`; keyed sources are registered as `UNSUPPORTED` and skipped |
| No credentials | no login flow, no token storage, no secrets in config |
| Honest identity | fixed `User-Agent: SubdomainX/1.0 (authorized security reconnaissance)` |
| Respectful rate limiting | per-source `RateLimiter` + exponential backoff on 429/503 |
| Read-only requests | only `GET` (and the documented public DNSDumpster form `POST`) |
| Bounded responses | `max_body_size` limit per response, default 1 MB for probes |
| No secret capture | cookie *names* only, never values |
| Local only | SQLite and `.cache/` on disk; no telemetry, no cloud service |

## Reporting a vulnerability in SUBDOMAINX

Open a GitHub issue (or a private security advisory) describing the problem,
the affected version and a reproduction. Please do not open a public issue for
an exploitable vulnerability before a fix is available.
