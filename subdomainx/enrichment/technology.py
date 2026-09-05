"""Lightweight, passive technology fingerprinting.

Only already-collected response metadata is inspected: headers, cookie *names*
and the (size limited) HTML body.  No extra requests are performed and nothing
intrusive is sent to the target.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from ..models import HTTPObservation, Technology
from ..utils.helpers import truncate


@dataclass(frozen=True)
class TechRule:
    """A single passive fingerprint rule."""

    name: str
    category: str
    evidence: str
    header: Optional[str] = None
    header_value: Optional[str] = None
    cookie: Optional[str] = None
    body: Optional[str] = None
    confidence: int = 60


RULES: List[TechRule] = [
    # --- web servers / proxies -------------------------------------------
    TechRule("nginx", "web-server", "Server header", header="server", header_value="nginx", confidence=92),
    TechRule("Apache", "web-server", "Server header", header="server", header_value="apache", confidence=92),
    TechRule("Microsoft-IIS", "web-server", "Server header", header="server", header_value="microsoft-iis", confidence=95),
    TechRule("Envoy", "proxy", "Server header", header="server", header_value="envoy", confidence=85),
    TechRule("HAProxy", "proxy", "Server header", header="server", header_value="haproxy", confidence=70),
    TechRule("Varnish", "cache", "Via/X-Varnish header", header="x-varnish", confidence=75),
    TechRule("Varnish", "cache", "Via header", header="via", header_value="varnish", confidence=70),
    TechRule("Squid", "cache", "Via header", header="via", header_value="squid", confidence=70),
    TechRule("Tomcat", "app-server", "Cookie JSESSIONID", cookie="jsessionid", confidence=60),
    TechRule("Apache-Coyote", "app-server", "Server header", header="server", header_value="coyote", confidence=80),
    # --- runtimes / frameworks -------------------------------------------
    TechRule("PHP", "language", "X-Powered-By header", header="x-powered-by", header_value="php", confidence=90),
    TechRule("ASP.NET", "framework", "X-Powered-By header", header="x-powered-by", header_value="asp.net", confidence=90),
    TechRule("ASP.NET", "framework", "Cookie ASPSESSIONID", cookie="aspsessionid", confidence=75),
    TechRule("Express", "framework", "X-Powered-By header", header="x-powered-by", header_value="express", confidence=90),
    TechRule("Next.js", "framework", "x-nextjs header", header="x-nextjs", confidence=88),
    TechRule("Next.js", "framework", "HTML body", body="/_next/static", confidence=70),
    TechRule("Nuxt.js", "framework", "HTML body", body="__NUXT__", confidence=72),
    TechRule("Vue.js", "framework", "HTML body", body="data-v-", confidence=55),
    TechRule("Vue.js", "framework", "HTML body", body="vue.min.js", confidence=65),
    TechRule("React", "framework", "HTML body", body="data-reactroot", confidence=65),
    TechRule("React", "framework", "HTML body", body="__REACT_DEVTOOLS", confidence=60),
    TechRule("Angular", "framework", "HTML body", body="ng-version=", confidence=70),
    TechRule("Angular", "framework", "HTML body", body="angular.min.js", confidence=60),
    TechRule("jQuery", "library", "HTML body", body="jquery", confidence=50),
    TechRule("Laravel", "framework", "Cookie laravel_session", cookie="laravel_session", confidence=85),
    TechRule("Laravel", "framework", "Cookie XSRF-TOKEN", cookie="xsrf-token", confidence=45),
    TechRule("Django", "framework", "Cookie csrftoken", cookie="csrftoken", confidence=60),
    TechRule("Django", "framework", "HTML body", body="csrfmiddlewaretoken", confidence=70),
    TechRule("Ruby on Rails", "framework", "X-Runtime header", header="x-runtime", confidence=55),
    TechRule("Ruby on Rails", "framework", "Cookie _session_id", cookie="_session_id", confidence=70),
    TechRule("WordPress", "cms", "HTML body", body="wp-content", confidence=80),
    TechRule("WordPress", "cms", "HTML body", body="wp-includes", confidence=80),
    TechRule("WordPress", "cms", "HTML generator", body='name="generator" content="WordPress', confidence=88),
    TechRule("Joomla", "cms", "HTML generator", body='name="generator" content="Joomla', confidence=88),
    TechRule("Drupal", "cms", "HTML generator", body='name="generator" content="Drupal', confidence=88),
    TechRule("Drupal", "cms", "HTML body", body="sites/all/themes", confidence=70),
    TechRule("Shopify", "saas", "Server header", header="server", header_value="shopify", confidence=85),
    TechRule("Salesforce", "saas", "HTML body", body="salesforce", confidence=55),
    TechRule("Jenkins", "ci", "X-Jenkins header", header="x-jenkins", confidence=92),
    TechRule("Grafana", "monitoring", "HTML body", body="grafana", confidence=65),
    TechRule("Kibana", "monitoring", "kbn-name header", header="kbn-name", confidence=90),
    TechRule("Swagger UI", "docs", "HTML body", body="swagger-ui", confidence=75),
    TechRule("OpenAPI/Swagger", "docs", "HTML body", body="swagger.json", confidence=60),
    TechRule("GraphQL", "api", "HTML body", body="graphql", confidence=45),
    # --- cloud / edge hints ----------------------------------------------
    TechRule("AWS", "cloud", "x-amz header", header="x-amz-request-id", confidence=70),
    TechRule("AWS", "cloud", "x-amzn header", header="x-amzn-requestid", confidence=70),
    TechRule("Google Cloud", "cloud", "x-goog header", header="x-goog-generation", confidence=70),
    TechRule("Google Frontend", "cloud", "Server header", header="server", header_value="google frontend", confidence=80),
    TechRule("Azure", "cloud", "x-azure-ref header", header="x-azure-ref", confidence=80),
    TechRule("Azure", "cloud", "Server header", header="server", header_value="microsoft-azure", confidence=75),
    TechRule("Netlify", "cloud", "x-nf-request-id header", header="x-nf-request-id", confidence=85),
    TechRule("Vercel", "cloud", "x-vercel-id header", header="x-vercel-id", confidence=88),
    TechRule("Heroku", "cloud", "Via header", header="via", header_value="vegur", confidence=75),
    TechRule("GitHub Pages", "cloud", "x-github-request-id header", header="x-github-request-id", confidence=80),
    TechRule("Fastly", "cdn", "x-served-by header", header="x-served-by", header_value="fastly", confidence=88),
    TechRule("Cloudflare", "cdn", "cf-ray header", header="cf-ray", confidence=95),
    TechRule("Cloudflare", "cdn", "Server header", header="server", header_value="cloudflare", confidence=92),
    TechRule("CloudFront", "cdn", "x-amz-cf-id header", header="x-amz-cf-id", confidence=95),
    TechRule("Akamai", "cdn", "x-cache-key header", header="x-cache-key", confidence=80),
    TechRule("Imperva/Incapsula", "cdn", "x-iinfo header", header="x-iinfo", confidence=70),
]


def _match_header(observation: HTTPObservation, rule: TechRule) -> Optional[str]:
    if not rule.header:
        return None
    headers = {str(k).lower(): str(v) for k, v in (observation.headers or {}).items()}
    value = headers.get(rule.header.lower())
    if value is None:
        return None
    if rule.header_value and rule.header_value not in value.lower():
        return None
    return f"{rule.header}: {truncate(value, 60)}"


def _match_cookie(observation: HTTPObservation, rule: TechRule) -> Optional[str]:
    if not rule.cookie:
        return None
    cookies = {c.lower() for c in (observation.cookies or [])}
    if rule.cookie.lower() in cookies:
        return f"cookie: {rule.cookie}"
    return None


def _match_body(body: str, rule: TechRule) -> Optional[str]:
    if not rule.body or not body:
        return None
    if rule.body.lower() in body.lower():
        return f"body contains '{rule.body}'"
    return None


def detect_technologies(
    observation: Optional[HTTPObservation],
    body: Optional[str] = None,
) -> List[Technology]:
    """Return technologies detected from an HTTP observation.

    ``body`` may be supplied when the caller kept the response body separately
    (the observation itself only stores metadata).
    """
    if observation is None:
        return []
    payload = body or ""
    found: Dict[str, Technology] = {}

    for rule in RULES:
        evidence = (
            _match_header(observation, rule)
            or _match_cookie(observation, rule)
            or _match_body(payload, rule)
        )
        if not evidence:
            continue
        existing = found.get(rule.name)
        if existing is None or rule.confidence > existing.confidence:
            found[rule.name] = Technology(
                name=rule.name,
                category=rule.category,
                evidence=evidence,
                confidence=rule.confidence,
            )
    return sorted(found.values(), key=lambda t: (-t.confidence, t.name))


def technologies_from_dns(cnames: List[str]) -> List[Technology]:
    """Derive technology hints purely from CNAME targets (no extra requests)."""
    hints: List[Technology] = []
    joined = " ".join(cnames or []).lower()
    for needle, name, category in (
        ("cloudfront.net", "CloudFront", "cdn"),
        ("amazonaws.com", "AWS", "cloud"),
        ("azurewebsites.net", "Azure App Service", "cloud"),
        ("azurefd.net", "Azure Front Door", "cdn"),
        ("storage.googleapis.com", "Google Cloud Storage", "cloud"),
        ("herokuapp.com", "Heroku", "cloud"),
        ("netlify.app", "Netlify", "cloud"),
        ("vercel.app", "Vercel", "cloud"),
    ):
        if needle in joined:
            hints.append(
                Technology(name=name, category=category, evidence=f"CNAME -> *.{needle}", confidence=75)
            )
    return hints
