"""CDN / edge provider classification.

Evidence is gathered passively from CNAME targets and response headers.  Because
a CNAME can be a stale or partial indicator, results are always qualified:

* ``Confirmed CDN`` - strong header evidence (``cf-ray``, ``x-amz-cf-id`` ...)
* ``Likely CDN``    - CNAME points at a known edge provider
* ``Possible CDN``  - weak / ambiguous evidence
* ``No CDN evidence``
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..models import CDNClassification, CDNConfidence, DNSInfo, HTTPObservation

#: CNAME suffix -> (provider, confidence)
CNAME_SIGNATURES: List[Tuple[str, str, CDNConfidence]] = [
    ("cdn.cloudflare.net", "Cloudflare", CDNConfidence.CONFIRMED),
    ("cloudflare.com", "Cloudflare", CDNConfidence.CONFIRMED),
    ("cloudflare.net", "Cloudflare", CDNConfidence.LIKELY),
    ("cloudfront.net", "AWS CloudFront", CDNConfidence.CONFIRMED),
    ("fastly.net", "Fastly", CDNConfidence.CONFIRMED),
    ("fastlylb.net", "Fastly", CDNConfidence.CONFIRMED),
    ("map.fastly.net", "Fastly", CDNConfidence.CONFIRMED),
    ("akamai.net", "Akamai", CDNConfidence.CONFIRMED),
    ("akamaiedge.net", "Akamai", CDNConfidence.CONFIRMED),
    ("akamaized.net", "Akamai", CDNConfidence.CONFIRMED),
    ("edgekey.net", "Akamai", CDNConfidence.CONFIRMED),
    ("edgesuite.net", "Akamai", CDNConfidence.CONFIRMED),
    ("akadns.net", "Akamai", CDNConfidence.LIKELY),
    ("azurefd.net", "Azure Front Door", CDNConfidence.CONFIRMED),
    ("azureedge.net", "Azure CDN", CDNConfidence.CONFIRMED),
    ("trafficmanager.net", "Azure Traffic Manager", CDNConfidence.LIKELY),
    ("stackpathcdn.com", "StackPath", CDNConfidence.CONFIRMED),
    ("stackpathdns.com", "StackPath", CDNConfidence.LIKELY),
    ("impervadns.net", "Imperva", CDNConfidence.CONFIRMED),
    ("incapsula.com", "Imperva", CDNConfidence.CONFIRMED),
    ("keycdn.com", "KeyCDN", CDNConfidence.CONFIRMED),
    ("kxcdn.com", "KeyCDN", CDNConfidence.CONFIRMED),
    ("cdn77.org", "CDN77", CDNConfidence.CONFIRMED),
    ("rsc.cdn77.org", "CDN77", CDNConfidence.CONFIRMED),
    ("netlify.app", "Netlify", CDNConfidence.LIKELY),
    ("netlify.com", "Netlify", CDNConfidence.LIKELY),
    ("vercel-dns.com", "Vercel", CDNConfidence.LIKELY),
    ("vercel.app", "Vercel", CDNConfidence.LIKELY),
    ("github.io", "GitHub Pages", CDNConfidence.LIKELY),
    ("github.map.fastly.net", "Fastly", CDNConfidence.CONFIRMED),
    ("googleusercontent.com", "Google", CDNConfidence.LIKELY),
    ("googlesyndication.com", "Google", CDNConfidence.LIKELY),
    ("l.doubleclick.net", "Google", CDNConfidence.LIKELY),
    ("sucuri.net", "Sucuri", CDNConfidence.CONFIRMED),
    ("cdn77.com", "CDN77", CDNConfidence.CONFIRMED),
    ("cloudflare-ipfs.com", "Cloudflare", CDNConfidence.CONFIRMED),
    ("b-cdn.net", "Bunny CDN", CDNConfidence.CONFIRMED),
    ("bunnycdn.com", "Bunny CDN", CDNConfidence.CONFIRMED),
    ("cdninstagram.com", "Facebook CDN", CDNConfidence.CONFIRMED),
    ("fbcdn.net", "Facebook CDN", CDNConfidence.CONFIRMED),
]

#: header name -> (substring, provider, confidence)
HEADER_SIGNATURES: List[Tuple[str, str, str, CDNConfidence]] = [
    ("cf-ray", "", "Cloudflare", CDNConfidence.CONFIRMED),
    ("cf-cache-status", "", "Cloudflare", CDNConfidence.CONFIRMED),
    ("server", "cloudflare", "Cloudflare", CDNConfidence.CONFIRMED),
    ("x-amz-cf-id", "", "AWS CloudFront", CDNConfidence.CONFIRMED),
    ("x-amz-cf-pop", "", "AWS CloudFront", CDNConfidence.CONFIRMED),
    ("via", "cloudfront", "AWS CloudFront", CDNConfidence.CONFIRMED),
    ("x-served-by", "fastly", "Fastly", CDNConfidence.CONFIRMED),
    ("fastly-restarts", "", "Fastly", CDNConfidence.CONFIRMED),
    ("x-cache-key", "", "Akamai", CDNConfidence.LIKELY),
    ("x-akamai-transformed", "", "Akamai", CDNConfidence.CONFIRMED),
    ("server", "akamai", "Akamai", CDNConfidence.CONFIRMED),
    ("x-azure-ref", "", "Azure Front Door", CDNConfidence.CONFIRMED),
    ("x-azure-ref-origin-shield", "", "Azure Front Door", CDNConfidence.CONFIRMED),
    ("x-vercel-id", "", "Vercel", CDNConfidence.LIKELY),
    ("x-nf-request-id", "", "Netlify", CDNConfidence.LIKELY),
    ("x-iinfo", "", "Imperva", CDNConfidence.LIKELY),
    ("x-sucuri-id", "", "Sucuri", CDNConfidence.CONFIRMED),
    ("x-cdn", "", "Generic CDN", CDNConfidence.POSSIBLE),
    ("x-cache", "hit", "Generic CDN", CDNConfidence.POSSIBLE),
    ("x-served-by", "cache", "Generic CDN", CDNConfidence.POSSIBLE),
]

_CONFIDENCE_ORDER = {
    CDNConfidence.NONE: 0,
    CDNConfidence.POSSIBLE: 1,
    CDNConfidence.LIKELY: 2,
    CDNConfidence.CONFIRMED: 3,
}


def _upgrade(current: CDNConfidence, new: CDNConfidence) -> CDNConfidence:
    return new if _CONFIDENCE_ORDER[new] > _CONFIDENCE_ORDER[current] else current


def classify_cdn(
    host: str,
    dns: Optional[DNSInfo] = None,
    http: Optional[HTTPObservation] = None,
) -> CDNClassification:
    """Classify the CDN/edge provider for a host using passive evidence."""
    provider: Optional[str] = None
    confidence = CDNConfidence.NONE
    evidence: List[str] = []

    cnames = [c.lower().rstrip(".") for c in ((dns.cname if dns else None) or [])]
    for cname in cnames:
        for suffix, name, level in CNAME_SIGNATURES:
            if cname == suffix or cname.endswith("." + suffix):
                if provider and provider != name and _CONFIDENCE_ORDER[confidence] >= _CONFIDENCE_ORDER[level]:
                    continue
                provider = name
                confidence = _upgrade(confidence, level)
                evidence.append(f"CNAME {cname} -> {name}")
                break

    if http and http.headers:
        headers = {str(k).lower(): str(v).lower() for k, v in http.headers.items()}
        for header, needle, name, level in HEADER_SIGNATURES:
            value = headers.get(header)
            if value is None:
                continue
            if needle and needle not in value:
                continue
            if provider and provider != name and _CONFIDENCE_ORDER[confidence] > _CONFIDENCE_ORDER[level]:
                continue
            if provider is None or _CONFIDENCE_ORDER[level] >= _CONFIDENCE_ORDER[confidence]:
                provider = name
            confidence = _upgrade(confidence, level)
            evidence.append(f"header {header}: {value[:60]}")

    if provider is None:
        return CDNClassification(provider=None, confidence=CDNConfidence.NONE, evidence=[])
    return CDNClassification(provider=provider, confidence=confidence, evidence=sorted(set(evidence)))


def summarize_cdn(classifications: Dict[str, CDNClassification]) -> Dict[str, int]:
    """Count hosts per CDN provider."""
    summary: Dict[str, int] = {}
    for classification in classifications.values():
        if not classification.provider:
            continue
        summary[classification.provider] = summary.get(classification.provider, 0) + 1
    return dict(sorted(summary.items(), key=lambda kv: (-kv[1], kv[0])))
