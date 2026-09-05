"""Cloud asset identification (asset intelligence only).

Detects cloud-related hostnames and CNAME targets such as ``*.amazonaws.com``,
``*.azurewebsites.net`` or ``*.storage.googleapis.com``.  SUBDOMAINX never tests
whether a cloud resource is reachable, misconfigured or vulnerable - it only
records that the asset exists.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..models import CloudAsset, DNSInfo, HTTPObservation

#: (CNAME suffix, provider, service, confidence)
CLOUD_SIGNATURES: List[Tuple[str, str, str, int]] = [
    ("s3.amazonaws.com", "AWS", "S3 bucket website", 90),
    ("s3-website", "AWS", "S3 website endpoint", 90),
    ("s3.", "AWS", "S3 endpoint", 80),
    ("elb.amazonaws.com", "AWS", "Elastic Load Balancer", 90),
    ("elasticbeanstalk.com", "AWS", "Elastic Beanstalk", 90),
    ("cloudfront.net", "AWS", "CloudFront distribution", 90),
    ("execute-api.amazonaws.com", "AWS", "API Gateway", 90),
    ("lambda-url", "AWS", "Lambda function URL", 80),
    ("amazonaws.com", "AWS", "AWS resource", 70),
    ("azurewebsites.net", "Azure", "App Service", 90),
    ("azure-mobile.net", "Azure", "Mobile Service", 80),
    ("blob.core.windows.net", "Azure", "Blob Storage", 95),
    ("file.core.windows.net", "Azure", "File Storage", 95),
    ("queue.core.windows.net", "Azure", "Queue Storage", 95),
    ("table.core.windows.net", "Azure", "Table Storage", 95),
    ("database.windows.net", "Azure", "SQL Database", 90),
    ("azurefd.net", "Azure", "Front Door", 90),
    ("azureedge.net", "Azure", "CDN", 85),
    ("cloudapp.azure.com", "Azure", "Virtual Machine", 85),
    ("trafficmanager.net", "Azure", "Traffic Manager", 80),
    ("azure-api.net", "Azure", "API Management", 90),
    ("storage.googleapis.com", "Google Cloud", "Cloud Storage", 95),
    ("storage.cloud.google.com", "Google Cloud", "Cloud Storage", 90),
    ("cloudfunctions.net", "Google Cloud", "Cloud Functions", 90),
    ("appspot.com", "Google Cloud", "App Engine", 90),
    ("run.app", "Google Cloud", "Cloud Run", 90),
    ("cloud.goog", "Google Cloud", "Google Cloud", 80),
    ("firebaseapp.com", "Google Cloud", "Firebase Hosting", 90),
    ("web.app", "Google Cloud", "Firebase Hosting", 85),
    ("digitaloceanspaces.com", "DigitalOcean", "Spaces object storage", 90),
    ("ondigitalocean.app", "DigitalOcean", "App Platform", 85),
    ("digitalocean.com", "DigitalOcean", "DigitalOcean resource", 60),
    ("herokuapp.com", "Heroku", "Heroku app", 90),
    ("herokudns.com", "Heroku", "Heroku DNS", 85),
    ("herokussl.com", "Heroku", "Heroku SSL", 85),
    ("netlify.app", "Netlify", "Netlify site", 90),
    ("vercel.app", "Vercel", "Vercel deployment", 90),
    ("github.io", "GitHub", "GitHub Pages", 85),
    ("githubusercontent.com", "GitHub", "GitHub content", 70),
    ("cloudflareworkers.com", "Cloudflare", "Workers", 85),
    ("workers.dev", "Cloudflare", "Workers", 85),
    ("r2.cloudflarestorage.com", "Cloudflare", "R2 storage", 90),
    ("pages.dev", "Cloudflare", "Cloudflare Pages", 85),
    ("linodeobjects.com", "Linode", "Object Storage", 85),
    ("linodeusercontent.com", "Linode", "Linode resource", 70),
    ("scw.cloud", "Scaleway", "Scaleway resource", 75),
    ("oraclecloud.com", "Oracle Cloud", "Oracle resource", 75),
    ("oraclecloudapps.com", "Oracle Cloud", "Oracle Apps", 80),
    ("aliyuncs.com", "Alibaba Cloud", "Alibaba resource", 70),
    ("ibmcloud.com", "IBM Cloud", "IBM resource", 70),
    ("myqcloud.com", "Tencent Cloud", "Tencent resource", 70),
]


def detect_cloud_asset(
    host: str,
    dns: Optional[DNSInfo] = None,
    http: Optional[HTTPObservation] = None,
) -> Optional[CloudAsset]:
    """Return a :class:`CloudAsset` when cloud evidence is present.

    CNAME targets are the strongest and most reliable passive indicator, so they
    are evaluated first.
    """
    cnames = [c.lower().rstrip(".") for c in ((dns.cname if dns else None) or [])]
    for cname in cnames:
        for suffix, provider, service, confidence in CLOUD_SIGNATURES:
            if cname == suffix or cname.endswith("." + suffix) or (suffix in cname and suffix.endswith(".")):
                return CloudAsset(
                    provider=provider,
                    service=service,
                    cname=cname,
                    evidence=f"CNAME {host} -> {cname}",
                    confidence=confidence,
                )

    # Fall back to the hostname itself (e.g. "assets.s3.example.com" style names
    # or hosts that *are* cloud endpoints).
    lowered = (host or "").lower()
    for suffix, provider, service, confidence in CLOUD_SIGNATURES:
        if lowered.endswith("." + suffix):
            return CloudAsset(
                provider=provider,
                service=service,
                cname=lowered,
                evidence=f"hostname ends with {suffix}",
                confidence=max(50, confidence - 20),
            )

    headers = {str(k).lower(): str(v).lower() for k, v in ((http.headers if http else None) or {}).items()}
    for header, needle, provider, service in (
        ("x-amz-request-id", "", "AWS", "AWS resource"),
        ("x-amz-bucket-region", "", "AWS", "S3 bucket"),
        ("x-ms-request-id", "", "Azure", "Azure resource"),
        ("x-goog-generation", "", "Google Cloud", "Cloud Storage"),
        ("x-guploader-uploadid", "", "Google Cloud", "Google Storage"),
        ("server", "awselb", "AWS", "Elastic Load Balancer"),
        ("server", "google frontend", "Google Cloud", "Google Frontend"),
    ):
        value = headers.get(header)
        if value is None:
            continue
        if needle and needle not in value:
            continue
        return CloudAsset(
            provider=provider,
            service=service,
            cname=cnames[0] if cnames else None,
            evidence=f"header {header}: {value[:60]}",
            confidence=65,
        )
    return None


def summarize_cloud(assets: List[CloudAsset]) -> Dict[str, int]:
    """Count detected cloud assets per provider."""
    summary: Dict[str, int] = {}
    for asset in assets or []:
        if not asset or not asset.provider:
            continue
        summary[asset.provider] = summary.get(asset.provider, 0) + 1
    return dict(sorted(summary.items(), key=lambda kv: (-kv[1], kv[0])))
