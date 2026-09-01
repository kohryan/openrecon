"""CDN, reverse-proxy, and shared-edge infrastructure detection.

Before attributing an observed service to the target organization, we must
determine whether the IP belongs to a CDN, reverse proxy, shared hosting
provider, cloud edge, or other shared infrastructure. Services running on
a shared CDN edge IP do NOT belong to the scanned organization's origin
infrastructure.

This module provides:
  - Known CDN/edge IP ranges (Cloudflare, Fastly, Akamai, etc.)
  - CNAME-based edge detection
  - HTTP header-based edge detection
  - A classification function that returns asset attribution status
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass
class EdgeAttribution:
    """Result of attributing an IP/hostname to infrastructure."""
    status: str  # "confirmed" | "probable" | "unconfirmed" | "shared-edge"
    provider: str | None = None
    evidence: str = ""
    notes: str = ""


# Known CDN/edge IP ranges. These are published by the vendors themselves.
# Source: official vendor documentation (Cloudflare, Fastly, Akamai, etc.)
CDN_IP_RANGES: dict[str, list[str]] = {
    "Cloudflare": [
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "108.162.192.0/18",
        "131.0.72.0/22",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "172.64.0.0/13",
        "173.245.48.0/20",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ],
    "Fastly": [
        "23.235.32.0/20",
        "43.249.72.0/22",
        "103.244.50.0/24",
        "103.245.222.0/23",
        "103.245.224.0/24",
        "104.156.80.0/20",
        "140.248.64.0/18",
        "140.248.128.0/17",
        "146.75.0.0/17",
        "151.101.0.0/16",
        "157.52.64.0/18",
        "167.82.0.0/17",
        "167.82.128.0/20",
        "167.82.160.0/20",
        "167.82.176.0/20",
        "172.111.64.0/18",
        "185.31.16.0/22",
        "199.27.72.0/21",
        "199.232.0.0/16",
        "2a04:4e40::/32",
        "2a04:4e42::/32",
    ],
    "Akamai": [
        "2.16.0.0/13",
        "23.0.0.0/12",
        "23.32.0.0/11",
        "23.64.0.0/14",
        "23.72.0.0/13",
        "23.192.0.0/11",
        "69.192.0.0/16",
        "88.221.0.0/16",
        "92.122.0.0/15",
        "95.100.0.0/15",
        "96.16.0.0/15",
        "96.6.0.0/15",
        "104.64.0.0/10",
        "118.214.0.0/16",
        "173.222.0.0/15",
        "184.24.0.0/13",
        "184.50.0.0/15",
        "184.84.0.0/14",
        "210.57.0.0/16",
    ],
    "AWS CloudFront": [
        "13.32.0.0/15",
        "13.35.0.0/16",
        "13.54.0.0/15",
        "13.56.0.0/14",
        "13.112.0.0/14",
        "13.124.0.0/14",
        "13.200.0.0/13",
        "13.208.0.0/13",
        "13.224.0.0/14",
        "13.248.0.0/14",
        "13.250.0.0/15",
        "143.204.0.0/16",
        "180.150.0.0/16",
        "204.246.160.0/20",
        "205.251.192.0/19",
        "205.251.240.0/22",
        "205.251.248.0/21",
        "216.137.32.0/19",
        "3.0.0.0/15",
        "3.2.0.0/15",
        "3.8.0.0/13",
        "3.16.0.0/14",
        "3.32.0.0/15",
        "3.48.0.0/14",
        "3.52.0.0/14",
        "52.0.0.0/11",
        "52.64.0.0/12",
        "52.84.0.0/15",
        "52.92.0.0/16",
        "52.94.0.0/15",
        "52.124.0.0/14",
        "54.64.0.0/11",
        "54.192.0.0/12",
        "54.208.0.0/13",
        "54.222.0.0/15",
        "54.230.0.0/16",
        "54.233.0.0/16",
        "54.239.0.0/16",
        "54.240.0.0/12",
        "99.77.0.0/16",
        "99.82.0.0/15",
        "99.84.0.0/14",
        "107.20.0.0/14",
        "120.52.0.0/16",
        "150.222.0.0/16",
        "205.251.224.0/19",
        "216.137.32.0/19",
    ],
    "Azure CDN": [
        "13.64.0.0/11",
        "13.96.0.0/13",
        "13.104.0.0/14",
        "20.36.0.0/14",
        "20.40.0.0/13",
        "20.48.0.0/12",
        "20.64.0.0/10",
        "20.128.0.0/16",
        "40.64.0.0/11",
        "40.96.0.0/12",
        "40.112.0.0/13",
        "40.120.0.0/14",
        "40.124.0.0/16",
        "51.4.0.0/15",
        "51.8.0.0/16",
        "51.12.0.0/15",
        "51.16.0.0/15",
        "51.51.0.0/16",
        "51.103.0.0/16",
        "51.104.0.0/15",
        "51.107.0.0/16",
        "51.116.0.0/16",
        "51.120.0.0/16",
        "51.124.0.0/16",
        "51.132.0.0/16",
        "51.136.0.0/15",
        "51.138.0.0/16",
        "51.140.0.0/14",
        "51.144.0.0/15",
        "52.96.0.0/12",
        "52.112.0.0/14",
        "52.120.0.0/14",
        "52.125.0.0/16",
        "52.126.0.0/15",
        "52.136.0.0/13",
        "52.145.0.0/16",
        "52.146.0.0/15",
        "52.148.0.0/14",
        "52.152.0.0/13",
        "52.160.0.0/11",
        "52.224.0.0/11",
        "104.40.0.0/13",
        "104.208.0.0/13",
        "137.116.0.0/16",
        "137.135.0.0/16",
        "138.91.0.0/16",
        "157.55.0.0/16",
        "157.56.0.0/16",
        "168.61.0.0/16",
        "168.62.0.0/15",
    ],
    "Google Cloud CDN": [
        "34.0.0.0/8",
        "35.184.0.0/13",
        "35.192.0.0/14",
        "35.196.0.0/15",
        "35.198.0.0/16",
        "35.199.0.0/17",
        "35.199.128.0/18",
        "35.199.192.0/19",
        "35.199.224.0/20",
        "35.199.240.0/21",
        "35.199.248.0/22",
        "35.199.252.0/23",
        "35.199.254.0/24",
        "35.200.0.0/13",
        "35.208.0.0/12",
        "35.224.0.0/12",
        "35.240.0.0/13",
        "64.233.160.0/19",
        "66.102.0.0/20",
        "66.249.64.0/19",
        "70.32.128.0/19",
        "72.14.192.0/18",
        "74.125.0.0/16",
        "104.132.0.0/14",
        "104.154.0.0/15",
        "104.196.0.0/14",
        "104.237.160.0/19",
        "107.167.160.0/19",
        "107.178.192.0/18",
        "108.59.80.0/20",
        "108.170.192.0/18",
        "108.177.0.0/17",
        "130.211.0.0/16",
        "142.250.0.0/15",
        "146.148.0.0/17",
        "162.216.148.0/22",
        "162.222.176.0/21",
        "172.217.0.0/16",
        "172.253.0.0/16",
        "173.194.0.0/16",
        "192.178.0.0/15",
        "199.36.154.0/23",
        "199.36.156.0/24",
        "199.192.112.0/22",
        "199.223.232.0/22",
        "207.223.160.0/20",
        "209.85.128.0/17",
        "216.58.192.0/19",
        "216.239.32.0/19",
    ],
    "Sucuri": [
        "185.93.228.0/22",
        "192.124.249.0/24",
        "198.18.0.0/15",
        "208.109.0.0/16",
    ],
    "Imperva/Incapsula": [
        "45.64.64.0/22",
        "62.210.0.0/16",
        "107.154.0.0/16",
        "149.126.72.0/21",
        "185.11.124.0/22",
        "198.143.32.0/19",
        "199.83.128.0/21",
    ],
}

# CNAME suffixes that indicate CDN/edge infrastructure
CDN_CNAME_SUFFIXES: dict[str, str] = {
    "cloudflare.net": "Cloudflare",
    "cloudflare.com": "Cloudflare",
    "cdn.cloudflare.net": "Cloudflare",
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    "akamai.net": "Akamai",
    "akamaiedge.net": "Akamai",
    "akamaihd.net": "Akamai",
    "edgesuite.net": "Akamai",
    "edgekey.net": "Akamai",
    "cloudfront.net": "AWS CloudFront",
    "azureedge.net": "Azure CDN",
    "azurefd.net": "Azure CDN",
    "msecnd.net": "Azure CDN",
    "googleusercontent.com": "Google Cloud CDN",
    "googledomains.com": "Google Cloud DNS",
    "cdn77.org": "CDN77",
    "bunnycdn.net": "BunnyCDN",
    "b-cdn.net": "BunnyCDN",
    "stackpathdns.com": "StackPath",
    "stackpathcdn.com": "StackPath",
    "keycdn.com": "KeyCDN",
    "kxcdn.com": "KeyCDN",
    "sucuri.net": "Sucuri",
    "incapdns.net": "Imperva/Incapsula",
    "incapsula.com": "Imperva/Incapsula",
    "section.io": "Section",
    "section.dev": "Section",
}

# HTTP headers that indicate CDN/edge presence
CDN_HEADER_INDICATORS: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "cf-request-id": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-cdn": "Generic CDN",
    "x-cdn-provider": "Generic CDN",
    "x-fastly-request-id": "Fastly",
    "x-akamai-transformed": "Akamai",
    "x-amz-cf-id": "AWS CloudFront",
    "x-amz-cf-pop": "AWS CloudFront",
    "x-azure-ref": "Azure CDN",
    "x-msedge-ref": "Azure CDN",
    "x-goog-cdn": "Google Cloud CDN",
    "x-goog-generation": "Google Cloud CDN",
}


def _build_cdn_networks() -> dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """Pre-compile CDN IP ranges into network objects for fast lookup."""
    networks: dict[str, list] = {}
    for provider, ranges in CDN_IP_RANGES.items():
        nets = []
        for r in ranges:
            try:
                nets.append(ipaddress.ip_network(r, strict=False))
            except ValueError:
                continue
        networks[provider] = nets
    return networks


_CDN_NETWORKS = _build_cdn_networks()


def is_cdn_ip(ip_str: str) -> tuple[bool, str | None]:
    """Check if an IP belongs to a known CDN/edge provider.
    
    Returns (is_cdn, provider_name).
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, None
    
    for provider, networks in _CDN_NETWORKS.items():
        for net in networks:
            if addr in net:
                return True, provider
    return False, None


def is_cdn_cname(cname: str) -> tuple[bool, str | None]:
    """Check if a CNAME target belongs to a known CDN/edge provider.
    
    Returns (is_cdn, provider_name).
    """
    if not cname:
        return False, None
    low = cname.lower().rstrip(".")
    for suffix, provider in CDN_CNAME_SUFFIXES.items():
        if low == suffix or low.endswith(f".{suffix}"):
            return True, provider
    return False, None


def detect_cdn_from_headers(headers: dict[str, str]) -> tuple[bool, str | None, str]:
    """Detect CDN/edge from HTTP response headers.
    
    Returns (is_cdn, provider_name, evidence).
    """
    for header, provider in CDN_HEADER_INDICATORS.items():
        for key, value in headers.items():
            if key.lower() == header:
                return True, provider, f"Header: {key}: {value[:100]}"
    return False, None, ""


def classify_ip_attribution(
    ip_str: str,
    cname: str | None = None,
    http_headers: dict[str, str] | None = None,
) -> EdgeAttribution:
    """Classify an IP's infrastructure attribution.
    
    Determines whether the IP belongs to:
    - The target organization (confirmed/probable)
    - A CDN/edge/shared provider (shared-edge)
    - Unknown (unconfirmed)
    """
    # Check IP ranges first
    is_cdn, provider = is_cdn_ip(ip_str)
    if is_cdn:
        return EdgeAttribution(
            status="shared-edge",
            provider=provider,
            evidence=f"IP {ip_str} matches {provider} published IP ranges",
            notes=(
                f"This IP belongs to {provider}'s edge infrastructure. "
                "Services observed on this IP may not belong to the target organization's "
                "origin infrastructure. Do not attribute arbitrary services on this edge IP "
                "directly to the origin without additional evidence."
            ),
        )
    
    # Check CNAME
    if cname:
        is_cdn, provider = is_cdn_cname(cname)
        if is_cdn:
            return EdgeAttribution(
                status="shared-edge",
                provider=provider,
                evidence=f"CNAME {cname} matches {provider} infrastructure",
                notes=(
                    f"Hostname resolves via CNAME to {provider}'s infrastructure. "
                    "The IP belongs to the CDN/edge, not the origin."
                ),
            )
    
    # Check HTTP headers
    if http_headers:
        is_cdn, provider, evidence = detect_cdn_from_headers(http_headers)
        if is_cdn:
            return EdgeAttribution(
                status="shared-edge",
                provider=provider,
                evidence=evidence,
                notes=(
                    f"HTTP response indicates {provider} edge infrastructure. "
                    "Services observed may be served by the CDN, not the origin."
                ),
            )
    
    return EdgeAttribution(
        status="unconfirmed",
        provider=None,
        evidence="",
        notes="IP attribution could not be determined from available data.",
    )
