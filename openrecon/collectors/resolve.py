"""Hostname -> IP resolution, plus DNS-only subdomain takeover detection."""

from __future__ import annotations

import asyncio
import ipaddress

from openrecon.collectors._platforms import managed_platform
from openrecon.collectors.base import Collector, register
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    CollectorResult,
    Edge,
    EdgeType,
    Finding,
    Node,
    NodeType,
    ScanMode,
    Severity,
)

# CNAME suffix -> the service that owns it. A dangling CNAME into one of these
# is the classic subdomain-takeover primitive.
TAKEOVER_SERVICES: dict[str, str] = {
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 website",
    "cloudfront.net": "AWS CloudFront",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.azure.com": "Azure Cloud Service",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage",
    "azureedge.net": "Azure CDN",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "vercel.app": "Vercel",
    "ghost.io": "Ghost",
    "wpengine.com": "WP Engine",
    "pantheonsite.io": "Pantheon",
    "surge.sh": "Surge",
    "fastly.net": "Fastly",
    "readthedocs.io": "Read the Docs",
    "zendesk.com": "Zendesk",
    "helpscoutdocs.com": "Help Scout",
    "statuspage.io": "Statuspage",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "bigcartel.com": "Big Cartel",
    "unbouncepages.com": "Unbounce",
    "launchrock.com": "LaunchRock",
    "tilda.ws": "Tilda",
    "webflow.io": "Webflow",
    "storage.googleapis.com": "Google Cloud Storage",
    "firebaseapp.com": "Firebase Hosting",
    "web.app": "Firebase Hosting",
}


def _service_for(cname: str) -> str | None:
    low = cname.lower()
    for suffix, service in TAKEOVER_SERVICES.items():
        if suffix in low:
            return service
    return None


@register
class ResolveCollector(Collector):
    name = "resolve"
    stage = "addresses"
    mode = ScanMode.PASSIVE
    description = "Resolve every discovered hostname to IPv4/IPv6 and CNAME targets"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        hosts = graph.hostnames()
        sem = asyncio.Semaphore(self.config.concurrency)

        async def resolve(host: str) -> tuple[str, bool, list[str], str | None]:
            async with sem:
                exists, ips, cname = await self.dns.resolves(host)
            return host, exists, ips, cname

        prov = self.prov("dns")
        live = 0
        third_party: dict[str, str] = {}
        for host, exists, ips, cname in await asyncio.gather(*(resolve(h) for h in hosts)):
            platform = managed_platform(cname)
            if platform:
                third_party[host] = platform
            node_type = (
                NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN
            )
            host_id = Node.make_id(node_type, host)
            result.nodes.append(
                Node.create(
                    node_type,
                    host,
                    attrs={"resolved_ips": ips, "cname": cname, "resolves": exists},
                    provenance=prov,
                    tags={"live"} if exists else {"unresolved"},
                )
            )
            if exists:
                live += 1

            if cname:
                cname_node = Node.create(
                    NodeType.SUBDOMAIN if cname.endswith(graph.meta.target) else NodeType.CLOUD_RESOURCE,
                    cname,
                    attrs={"external": not cname.endswith(graph.meta.target)},
                    provenance=prov,
                )
                result.nodes.append(cname_node)
                result.edges.append(
                    Edge(
                        source=host_id,
                        target=cname_node.id,
                        type=EdgeType.CNAME_TO,
                        provenance=[prov],
                    )
                )

            for ip in ips:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                ip_tags: set[str] = {"private"} if addr.is_private else set()
                if platform:
                    ip_tags.add("shared-infrastructure")
                ip_node = Node.create(
                    NodeType.IP,
                    ip,
                    attrs={
                        "version": addr.version,
                        "private": addr.is_private,
                        "managed_by": platform,
                    },
                    provenance=prov,
                    tags=ip_tags,
                )
                result.nodes.append(ip_node)
                result.edges.append(
                    Edge(
                        source=host_id,
                        target=ip_node.id,
                        type=EdgeType.RESOLVES_TO,
                        provenance=[prov],
                    )
                )
                # Resolved addresses of in-scope hostnames become active-scannable -
                # unless the hostname is served by a managed platform, in which
                # case the address belongs to that platform and scanning it would
                # be scanning someone the operator has no authorization over.
                if (
                    self.ctx.scope is not None
                    and not platform
                    and self.ctx.scope.allows_host(host)
                ):
                    self.ctx.scope.authorize_ip(ip)

        result.stats["hosts_resolved"] = live
        result.stats["hosts_total"] = len(hosts)
        result.stats["managed_platforms"] = third_party
        if third_party:
            platforms = sorted(set(third_party.values()))
            result.findings.append(
                Finding(
                    title=f"{len(third_party)} hostname(s) served by third-party platforms",
                    severity=Severity.INFO,
                    category="attack-surface-sprawl",
                    node_ids=[Node.make_id(NodeType.DOMAIN, graph.meta.target)],
                    description=(
                        "These hostnames resolve into infrastructure operated by "
                        + ", ".join(platforms)
                        + ". Their addresses are excluded from active scanning: they belong to "
                        "the platform, not to you, and owning the domain does not authorize "
                        "testing their servers. Assess these via the platform's own controls "
                        "and its bug bounty or security contact."
                    ),
                    evidence={"hosts": third_party},
                    remediation=(
                        "Review the platform account's own security settings. To include these "
                        "addresses in an active scan you need authorization from the platform, "
                        "declared explicitly under `networks` in the scope file."
                    ),
                    collector=self.name,
                )
            )
        return result


@register
class TakeoverCollector(Collector):
    name = "takeover"
    stage = "addresses"
    mode = ScanMode.PASSIVE
    description = "Detect dangling CNAMEs pointing at unclaimed third-party services"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        candidates: list[tuple[Node, str, str]] = []

        for node in graph.nodes_of(NodeType.SUBDOMAIN, NodeType.DOMAIN):
            cname = node.attrs.get("cname")
            if not cname:
                continue
            service = _service_for(str(cname))
            if service:
                candidates.append((node, str(cname), service))

        if not candidates:
            return result

        sem = asyncio.Semaphore(self.config.concurrency)

        async def check(cname: str) -> bool:
            """True when the CNAME target itself does not resolve - the danger signal."""
            async with sem:
                exists, _, _ = await self.dns.resolves(cname)
            return not exists

        dangling = await asyncio.gather(*(check(c) for _, c, _ in candidates))
        prov = self.prov("dns-cname")

        for (node, cname, service), is_dangling in zip(candidates, dangling, strict=True):
            if not is_dangling:
                continue
            result.nodes.append(
                Node.create(
                    node.type,
                    node.label,
                    provenance=prov,
                    tags={"takeover", "suspicious"},
                )
            )
            result.findings.append(
                Finding(
                    title=f"Possible subdomain takeover: {node.label} -> {service}",
                    severity=Severity.HIGH,
                    category="subdomain-takeover",
                    node_ids=[node.id],
                    description=(
                        f"{node.label} is a CNAME to {cname} ({service}), but that target does "
                        "not resolve. If the underlying resource has been released, an attacker "
                        "can register it and serve content from your domain - including cookies, "
                        "OAuth callbacks, and CSP-trusted scripts."
                    ),
                    evidence={"cname": cname, "service": service},
                    remediation=(
                        f"Either reclaim the {service} resource or delete the DNS record for "
                        f"{node.label}."
                    ),
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    collector=self.name,
                )
            )
        result.stats["takeover_candidates"] = len(candidates)
        return result
