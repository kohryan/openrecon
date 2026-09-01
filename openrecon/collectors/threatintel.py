"""Reputation and threat intelligence for discovered assets.

URLhaus (abuse.ch) needs no key and answers the question that matters most:
is any of my infrastructure already being used to serve malware or phishing?
VirusTotal adds multi-engine reputation when a key is present.
"""

from __future__ import annotations

import asyncio

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

URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
VT_DOMAIN = "https://www.virustotal.com/api/v3/domains/{domain}"


@register
class UrlhausCollector(Collector):
    name = "urlhaus"
    stage = "threat"
    mode = ScanMode.PASSIVE
    description = "Check hostnames and IPs against abuse.ch URLhaus malware URL feed"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        assets = [n for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN, NodeType.IP)]
        assets = [n for n in assets if not n.attrs.get("private")][:200]
        sem = asyncio.Semaphore(5)
        prov = self.prov("urlhaus")

        async def lookup(node: Node) -> tuple[Node, dict | None]:
            async with sem:
                resp = await self.http.request(
                    "POST", URLHAUS_HOST, data={"host": node.label}, retries=1
                )
            if resp is None or resp.status_code >= 400:
                return node, None
            try:
                return node, resp.json()
            except ValueError:
                return node, None

        for node, data in await asyncio.gather(*(lookup(n) for n in assets)):
            if not data or data.get("query_status") != "ok":
                continue
            urls = data.get("urls") or []
            online = [u for u in urls if u.get("url_status") == "online"]
            if not urls:
                continue

            threat = Node.create(
                NodeType.THREAT,
                f"urlhaus:{node.label}",
                label=f"URLhaus: {len(urls)} malicious URL(s)",
                attrs={
                    "asset": node.label,
                    "total_urls": len(urls),
                    "online_urls": len(online),
                    "blacklists": data.get("blacklists"),
                    "sample": [u.get("url") for u in urls[:5]],
                },
                provenance=prov,
                tags={"malicious"},
            )
            result.nodes.append(threat)
            result.nodes.append(
                Node.create(node.type, node.label, provenance=prov, tags={"suspicious", "malicious"})
            )
            result.edges.append(
                Edge(source=node.id, target=threat.id, type=EdgeType.FLAGGED_AS, provenance=[prov])
            )
            result.findings.append(
                Finding(
                    title=f"{node.label} is listed in URLhaus with {len(urls)} malicious URL(s)",
                    severity=Severity.CRITICAL if online else Severity.HIGH,
                    category="threat-intelligence",
                    node_ids=[node.id, threat.id],
                    description=(
                        "Infrastructure attributed to this asset is serving, or has served, "
                        "malware or phishing content. Either it is compromised, or someone is "
                        "abusing a service you host."
                    ),
                    evidence={
                        "total_urls": len(urls),
                        "online_urls": len(online),
                        "sample": [u.get("url") for u in urls[:3]],
                    },
                    remediation=(
                        "Investigate the host for compromise, remove the content, and request "
                        "delisting once clean."
                    ),
                    references=["https://urlhaus.abuse.ch/"],
                    collector=self.name,
                )
            )
        return result


@register
class VirusTotalCollector(Collector):
    name = "virustotal"
    stage = "threat"
    mode = ScanMode.PASSIVE
    description = "Multi-engine domain reputation and passive DNS from VirusTotal"
    requires_keys = ("virustotal",)

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        headers = {"x-apikey": self.config.key("virustotal") or ""}
        hosts = graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)[:50]
        sem = asyncio.Semaphore(4)
        prov = self.prov("virustotal")

        async def lookup(node: Node) -> tuple[Node, dict | None]:
            async with sem:
                return node, await self.http.get_json(
                    VT_DOMAIN.format(domain=node.label), headers=headers, retries=1
                )

        for node, data in await asyncio.gather(*(lookup(n) for n in hosts)):
            attributes = ((data or {}).get("data") or {}).get("attributes") or {}
            stats = attributes.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            if malicious == 0 and suspicious == 0:
                continue
            result.nodes.append(
                Node.create(
                    node.type,
                    node.label,
                    attrs={"vt_malicious": malicious, "vt_suspicious": suspicious},
                    provenance=prov,
                    tags={"suspicious"} | ({"malicious"} if malicious >= 3 else set()),
                )
            )
            result.findings.append(
                Finding(
                    title=f"{node.label} flagged by {malicious} security vendors",
                    severity=Severity.HIGH if malicious >= 3 else Severity.MEDIUM,
                    category="threat-intelligence",
                    node_ids=[node.id],
                    evidence={"stats": stats, "reputation": attributes.get("reputation")},
                    remediation="Investigate the host and request re-analysis once remediated.",
                    collector=self.name,
                )
            )
        return result
