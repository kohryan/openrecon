"""Network attribution: IP -> announced prefix -> ASN -> operator.

Uses Team Cymru's public IP-to-ASN DNS interface, which needs no API key and no
traffic to the target. Detects hosting sprawl and shadow IT along the way.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections import Counter

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

ORIGIN_V4 = "origin.asn.cymru.com"
ORIGIN_V6 = "origin6.asn.cymru.com"
ASN_INFO = "asn.cymru.com"

# Providers where "one more account" is how shadow IT happens.
CLOUD_HINTS = {
    "amazon": "AWS",
    "aws": "AWS",
    "google": "GCP",
    "microsoft": "Azure",
    "azure": "Azure",
    "digitalocean": "DigitalOcean",
    "linode": "Akamai/Linode",
    "akamai": "Akamai",
    "cloudflare": "Cloudflare",
    "hetzner": "Hetzner",
    "ovh": "OVH",
    "vultr": "Vultr",
    "oracle": "OCI",
    "alibaba": "Alibaba Cloud",
    "fastly": "Fastly",
}


def _reverse_pointer(ip: str) -> tuple[str, str] | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback:
        return None
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + "." + ORIGIN_V4, ORIGIN_V4
    nibbles = ".".join(reversed(addr.exploded.replace(":", "")))
    return f"{nibbles}.{ORIGIN_V6}", ORIGIN_V6


@register
class AsnCollector(Collector):
    name = "asn"
    stage = "network"
    mode = ScanMode.PASSIVE
    description = "Map IPs to announced prefixes, ASNs, and hosting providers (Team Cymru)"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        ips = [n.label for n in graph.nodes_of(NodeType.IP) if not n.attrs.get("private")]
        if not ips:
            return result

        sem = asyncio.Semaphore(self.config.concurrency)

        async def origin(ip: str) -> tuple[str, list[str]]:
            pointer = _reverse_pointer(ip)
            if pointer is None:
                return ip, []
            async with sem:
                return ip, await self.dns.query(pointer[0], "TXT")

        lookups = await asyncio.gather(*(origin(ip) for ip in ips))
        asn_numbers: set[str] = set()
        prov = self.prov("cymru")
        provider_counter: Counter[str] = Counter()

        for ip, answers in lookups:
            if not answers:
                continue
            # "13335 | 104.16.0.0/12 | US | arin | 2011-10-14"
            fields = [f.strip() for f in answers[0].split("|")]
            if len(fields) < 3:
                continue
            asn = fields[0].split()[0]
            prefix, country = fields[1], fields[2]
            asn_numbers.add(asn)

            ip_id = Node.make_id(NodeType.IP, ip)
            result.nodes.append(
                Node.create(
                    NodeType.IP,
                    ip,
                    attrs={"asn": asn, "prefix": prefix, "country": country},
                    provenance=prov,
                )
            )
            net_node = Node.create(
                NodeType.NETBLOCK,
                prefix,
                attrs={"asn": asn, "country": country},
                provenance=prov,
            )
            result.nodes.append(net_node)
            result.edges.append(
                Edge(source=ip_id, target=net_node.id, type=EdgeType.IN_NETBLOCK, provenance=[prov])
            )

        # Fix the order once: gathering over the set and zipping against a
        # differently-ordered sequence would attach each operator name to the
        # wrong ASN.
        ordered_asns = sorted(asn_numbers)
        info = await asyncio.gather(
            *(self.dns.query(f"AS{a}.{ASN_INFO}", "TXT") for a in ordered_asns)
        )
        for asn, answers in zip(ordered_asns, info, strict=True):
            # "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
            fields = [f.strip() for f in (answers[0].split("|") if answers else [])]
            org = fields[-1] if len(fields) >= 5 else f"AS{asn}"
            country = fields[1] if len(fields) >= 2 else None
            provider = next(
                (label for hint, label in CLOUD_HINTS.items() if hint in org.lower()), None
            )
            if provider:
                provider_counter[provider] += 1

            asn_node = Node.create(
                NodeType.ASN,
                asn,
                label=f"AS{asn} {org}",
                attrs={
                    "asn": asn,
                    "organization": org,
                    "country": country,
                    "registry": fields[2] if len(fields) >= 3 else None,
                    "provider": provider,
                },
                provenance=prov,
                tags={"cloud"} if provider else {"hosting"},
            )
            result.nodes.append(asn_node)
            for net in [n for n in result.nodes if n.type is NodeType.NETBLOCK and n.attrs.get("asn") == asn]:
                result.edges.append(
                    Edge(
                        source=net.id,
                        target=asn_node.id,
                        type=EdgeType.ANNOUNCED_BY,
                        provenance=[prov],
                    )
                )

        result.findings.extend(self._sprawl_findings(graph, asn_numbers, provider_counter))
        result.stats["asns"] = sorted(asn_numbers)
        result.stats["providers"] = dict(provider_counter)
        return result

    def _sprawl_findings(
        self,
        graph: AttackSurfaceGraph,
        asn_numbers: set[str],
        providers: Counter[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        domain_id = Node.make_id(NodeType.DOMAIN, graph.meta.target)
        if len(providers) >= 3:
            findings.append(
                Finding(
                    title=f"Infrastructure spread across {len(providers)} hosting providers",
                    severity=Severity.LOW,
                    category="attack-surface-sprawl",
                    node_ids=[domain_id],
                    description=(
                        "Assets on many providers usually means several teams provisioning "
                        "independently - the classic precondition for forgotten, unpatched hosts."
                    ),
                    evidence={"providers": dict(providers)},
                    remediation="Inventory each provider account and bring them under one asset register.",
                    collector=self.name,
                )
            )
        if len(asn_numbers) >= 8:
            findings.append(
                Finding(
                    title=f"Assets announced by {len(asn_numbers)} distinct ASNs",
                    severity=Severity.INFO,
                    category="attack-surface-sprawl",
                    node_ids=[domain_id],
                    evidence={"asns": sorted(asn_numbers)},
                    collector=self.name,
                )
            )
        return findings
