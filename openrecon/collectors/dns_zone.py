"""Active DNS checks against the target's own authoritative nameservers."""

from __future__ import annotations

import asyncio

import dns.exception
import dns.query
import dns.zone

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


@register
class ZoneTransferCollector(Collector):
    name = "axfr"
    stage = "dns"
    mode = ScanMode.ACTIVE
    description = "Attempt an AXFR zone transfer against each authoritative nameserver"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        apex = graph.meta.target
        nameservers = [n.label for n in graph.nodes_of(NodeType.NAMESERVER)]
        if not nameservers:
            nameservers = [ns.rstrip(".") for ns in await self.dns.query(apex, "NS")]

        allowed = self.targets_in_scope(nameservers)
        refused = set(nameservers) - set(allowed)
        if refused:
            result.errors.append(f"axfr: skipped out-of-scope nameservers: {sorted(refused)}")

        domain_id = Node.make_id(NodeType.DOMAIN, apex)
        prov = self.prov("axfr")

        for ns in allowed:
            ips = await self.dns.query(ns, "A")
            for ip in ips[:1]:
                names = await self._try_axfr(ip, apex)
                if names is None:
                    continue
                result.findings.append(
                    Finding(
                        title=f"Zone transfer (AXFR) allowed on {ns}",
                        severity=Severity.HIGH,
                        category="dns-exposure",
                        node_ids=[domain_id, Node.make_id(NodeType.NAMESERVER, ns)],
                        description=(
                            f"{ns} served the full {apex} zone to an unauthenticated client, "
                            f"disclosing {len(names)} records including internal hostnames."
                        ),
                        evidence={"nameserver": ns, "records_disclosed": len(names),
                                  "sample": sorted(names)[:20]},
                        remediation="Restrict AXFR with allow-transfer to your secondary NS only.",
                        collector=self.name,
                    )
                )
                for host in sorted(names)[: self.config.max_subdomains]:
                    if not host.endswith(apex) or host == apex:
                        continue
                    node = Node.create(
                        NodeType.SUBDOMAIN,
                        host,
                        attrs={"apex": apex, "source": "axfr"},
                        provenance=prov,
                        tags={"zone-transfer"},
                    )
                    result.nodes.append(node)
                    result.edges.append(
                        Edge(
                            source=domain_id,
                            target=node.id,
                            type=EdgeType.HAS_SUBDOMAIN,
                            provenance=[prov],
                        )
                    )
        return result

    async def _try_axfr(self, ip: str, apex: str) -> set[str] | None:
        """dnspython has no async AXFR helper, so run the blocking one off-thread."""

        def sync_xfr() -> dns.zone.Zone:
            return dns.zone.from_xfr(
                dns.query.xfr(ip, apex, timeout=self.config.dns_timeout, lifetime=20)
            )

        loop = asyncio.get_running_loop()
        try:
            zone = await asyncio.wait_for(
                loop.run_in_executor(None, sync_xfr), timeout=self.config.dns_timeout * 4
            )
        except (TimeoutError, dns.exception.DNSException, OSError):
            return None
        return {str(name.derelativize(zone.origin)).rstrip(".") for name in zone.nodes}
