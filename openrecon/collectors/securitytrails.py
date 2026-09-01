"""Passive DNS and subdomain intelligence from SecurityTrails.

SecurityTrails holds one of the largest passive-DNS and historical zone
datasets in existence. It is a *second independent net* over the subdomain pond,
which is exactly what ``openrecon.coverage`` rewards: when CT logs and resolution
both favour conventional names, an API that has watched the zone change for years
surfaces hosts neither of them will - ``old-mail``, ``legacy-api``, hosts that
stopped answering years ago but still resolve from cached glue.

This collector is a ``subdomains``-stage passive source. It requires a
``SECURITYTRAILS_API_KEY`` (free tier available). Without it, it skips cleanly,
exactly like the rest of the keyed collectors. It reads the graph so far and
merges its discoveries as ordinary subdomain nodes, so downstream stages
(resolution, fingerprinting, vuln correlation) pick them up for free.

API reference (v1):
  * ``/v1/domain/{domain}/subdomains`` - current + historical subdomains
  * ``/v1/domain/{domain}/history/dns/a`` - historical A-record observations
"""

from __future__ import annotations

from openrecon.collectors.base import Collector, register
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    CollectorResult,
    Edge,
    EdgeType,
    Node,
    NodeType,
    ScanMode,
)

STS_BASE = "https://api.securitytrails.com/v1"


@register
class SecurityTrailsCollector(Collector):
    name = "securitytrails"
    stage = "subdomains"
    mode = ScanMode.PASSIVE
    description = "Historical subdomains and passive DNS from the SecurityTrails API"
    requires_keys = ("securitytrails",)

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        apex = graph.meta.target
        key = self.config.key("securitytrails") or ""
        headers = {"APIKEY": key, "Accept": "application/json"}
        prov = self.prov("securitytrails")
        domain_id = Node.make_id(NodeType.DOMAIN, apex)

        known = {n.label for n in graph.nodes_of(NodeType.SUBDOMAIN, NodeType.DOMAIN)}

        # 1) Subdomain inventory (current + historical).
        sub = await self.http.get_json(
            f"{STS_BASE}/domain/{apex}/subdomains", headers=headers, retries=2
        )
        subdomains: set[str] = set()
        if sub:
            for name in (sub.get("subdomains") or []):
                host = f"{name}.{apex}".lower()
                if host.endswith(apex):
                    subdomains.add(host)

        # 2) Historical A-record observations: a hostname that once resolved but
        #    no longer answers live DNS still matters for an attack-surface map.
        history = await self.http.get_json(
            f"{STS_BASE}/domain/{apex}/history/dns/a", headers=headers, retries=2
        )
        historical: set[str] = set()
        if history:
            for entry in (history.get("records") or []):
                for value in entry.get("values", []):
                    host = str(value.get("hostname", "")).lower()
                    if host and host.endswith(apex) and host != apex:
                        historical.add(host)

        all_hosts = (subdomains | historical) - known
        all_hosts = {h for h in all_hosts if h.count(".") >= 2 or h != apex}
        if len(all_hosts) > self.config.max_subdomains:
            result.errors.append(
                f"securitytrails: truncated {len(all_hosts)} names to "
                f"max_subdomains={self.config.max_subdomains}"
            )
            all_hosts = set(sorted(all_hosts)[: self.config.max_subdomains])

        from openrecon.collectors.subdomains import _tags_for

        for host in sorted(all_hosts):
            node = Node.create(
                NodeType.SUBDOMAIN,
                host,
                attrs={"apex": apex, "source": "securitytrails"},
                provenance=prov,
                tags=_tags_for(host, apex) | (
                    {"historical"} if host in historical and host not in subdomains else set()
                ),
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

        result.stats["securitytrails_subdomains"] = len(subdomains)
        result.stats["securitytrails_historical"] = len(historical - subdomains if subdomains else historical)
        result.stats["securitytrails_new"] = len(all_hosts)
        return result
