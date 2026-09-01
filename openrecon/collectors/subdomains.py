"""Subdomain discovery from certificate transparency plus resolution validation.

Two collectors live here:
  * `ct` - reads public CT logs (crt.sh, certspotter). Pure OSINT.
  * `dnsbrute` - resolves a wordlist against public recursive resolvers.

Both stay passive: neither sends a packet to target-owned infrastructure.
"""

from __future__ import annotations

import asyncio
from typing import Any

from openrecon.collectors._ct import fetch_ct, names_from
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

# Names that usually mean "not production" - useful signal for the risk engine.
SENSITIVE_PREFIXES = {
    "dev", "test", "staging", "stage", "uat", "qa", "sandbox", "demo", "preprod",
    "internal", "intranet", "corp", "vpn", "admin", "jenkins", "gitlab", "git",
    "jira", "confluence", "grafana", "kibana", "prometheus", "phpmyadmin", "db",
    "backup", "old", "legacy", "beta", "debug", "mail", "smtp", "ftp", "sftp",
    "api", "gateway", "auth", "sso", "login", "portal", "s3", "minio", "registry",
}

DEFAULT_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure",
    "vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns", "ww1", "host", "support",
    "dev", "web", "bbs", "mx", "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2",
    "gw", "admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov", "2tty", "vps",
    "govyty", "hgfgdf", "news", "1rer", "lkjkui", "staging", "stage", "beta", "demo",
    "jenkins", "gitlab", "git", "jira", "confluence", "grafana", "kibana", "prometheus",
    "sentry", "vault", "consul", "nomad", "k8s", "kubernetes", "rancher", "harbor",
    "registry", "docker", "nexus", "artifactory", "sonar", "phpmyadmin", "pma", "db",
    "database", "mysql", "postgres", "redis", "mongo", "elastic", "es", "search",
    "internal", "intranet", "corp", "vpn2", "sso", "auth", "login", "id", "account",
    "accounts", "billing", "payment", "pay", "checkout", "static", "assets", "img",
    "images", "media", "video", "download", "downloads", "files", "share", "backup",
    "backups", "old", "legacy", "archive", "uat", "qa", "sandbox", "preprod", "prod",
    "monitor", "monitoring", "status", "health", "metrics", "logs", "log", "syslog",
    "smtp2", "imap", "pop", "pop3", "ldap", "ad", "dc", "print", "proxy", "gateway",
    "router", "firewall", "switch", "nas", "storage", "s3", "minio", "swift", "ceph",
]


def _tags_for(host: str, apex: str) -> set[str]:
    label = host[: -(len(apex) + 1)] if host != apex else ""
    parts = set(label.split("."))
    tags = {p for p in parts & SENSITIVE_PREFIXES}
    if tags & {"dev", "test", "staging", "stage", "uat", "qa", "sandbox", "demo", "preprod"}:
        tags.add("non-production")
    if tags & {"admin", "jenkins", "gitlab", "git", "jira", "confluence", "grafana", "kibana",
               "phpmyadmin", "vpn", "internal", "intranet", "registry"}:
        tags.add("sensitive-service")
    return tags


def _subdomain_nodes(hosts: set[str], apex: str, prov: Any) -> list[Node]:
    nodes = []
    for host in sorted(hosts):
        if host == apex:
            continue
        nodes.append(
            Node.create(
                NodeType.SUBDOMAIN,
                host,
                attrs={"apex": apex},
                provenance=prov,
                tags=_tags_for(host, apex),
            )
        )
    return nodes


@register
class CertificateTransparencyCollector(Collector):
    name = "ct"
    stage = "subdomains"
    mode = ScanMode.PASSIVE
    description = "Subdomains from public certificate transparency logs"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        apex = graph.meta.target
        records, errors = await fetch_ct(self.http, apex, token=self.config.key("certspotter"))
        result.errors.extend(errors)

        names = names_from(records, apex)
        if len(names) > self.config.max_subdomains:
            result.errors.append(
                f"ct: truncated {len(names)} names to max_subdomains={self.config.max_subdomains}"
            )
            names = set(sorted(names)[: self.config.max_subdomains])

        domain_id = Node.make_id(NodeType.DOMAIN, apex)
        prov = self.prov("crt.sh+certspotter")
        for node in _subdomain_nodes(names, apex, prov):
            result.nodes.append(node)
            result.edges.append(
                Edge(
                    source=domain_id,
                    target=node.id,
                    type=EdgeType.HAS_SUBDOMAIN,
                    provenance=[prov],
                )
            )

        result.stats["ct_names"] = len(names)
        result.stats["ct_certificates"] = len(records)
        return result


@register
class DnsBruteCollector(Collector):
    name = "dnsbrute"
    stage = "subdomains"
    mode = ScanMode.PASSIVE
    description = "Resolve a wordlist of common hostnames against public resolvers"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        apex = graph.meta.target
        domain_id = Node.make_id(NodeType.DOMAIN, apex)

        is_wildcard, wildcard_ips, wildcard_cnames, unstable = await self._wildcard(apex)

        if is_wildcard and unstable:
            # Every name would appear to resolve and we cannot tell which are
            # real. Reporting 150 invented hosts is worse than reporting none.
            result.errors.append(
                f"dnsbrute: {apex} has wildcard DNS with a rotating address pool - "
                "wordlist results are indistinguishable from the wildcard and were discarded"
            )
            result.stats["wildcard_dns"] = "unstable"
            result.stats["bruteforce_hits"] = 0
            return result

        candidates = [f"{w}.{apex}" for w in DEFAULT_WORDLIST]
        sem = asyncio.Semaphore(self.config.concurrency)

        async def probe(host: str) -> tuple[str, list[str], str | None] | None:
            async with sem:
                exists, ips, cname = await self.dns.resolves(host)
            if not exists:
                return None
            if is_wildcard:
                if cname and cname.lower() in wildcard_cnames:
                    return None
                if ips and set(ips).issubset(wildcard_ips):
                    return None
                if not ips and not cname:
                    return None
            return host, ips, cname

        found = [r for r in await asyncio.gather(*(probe(h) for h in candidates)) if r]
        prov = self.prov("dns-wordlist")
        for host, ips, cname in found:
            node = Node.create(
                NodeType.SUBDOMAIN,
                host,
                attrs={"apex": apex, "resolved_ips": ips, "cname": cname},
                provenance=prov,
                tags=_tags_for(host, apex),
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
        result.stats["bruteforce_hits"] = len(found)
        result.stats["wildcard_dns"] = sorted(wildcard_ips) if is_wildcard else []
        return result

    async def _wildcard(self, apex: str) -> tuple[bool, set[str], set[str], bool]:
        """Detect wildcard DNS. Returns (is_wildcard, ips, cnames, unstable).

        Comparing the IP sets of two random probes only works when the wildcard
        answers with a stable address. Anything behind a CDN - which is most
        wildcards now - answers from a rotating edge pool, the intersection comes
        back empty, and every word in the list is recorded as a live host. The
        reliable signal is far simpler: if names nobody would ever register
        resolve at all, the zone has a wildcard.
        """
        probes = [f"openrecon-wildcard-probe-{i}-zzq.{apex}" for i in range(3)]
        answers = await asyncio.gather(*(self.dns.resolves(p) for p in probes))

        resolved = [a for a in answers if a[0]]
        if len(resolved) < len(probes):
            return False, set(), set(), False

        ips: set[str] = set()
        cnames: set[str] = set()
        per_probe: list[frozenset[str]] = []
        for _exists, probe_ips, cname in resolved:
            ips |= set(probe_ips)
            per_probe.append(frozenset(probe_ips))
            if cname:
                cnames.add(cname.lower())

        # An address pool that differs between probes cannot be used to tell a
        # real host from a wildcard hit, so we say so instead of guessing.
        unstable = len({p for p in per_probe if p}) > 1 and not set.intersection(
            *(set(p) for p in per_probe if p)
        )
        return True, ips, cnames, unstable
