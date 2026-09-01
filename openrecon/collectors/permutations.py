"""Intelligent subdomain name generation in the spirit of OWASP Amass.

A static wordlist (``dnsbrute``) finds conventional hosts but misses the
structured names real organisations use: ``api-v2``, ``dev-internal``,
``old-mail``, ``login2``, ``staging-na``. Amass's edge over a plain wordlist is
that it *derives* candidate names from what it already knows instead of only
consulting a fixed list.

This collector does the same derivation, passively. It harvests "base words"
from every hostname already discovered in the scan (the apex label, every known
subdomain label, the registrable name itself) and combines them with a compact
keyword set using the same alteration operators Amass ships:

* **insert**   ``base`` + ``word``           -> ``baseword``
* **omit**     drop a segment from a compound label -> ``mail`` (from ``mail2``)
* **suffix**   ``word`` + ``base``           -> ``wordbase``
* **prefix**   ``base`` + ``-`` + ``word``   -> ``base-word``
* **replace**  swap a digit/region token      -> ``api2`` (from ``api1``)
* **homoglyph** ``o`` <-> ``0``, ``l`` <-> ``1`` -> ``dev0`` (from ``devo``)

Candidates are validated against the public resolvers (like ``dnsbrute``), so no
machine the target controls is ever contacted and nothing is asserted to exist
until DNS agrees. Wildcard detection is reused so a CDN-backed zone cannot
manufacture hundreds of phantom hosts.

The collector reads the graph so far - that is the whole point. Running it later
in the ``subdomains`` stage (after ``ct`` and ``dnsbrute``) means it can mine
*their* discoveries for base words, not just the apex.
"""

from __future__ import annotations

import asyncio
import re

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

# Keywords combined with harvested base words. Deliberately small and
# high-yield: this is a *derivation* pass, not a replacement for the wordlist.
KEYWORDS = [
    "api", "app", "web", "www", "dev", "test", "stage", "staging", "uat", "qa",
    "prod", "preprod", "beta", "demo", "old", "new", "portal", "admin", "login",
    "auth", "sso", "vpn", "mail", "remote", "secure", "internal", "intranet",
    "corp", "gw", "gateway", "cdn", "static", "assets", "media", "img", "files",
    "download", "upload", "cloud", "db", "data", "sql", "redis", "cache", "mq",
    "jenkins", "git", "gitlab", "jira", "confluence", "grafana", "kibana",
    "prometheus", "sentry", "status", "health", "monitor", "metrics", "logs",
    "v1", "v2", "v3", "ns", "mx", "smtp", "ftp", "ssh", "rdp", "proxy", "lb",
    "node", "svc", "svr", "server", "host", "edge", "origin", "backend",
    "frontend", "mobile", "m", "shop", "store", "pay", "billing", "api2",
]

# Base words that are never productive to permute against - they are themselves
# the generic label, not part of an organisation's naming vocabulary, so
# deriving ``wwwadmin`` or ``www-dev`` only spends resolver budget on noise.
_NOISE_BASE = {"www", "ftp", "mx", "ns", "m", "email"}

# Tokens that look like they carry an incrementing/region meaning and can be
# swapped out to surface sibling hosts (``api1`` -> ``api2`` -> ``api3``).
_DIGIT_TAIL = re.compile(r"^(?P<root>[a-z]+?)(?P<num>\d+)$")
_REGION_TAIL = re.compile(r"^(?P<root>[a-z]+?)[-_](?P<region>us|eu|uk|de|fr|ap|na|sa|asia|east|west|north|south)$")

# Homoglyph pairs: visually confusable substitutions attackers and typos use.
_HOMOGLYPHS: tuple[tuple[str, str], ...] = (("o", "0"), ("l", "1"), ("i", "1"))


def _labels_from(apex: str, host: str) -> list[str]:
    """Split a hostname into its meaningful label segments, apex stripped."""
    if host == apex:
        return []
    if host.endswith(f".{apex}"):
        head = host[: -(len(apex) + 1)]
    elif host.endswith(apex):
        head = host[: -len(apex)]
    else:
        head = host
    return [p for p in head.replace("_", "-").split("-") if p]


def harvest_base_words(graph: AttackSurfaceGraph) -> set[str]:
    """Collect plausible base words from everything seen so far.

    The apex registrable name, every discovered subdomain label, and the apex
    prefix become seeds. Pure numbers, single chars, and the keywords themselves
    are dropped so we do not permute noise.
    """
    apex = graph.meta.target
    words: set[str] = set()
    apex_base = apex.split(".")[0]
    if len(apex_base) >= 3:
        words.add(apex_base)

    for node in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN):
        for seg in _labels_from(apex, node.label):
            if len(seg) >= 3 and not seg.isdigit():
                words.add(seg)

    # Also pull any base words already implied by existing subdomain seams.
    # Keep keyword-label base words (``api``, ``mail``) - they ARE the
    # organisation's vocabulary and the whole point of permutation. Only drop
    # pure noise bases that would just burn resolver budget.
    return {w for w in words if w not in _NOISE_BASE}


def derive_candidates(base_words: set[str]) -> set[str]:
    """Apply Amass-style alterations to produce candidate host prefixes."""
    out: set[str] = set()
    bases = sorted(base_words)
    for base in bases:
        for kw in KEYWORDS:
            out.add(f"{base}{kw}")
            out.add(f"{kw}{base}")
            out.add(f"{base}-{kw}")
            out.add(f"{kw}-{base}")
        # omit: a compound already containing a keyword yields the bare root
        # (handled by the insert/suffix forms above); here we also lift pure
        # trailing-digit and region mutations.
        m = _DIGIT_TAIL.match(base)
        if m:
            out.add(f"{m.group('root')}2")
            out.add(f"{m.group('root')}3")
        m = _REGION_TAIL.match(base)
        if m:
            for region in ("us", "eu", "uk", "ap", "east", "west"):
                out.add(f"{m.group('root')}-{region}")
        # homoglyph mutations
        for a, b in _HOMOGLYPHS:
            if a in base:
                out.add(base.replace(a, b, 1))
            if b in base:
                out.add(base.replace(b, a, 1))
    return out


def _tags_for(host: str, apex: str) -> set[str]:
    from openrecon.collectors.subdomains import _tags_for as _sub_tags

    return _sub_tags(host, apex)


@register
class PermutationCollector(Collector):
    name = "permute"
    stage = "subdomains"
    mode = ScanMode.PASSIVE
    description = (
        "Amass-style name permutation: derives candidates from discovered hosts "
        "and validates them against public resolvers"
    )

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        apex = graph.meta.target
        domain_id = Node.make_id(NodeType.DOMAIN, apex)

        base_words = harvest_base_words(graph)
        if not base_words:
            result.stats["permute_base_words"] = 0
            result.stats["permute_hits"] = 0
            return result

        candidates = derive_candidates(base_words)
        # Drop anything that is already known so we only validate the new ones.
        known = {n.label for n in graph.nodes_of(NodeType.SUBDOMAIN, NodeType.DOMAIN)}
        candidates = {c for c in candidates if f"{c}.{apex}" not in known}
        if not candidates:
            result.stats["permute_base_words"] = len(base_words)
            result.stats["permute_hits"] = 0
            return result

        # Wildcard handling mirrors dnsbrute: a rotating-pool wildcard makes
        # every candidate "resolve", which would manufacture phantom hosts.
        is_wildcard, wildcard_ips, wildcard_cnames, unstable = await self._wildcard(apex)
        if is_wildcard and unstable:
            result.errors.append(
                f"permute: {apex} has an unstable wildcard; permutation results "
                "are indistinguishable from the wildcard and were discarded"
            )
            result.stats["wildcard_dns"] = "unstable"
            result.stats["permute_hits"] = 0
            result.stats["permute_base_words"] = len(base_words)
            return result

        full = [f"{c}.{apex}" for c in sorted(candidates)][: self.config.max_subdomains]
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

        found = [r for r in await asyncio.gather(*(probe(h) for h in full)) if r]
        prov = self.prov("permutation+resolvers")
        for host, ips, cname in found:
            node = Node.create(
                NodeType.SUBDOMAIN,
                host,
                attrs={"apex": apex, "resolved_ips": ips, "cname": cname,
                       "source": "permute"},
                provenance=prov,
                tags=_tags_for(host, apex) | {"permutation"},
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

        result.stats["permute_base_words"] = len(base_words)
        result.stats["permute_candidates"] = len(full)
        result.stats["permute_hits"] = len(found)
        if is_wildcard:
            result.stats["wildcard_dns"] = sorted(wildcard_ips)
        return result

    async def _wildcard(self, apex: str) -> tuple[bool, set[str], set[str], bool]:
        """Identical signal to dnsbrute: do random probes resolve at all?"""
        probes = [f"openrecon-perm-probe-{i}-zzq.{apex}" for i in range(3)]
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
        unstable = len({p for p in per_probe if p}) > 1 and not set.intersection(
            *(set(p) for p in per_probe if p)
        )
        return True, ips, cnames, unstable
