"""Hermetic tests for the permutation and SecurityTrails collectors.

Nothing here touches the network. DNS resolution is stubbed so we can assert
which candidates the permutation collector would probe, and the SecurityTrails
HTTP layer is stubbed so we can assert parsing and merge behaviour.
"""

from __future__ import annotations

from openrecon.collectors.base import CollectorContext
from openrecon.collectors.permutations import (
    derive_candidates,
    harvest_base_words,
)
from openrecon.collectors.securitytrails import SecurityTrailsCollector
from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Node, NodeType

# ------------------------------------------------------------------- pure logic


def test_harvest_pulls_base_words_from_discovered_hosts():
    graph = AttackSurfaceGraph.seed("example.com")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "api.example.com"))
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "dev-mail.example.com"))
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "www.example.com"))
    words = harvest_base_words(graph)
    assert "api" in words
    assert "mail" in words
    # the apex registrable name is itself a base word
    assert "example" in words
    # generic keywords are not harvested as base words
    assert "www" not in words


def test_derive_produces_insert_suffix_and_prefix_forms():
    cands = derive_candidates({"api"})
    assert "apiadmin" in cands          # insert
    assert "adminapi" in cands          # suffix
    assert "api-admin" in cands         # prefix
    assert "admin-api" in cands


def test_derive_mutates_trailing_digits_and_regions():
    cands = derive_candidates({"api1"})
    assert "api2" in cands
    assert "api3" in cands
    cands = derive_candidates({"app-useast".replace("useast", "us")})  # "app-us"
    # region tail mutation: 'app-us' -> 'app-eu' etc.
    assert any(c.startswith("app-") and c != "app-us" for c in cands)


def test_derive_applies_homoglyph_substitutions():
    cands = derive_candidates({"dev0"})  # 0 -> o
    assert "devo" in cands
    cands = derive_candidates({"devo"})
    assert "dev0" in cands


# --------------------------------------------------------------- permutation run


class _Dns:
    """Stub resolver: a fixed allow-list of hosts that 'exist'."""

    def __init__(self, existing: set[str]) -> None:
        self._existing = existing

    async def resolves(self, name: str):
        return (name in self._existing, ["203.0.113.10"] if name in self._existing else [], None)


async def test_permute_resolves_derived_candidates_and_tags_them():
    graph = AttackSurfaceGraph.seed("example.com")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "api.example.com"))

    existing = {"apiadmin.example.com", "api-auth.example.com", "nope-xyz.example.com"}
    ctx = CollectorContext(config=Config(), http=None, dns=_Dns(existing))  # type: ignore[arg-type]
    result = await CollectorCollector(ctx).collect(graph)

    labels = {n.label for n in result.nodes}
    assert "apiadmin.example.com" in labels
    assert "api-auth.example.com" in labels
    assert "nope-xyz.example.com" not in labels
    assert result.stats["permute_hits"] == 2
    # derived nodes are tagged so downstream can tell them apart
    assert all("permutation" in n.tags for n in result.nodes)
    # edges back to the apex domain
    assert result.edges and all(e.type.value == "has_subdomain" for e in result.edges)


class PermutationCollector:
    """Local handle so the test does not import the registered class twice."""

    def __init__(self, ctx: CollectorContext) -> None:
        from openrecon.collectors.permutations import PermutationCollector as PC

        self._c = PC(ctx)

    async def collect(self, graph):
        return await self._c.collect(graph)


# alias used above
CollectorCollector = PermutationCollector


async def test_permute_skips_when_no_base_words():
    graph = AttackSurfaceGraph.seed("example.com")  # only the apex, no subdomains
    ctx = CollectorContext(config=Config(), http=None, dns=_Dns(set()))  # type: ignore[arg-type]
    result = await PermutationCollector(ctx).collect(graph)
    assert result.nodes == []
    assert result.stats["permute_hits"] == 0


# -------------------------------------------------------------- securitytrails


class _Http:
    """Stub HTTP that returns canned SecurityTrails payloads."""

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    async def get_json(self, url, *, params=None, headers=None, cache=True, retries=2):
        return self._payload


async def test_securitytrails_skips_without_key():
    ctx = CollectorContext(config=Config(active=False), http=None, dns=None)  # type: ignore[arg-type]
    collector = SecurityTrailsCollector(ctx)
    ok, reason = collector.available()
    assert not ok and "missing API key" in reason


async def test_securitytrails_parses_and_merges_hosts():
    graph = AttackSurfaceGraph.seed("example.com")
    payload = {
        "subdomains": ["api", "dev", "legacy-api"],
        "records": [
            {"values": [{"hostname": "old-mail.example.com"}]},
        ],
    }
    ctx = CollectorContext(
        config=Config(),
        http=_Http(payload),  # type: ignore[arg-type]
        dns=None,  # type: ignore[arg-type]
    )
    # inject the key so available() passes
    ctx.config.api_keys["securitytrails"] = "test-key"
    result = await SecurityTrailsCollector(ctx).collect(graph)

    labels = {n.label for n in result.nodes}
    assert "api.example.com" in labels
    assert "dev.example.com" in labels
    assert "legacy-api.example.com" in labels
    assert "old-mail.example.com" in labels  # from history
    # historical-only host is tagged
    hist = next(n for n in result.nodes if n.label == "old-mail.example.com")
    assert "historical" in hist.tags
    assert result.stats["securitytrails_new"] == 4


async def test_securitytrails_does_not_duplicate_known_hosts():
    graph = AttackSurfaceGraph.seed("example.com")
    graph.add_node(Node.create(NodeType.SUBDOMAIN, "api.example.com"))
    payload = {"subdomains": ["api", "newhost"], "records": []}
    ctx = CollectorContext(
        config=Config(),
        http=_Http(payload),  # type: ignore[arg-type]
        dns=None,  # type: ignore[arg-type]
    )
    ctx.config.api_keys["securitytrails"] = "test-key"
    result = await SecurityTrailsCollector(ctx).collect(graph)
    labels = {n.label for n in result.nodes}
    assert "api.example.com" not in labels
    assert "newhost.example.com" in labels
