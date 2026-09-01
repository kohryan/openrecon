"""Client-side dependency recovery from bundles and source maps."""

from __future__ import annotations

import json

import pytest

from openrecon.collectors._platforms import managed_platform, tenant_platform
from openrecon.collectors.base import CollectorContext
from openrecon.collectors.sbom import SbomCollector
from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Node, NodeType, Severity
from openrecon.scope import Scope

# Shapes taken from real production bundles.
NEXT_MAIN = (
    'self.__NEXT_DATA__={};var t={};'
    'for(var n=0;n<e.length;n++)r(n);return e}var F;t.version="12.1.6",t.router=F;'
)
REACT_DOM = 'ReactCurrentDispatcher:{current:null},version:"17.0.2",render:function(){}'
JQUERY_BANNER = "/*! jQuery v3.5.1 | (c) JS Foundation */ !function(e,t){}"


@pytest.fixture
def collector() -> SbomCollector:
    ctx = CollectorContext(
        config=Config(active=True),
        http=None,  # type: ignore[arg-type]
        dns=None,  # type: ignore[arg-type]
        scope=Scope(include=["*.example.com", "example.com"]),
    )
    return SbomCollector(ctx)


# ------------------------------------------------------------- fingerprinting


def test_next_version_is_recovered_from_the_main_chunk(collector):
    """Next.js is where the CVEs are, and it only leaks its version here."""
    assert collector._fingerprint(NEXT_MAIN)["next"] == "12.1.6"


def test_react_version_is_recovered(collector):
    assert collector._fingerprint(REACT_DOM)["react-dom"] == "17.0.2"


def test_banner_comments_are_read(collector):
    assert collector._fingerprint(JQUERY_BANNER).get("jquery") == "3.5.1"


def test_a_bundle_without_markers_yields_nothing(collector):
    assert collector._fingerprint("var a=1;function b(){return 2}") == {}


def test_version_constants_are_not_attributed_to_the_wrong_package(collector):
    """A bare version string with no Next marker must not become a Next version."""
    assert "next" not in collector._fingerprint('var x={version:"9.9.9"}')


def test_build_layout_identifies_the_framework(collector):
    assert collector._build_tool(["https://x/_next/static/chunks/main.js"]) == "next"
    assert collector._build_tool(["https://x/_nuxt/entry.js"]) == "nuxt"
    assert collector._build_tool(["https://x/js/app.js"]) == ""


# ------------------------------------------------------------- bundle listing


def test_only_same_origin_bundles_are_fetched(collector):
    html = (
        '<script src="/_next/static/chunks/main.js"></script>'
        '<script src="https://cdn.example.net/react.js"></script>'
        '<script src="https://app.example.com/local.js"></script>'
    )
    urls = collector._bundle_urls("https://app.example.com/", html)
    assert urls == [
        "https://app.example.com/_next/static/chunks/main.js",
        "https://app.example.com/local.js",
    ], "a CDN's copy of a library is not this site's dependency, and not our traffic to send"


# ------------------------------------------------------------- source maps


class _StubHttp:
    def __init__(self, routes: dict[str, tuple[int, str]]):
        self.routes = routes
        self.calls: list[str] = []

    async def request(self, method, url, *, retries=1, **kw):
        self.calls.append(url)
        for prefix, (status, body) in self.routes.items():
            if url.startswith(prefix):
                return _StubResponse(status, body)
        return None

    async def get_text(self, url, *, retries=1, max_bytes=0, **kw):
        response = await self.request("GET", url)
        return response.text if response and response.status_code < 400 else None


class _StubResponse:
    def __init__(self, status: int, text: str):
        self.status_code = status
        self.text = text


SOURCEMAP = json.dumps(
    {
        "version": 3,
        "sources": [
            "webpack://app/./node_modules/lodash/lodash.js",
            "webpack://app/./node_modules/@sentry/browser/esm/index.js",
            "webpack://app/./src/pages/index.tsx",
        ],
    }
)


async def test_a_published_source_map_is_found_and_read(collector):
    http = _StubHttp(
        {
            "https://app.example.com/app.js.map": (200, SOURCEMAP),
        }
    )
    collector.http = http
    import asyncio

    result = await collector._check_sourcemap(
        asyncio.Semaphore(1),
        "https://app.example.com/app.js",
        "code();\n//# sourceMappingURL=app.js.map",
    )
    assert result is not None
    _url, packages = result
    assert packages == ["@sentry/browser", "lodash"], "scoped packages must survive"


async def test_a_missing_source_map_is_not_a_finding(collector):
    import asyncio

    collector.http = _StubHttp({})
    assert await collector._check_sourcemap(
        asyncio.Semaphore(1), "https://app.example.com/app.js", "//# sourceMappingURL=app.js.map"
    ) is None


def test_source_map_exposure_is_reported_as_a_disclosure(collector):
    result = collector._sourcemap_finding(
        "app.example.com",
        Node.make_id(NodeType.SUBDOMAIN, "app.example.com"),
        "https://app.example.com/app.js.map",
        ["lodash", "@sentry/browser"],
        collector.prov("x"),
    )
    assert result.findings[0].severity is Severity.MEDIUM
    assert "source map" in result.findings[0].title.lower()
    assert result.nodes[0].type is NodeType.SECRET


# ------------------------------------------------------------- end to end


async def test_analyze_host_emits_versioned_dependency_nodes(collector):
    graph = AttackSurfaceGraph.seed("example.com", mode="active")
    collector.http = _StubHttp(
        {
            "https://example.com/_next/static/chunks/main.js": (200, NEXT_MAIN),
            "https://example.com/": (
                200,
                '<script src="/_next/static/chunks/main.js"></script>',
            ),
        }
    )
    import asyncio

    result = await collector._analyze_host(asyncio.Semaphore(2), graph, "example.com")
    packages = {
        n.attrs["product"]: n.attrs["version"]
        for n in result.nodes
        if n.type is NodeType.TECHNOLOGY
    }
    assert packages["next"] == "12.1.6"
    assert all(n.attrs["ecosystem"] == "npm" for n in result.nodes if n.type is NodeType.TECHNOLOGY)


async def test_a_refusal_is_reported_rather_than_read_as_clean(collector):
    """A 403 must not look identical to "no dependencies found"."""
    graph = AttackSurfaceGraph.seed("example.com", mode="active")
    collector.http = _StubHttp({"https://example.com/": (403, "")})
    import asyncio

    result = await collector._analyze_host(asyncio.Semaphore(2), graph, "example.com")
    assert result.nodes == []
    assert any(e.startswith("blocked:") for e in result.errors)


async def test_unversioned_components_are_flagged_as_a_coverage_gap(collector):
    graph = AttackSurfaceGraph.seed("example.com", mode="active")
    collector.http = _StubHttp(
        {
            "https://example.com/_next/static/chunks/x.js": (200, "var a=1"),
            "https://example.com/": (200, '<script src="/_next/static/chunks/x.js"></script>'),
        }
    )
    import asyncio

    result = await collector._analyze_host(asyncio.Semaphore(2), graph, "example.com")
    gap = [f for f in result.findings if f.category == "coverage-gap"]
    assert gap and "not evidence that they are patched" in gap[0].description


# ------------------------------------------------------------- platform facts


@pytest.mark.parametrize(
    "host,platform",
    [
        ("digaris.vercel.app", "Vercel"),
        ("docs.github.io", "GitHub Pages"),
        ("kohryan.my.id", None),
        ("example.com", None),
    ],
)
def test_tenant_hostnames_are_recognised(host, platform):
    assert tenant_platform(host) == platform


def test_managed_and_tenant_answer_different_questions():
    assert managed_platform("cname.vercel-dns.com") == "Vercel"
    assert tenant_platform("cname.vercel-dns.com") is None
