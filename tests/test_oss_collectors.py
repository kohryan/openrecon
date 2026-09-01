"""OSS collectors: graceful skip when absent, correct parse when present.

No real tooling is required. ``_fake_bin`` writes a script that emits fixture
output and exits 0, then we point ``Config.tool_paths`` at it - exactly how a
user would override discovery. Parsers are also exercised in isolation.
"""

from __future__ import annotations

import stat
import textwrap

from openrecon.collectors.base import CollectorContext
from openrecon.collectors.oss import (
    NaabuCollector,
    SpiderFootCollector,
    SubfinderCollector,
    ToolRunner,
)
from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import NodeType


def _write_fake_bin(tmp_path, body: str) -> str:
    path = tmp_path / "fakebin"
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def _ctx(config: Config, graph: AttackSurfaceGraph) -> CollectorContext:
    # CollectorContext wants http/dns/scope; none of the OSS collectors touch
    # them, so minimal stubs keep the contract satisfied.
    class _Stub:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

    return CollectorContext(config=config, http=_Stub(), dns=_Stub(), scope=None)


# ----------------------------------------------------------- availability/skip


def test_subfinder_skips_without_binary(monkeypatch):
    # Force the binary unresolvable so the test is hermetic even on a machine
    # where `make tools` has already installed subfinder onto PATH or into the
    # go bin dir that Config.tool() also searches.
    import shutil

    monkeypatch.setattr(shutil, "which", lambda _name: None)
    monkeypatch.setattr("openrecon.config._extra_tool_dirs", lambda: [])
    cfg = Config(active=False)
    assert cfg.tool("subfinder") is None
    ok, reason = SubfinderCollector(
        CollectorContext(config=cfg, http=None, dns=None, scope=None)
    ).available()
    assert ok is False
    # error now carries an actionable install hint, not a dead end
    assert reason.startswith("missing tool(s): subfinder ->")
    assert "go install" in reason


def test_spiderfoot_skips_without_binary():
    cfg = Config(active=False)
    ok, reason = SpiderFootCollector(
        CollectorContext(config=cfg, http=None, dns=None, scope=None)
    ).available()
    assert ok is False
    assert "spiderfoot" in reason


# ----------------------------------------------------------------- parsers


def test_subfinder_host_from_bare_and_json():
    assert SubfinderCollector._host_from("dev.example.com", "example.com") == "dev.example.com"
    assert SubfinderCollector._host_from('{"host":"api.example.com"}', "example.com") == "api.example.com"
    assert SubfinderCollector._host_from("unrelated.org", "example.com") is None
    assert SubfinderCollector._host_from("example.com", "example.com") is None


def test_spiderfoot_scan_table_parse():
    corpus = textwrap.dedent(
        """
        ["type", "value", "source", "confidence"]
        ["DOMAIN_NAME", "dev.example.com", "DNS", "100"]
        ["IP_ADDRESS", "93.184.216.34", "DNS", "100"]
        ["LEAKED_CREDENTIAL", "user:pass@evil", "HIBP", "90"]
        ["EMAILADDR", "admin@example.com", "SF", "80"]
        """
    ).strip()
    rows = SpiderFootCollector._parse_scan_table(corpus)
    assert len(rows) == 4
    assert rows[0]["type"] == "DOMAIN_NAME"
    assert rows[0]["value"] == "dev.example.com"


def test_spiderfoot_parse_ignores_malformed_lines():
    corpus = '["type","value"]\nnot-json\n["DOMAIN_NAME","x.example.com"]'
    rows = SpiderFootCollector._parse_scan_table(corpus)
    assert rows == [{"type": "DOMAIN_NAME", "value": "x.example.com"}]


# -------------------------------------------------------- end-to-end via fake bin


def test_subfinder_collect_against_fake_bin(graph, tmp_path):
    fake = _write_fake_bin(
        tmp_path,
        textwrap.dedent(
            """
            echo "staging.example.com"
            echo '{"host":"mail.example.com"}'
            echo "unrelated.org"
            """
        ),
    )
    cfg = Config(active=False, tool_paths={"subfinder": fake})
    collector = SubfinderCollector(_ctx(cfg, graph))
    assert collector.available() == (True, "")

    out = asyncio_run(collector.collect(graph))
    labels = {n.label for n in out.nodes}
    assert "staging.example.com" in labels
    assert "mail.example.com" in labels
    # pre-existing (from fixture) or out-of-scope hosts must not be re-added
    assert "unrelated.org" not in labels
    assert out.stats["subfinder_new"] == 2
    # edges back to the apex domain
    assert any(e.type.value == "has_subdomain" for e in out.edges)


def test_spiderfoot_collect_against_fake_bin(graph, tmp_path):
    fake = _write_fake_bin(
        tmp_path,
        textwrap.dedent(
            """
            echo '["type","value"]'
            echo '["DOMAIN_NAME","staging2.example.com"]'
            echo '["IP_ADDRESS","203.0.113.5"]'
            echo '["LEAKED_CREDENTIAL","breached@evil"]'
            echo '["EMAILADDR","admin@example.com"]'
            """
        ),
    )
    cfg = Config(active=False, tool_paths={"spiderfoot": fake})
    collector = SpiderFootCollector(_ctx(cfg, graph))
    assert collector.available() == (True, "")

    out = asyncio_run(collector.collect(graph))
    types = {n.type for n in out.nodes}
    assert NodeType.SUBDOMAIN in types
    assert NodeType.IP in types
    # finding-only types become findings, not nodes
    cats = {f.category for f in out.findings}
    assert "spiderfoot-osint" in cats
    leaked = [f for f in out.findings if "Leaked Credential" in f.title]
    assert leaked and leaked[0].severity.value == "critical"


def test_toolrunner_reports_missing_binary():
    cfg = Config(active=False, tool_paths={"nope": "/no/such/binary"})
    runner = ToolRunner(CollectorContext(config=cfg, http=None, dns=None, scope=None))
    out, err = asyncio_run(runner.run("nope", ["--help"]))
    assert out is None
    assert "nope" in err


# ----------------------------------------------------------- active OSS scanners


def test_naabu_skips_without_active_mode():
    cfg = Config(active=False)
    ok, reason = NaabuCollector(
        CollectorContext(config=cfg, http=None, dns=None, scope=None)
    ).available()
    assert ok is False
    assert "active mode disabled" in reason


def test_naabu_collect_against_fake_bin(graph, tmp_path):
    # implicit scope authorizes *.example.com and resolved IPs
    from openrecon.scope import Scope

    scope = Scope.implicit("example.com")
    fake = _write_fake_bin(
        tmp_path,
        textwrap.dedent(
            """
            echo '{"host":"93.184.216.34","port":443}'
            echo '{"host":"93.184.216.34","port":8080}'
            echo 'not-json'
            """
        ),
    )
    cfg = Config(active=True, tool_paths={"naabu": fake})
    ctx = CollectorContext(config=cfg, http=None, dns=None, scope=scope)
    collector = NaabuCollector(ctx)
    assert collector.available() == (True, "")

    out = asyncio_run(collector.collect(graph))
    svc_ids = {n.id for n in out.nodes if n.type.value == "service"}
    assert "service:93.184.216.34:443" in svc_ids
    assert "service:93.184.216.34:8080" in svc_ids
    assert out.stats["naabu_open"] == 2
    assert any(
        e.type.value == "exposes" and e.target.startswith("service:")
        for e in out.edges
    )


# --------------------------------------------------------------- test helpers


def asyncio_run(coro):
    import asyncio

    return asyncio.run(coro)
