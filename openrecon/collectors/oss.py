"""Open-source security tooling as first-class collectors.

Platforms like SpiderFoot, subfinder, amass and nuclei are the comprehensive,
self-hostable half of reconnaissance: no per-query API bill, no rate limit, and
no dependence on a third party's view of the target. They are invoked as
subprocesses (never imported) and their output is parsed into the same
Node/Edge/Finding language every other collector speaks, so the pipeline, risk
engine and report need no special-casing.

Two proofs of the pattern live here:

* ``SubfinderCollector`` - a fast passive subdomain enumerator. Runs the binary
  (``subfinder``) and parses its one-host-per-line output.
* ``SpiderFootCollector`` - the "model tech" you asked for: a single tool that
  sweeps DNS, subdomains, emails, breaches, cloud buckets, vulnerabilities and
  more. It runs SpiderFoot's CLI, ingests its JSON corpus, and turns each
  module's findings into typed nodes and findings.

Every collector degrades gracefully: if the binary is not installed (or not on
``tool_paths``) it is skipped exactly like a keyed API collector is when its key
is missing. Tests feed fixture output through the parsers and run the collectors
against a fake binary, so no real tooling is required to verify them.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from openrecon.collectors.base import Collector, CollectorContext, register
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


class ToolRunner:
    """Run an external binary and return its stdout, with timeouts.

    Subprocess execution is isolated here so collectors stay declarative: they
    declare the binary name + args and hand the captured text to a parser.
    """

    def __init__(self, ctx: CollectorContext) -> None:
        self.ctx = ctx

    async def run(
        self,
        binary: str,
        args: list[str],
        *,
        timeout: float | None = None,
        text: bool = True,
    ) -> tuple[str | None, str]:
        """Execute ``binary args``; return (stdout, error).

        ``stdout`` is ``None`` on a hard failure (binary missing, non-zero exit)
        so callers can record a skip rather than crash the scan.
        """
        path = self.ctx.config.tool(binary)
        if not path:
            return None, f"{binary} not found on PATH or tool_paths"
        try:
            proc = await asyncio.create_subprocess_exec(
                path,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return None, f"{binary} could not be started: {exc}"
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(), timeout=timeout or self.ctx.config.timeout * 30
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return None, f"{binary} timed out after {timeout or self.ctx.config.timeout * 30}s"
        if proc.returncode not in (0, None):
            return None, (err or b"").decode("utf-8", "replace")[:300]
        return (out or b"").decode("utf-8", "replace") if text else (out or b""), ""


@register
class SubfinderCollector(Collector):
    """Passive subdomain enumeration via subfinder.

    subfinder aggregates dozens of passive sources (AlienVault OTX, ThreatMiner,
    the CRT resumption, etc.) into one fast pass. It is a *second independent
    net* over the subdomain pond alongside CT logs and SecurityTrails, which the
    coverage model rewards: hosts one source misses, another often catches.
    """

    name = "subfinder"
    stage = "subdomains"
    mode = ScanMode.PASSIVE
    description = "Enumerate passive subdomain sources with subfinder"
    requires_bins = ("subfinder",)

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        apex = graph.meta.target
        binary = self.config.tool("subfinder")
        assert binary, "subfinder presence checked by available()"

        raw, err = await ToolRunner(self.ctx).run(
            "subfinder", ["-d", apex, "-silent", "-json"], text=True
        )
        if raw is None:
            result.errors.append(f"subfinder: {err}")
            return result

        known = {n.label for n in graph.nodes_of(NodeType.SUBDOMAIN, NodeType.DOMAIN)}
        from openrecon.collectors.subdomains import _tags_for

        prov = self.prov("subfinder")
        seen: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            host = self._host_from(line, apex)
            if not host or host in known or host in seen:
                continue
            seen.add(host)
            node = Node.create(
                NodeType.SUBDOMAIN,
                host,
                attrs={"apex": apex, "source": "subfinder"},
                provenance=prov,
                tags=_tags_for(host, apex),
            )
            result.nodes.append(node)
            result.edges.append(
                Edge(
                    source=Node.make_id(NodeType.DOMAIN, apex),
                    target=node.id,
                    type=EdgeType.HAS_SUBDOMAIN,
                    provenance=[prov],
                )
            )
        result.stats["subfinder_new"] = len(seen)
        return result

    @staticmethod
    def _host_from(line: str, apex: str) -> str | None:
        """subfinder emits either bare hosts or ``{"host": "x"}`` JSON."""
        text = line.strip()
        if text.startswith("{"):
            try:
                obj = json.loads(text)
            except ValueError:
                return None
            text = str(obj.get("host") or obj.get("input") or "").strip().lower()
        else:
            text = text.lower()
        if not text or not text.endswith(apex) or text == apex:
            return None
        return text


# ----------------------------------------------------------------- ----------
# SpiderFoot: the comprehensive "model tech" collector.
#
# SpiderFoot's CLI mode writes a JSON "scan table" where every row is one
# observed fact: a module, a type, a value, the source asset and a confidence.
# We learn the column order from the header row (SF changes it between
# versions) and map the data types it emits to our node vocabulary.
# ----------------------------------------------------------------- ----------

# SpiderFoot data types -> our node vocabulary. Types that are high-signal
# (credentials, threats, emails) become findings; the rest become nodes.
_SF_TYPE_TO_NODE: dict[str, NodeType | None] = {
    "DOMAIN_NAME": NodeType.SUBDOMAIN,
    "INTERNET_NAME": NodeType.SUBDOMAIN,
    "AFFILIATE_INTERNET_NAME": NodeType.SUBDOMAIN,
    "CO_HOSTED_SITE": NodeType.SUBDOMAIN,
    "IP_ADDRESS": NodeType.IP,
    "NETBLOCK_OWNER": NodeType.ORGANIZATION,
    "CLOUD_BUCKET": NodeType.CLOUD_RESOURCE,
    "WEB_ANALYTICS_ID": NodeType.TECHNOLOGY,
    "HTTP_CODE": NodeType.SERVICE,
    "TCP_PORT_OPEN": NodeType.SERVICE,
    "VULNERABILITY": NodeType.VULNERABILITY,
    # Finding-only types (no stable node asset of their own):
    "LEAKED_CREDENTIAL": None,
    "MALICIOUS_ASN": None,
    "EMAILADDR": None,
}


@register
class SpiderFootCollector(Collector):
    """Comprehensive OSINT via SpiderFoot's scan-table CLI.

    One tool, dozens of modules: DNS, subdomains, emails, breaches, cloud
    buckets, banners, vulnerabilities, threats. It is the closest open-source
    analogue to the "model tech" that ties passive sources together. We run
    ``sf.py`` in scan-table mode, read the JSON corpus, and turn each row into a
    typed node (and, for the high-signal types, a finding).
    """

    name = "spiderfoot"
    stage = "threat"
    mode = ScanMode.PASSIVE
    description = "Run SpiderFoot modules and ingest the scan table as typed nodes"
    requires_bins = ("spiderfoot",)

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        apex = graph.meta.target
        binary = self.config.tool("spiderfoot")
        assert binary, "spiderfoot presence checked by available()"

        raw, err = await ToolRunner(self.ctx).run(
            "spiderfoot", ["-s", apex, "-o", "json", "-m", "all"], text=True
        )
        if raw is None:
            result.errors.append(f"spiderfoot: {err}")
            return result

        rows = self._parse_scan_table(raw)
        result.stats["spiderfoot_rows"] = len(rows)
        from openrecon.collectors.subdomains import _tags_for

        prov = self.prov("spiderfoot")
        for row in rows:
            self._ingest(row, graph, result, prov, apex, _tags_for)
        return result

    # ----- parsing ----------------------------------------------------------

    @staticmethod
    def _parse_scan_table(raw: str) -> list[dict[str, Any]]:
        """Parse SpiderFoot's ``-o json`` scan table.

        The first line is a header describing the column order; subsequent lines
        are JSON arrays aligned to that header. Returns a list of dicts keyed by
        header name. Robust to SpiderFoot reordering/renaming columns.
        """
        rows: list[dict[str, Any]] = []
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        if not lines:
            return rows
        try:
            header = json.loads(lines[0])
        except ValueError:
            return rows
        for line in lines[1:]:
            try:
                cells = json.loads(line)
            except ValueError:
                continue
            if not isinstance(cells, list) or len(cells) != len(header):
                continue
            rows.append(dict(zip(header, cells, strict=True)))
        return rows

    # ----- ingestion --------------------------------------------------------

    def _ingest(self, row, graph, result, prov, apex, tags_for) -> None:  # type: ignore[no-untyped-def]
        ftype = str(row.get("type") or row.get("data_type") or "").strip().upper()
        value = str(row.get("value") or "").strip()
        if not value:
            return
        node_type = _SF_TYPE_TO_NODE.get(ftype)
        if node_type is None:
            # Finding-only types: report the signal without a stable asset node.
            sev = {
                "LEAKED_CREDENTIAL": Severity.CRITICAL,
                "MALICIOUS_ASN": Severity.HIGH,
                "EMAILADDR": Severity.LOW,
            }.get(ftype, Severity.MEDIUM)
            result.findings.append(
                Finding(
                    title=f"{ftype.replace('_', ' ').title()} observed: {value}",
                    severity=sev,
                    category="spiderfoot-osint",
                    node_ids=[Node.make_id(NodeType.DOMAIN, apex)],
                    description=f"SpiderFoot module reported {ftype} for {apex}.",
                    evidence={"type": ftype, "value": value},
                    collector=self.name,
                )
            )
            return

        key = value.lower()
        if node_type is NodeType.SUBDOMAIN:
            if not key.endswith(apex) or key == apex:
                return
            node = Node.create(
                NodeType.SUBDOMAIN,
                key,
                attrs={"apex": apex, "source": "spiderfoot"},
                provenance=prov,
                tags=tags_for(key, apex),
            )
            result.edges.append(
                Edge(
                    source=Node.make_id(NodeType.DOMAIN, apex),
                    target=node.id,
                    type=EdgeType.HAS_SUBDOMAIN,
                    provenance=[prov],
                )
            )
        elif node_type is NodeType.IP:
            node = Node.create(
                NodeType.IP, value, attrs={"source": "spiderfoot"}, provenance=prov
            )
        else:
            node = Node.create(
                node_type, f"{ftype}:{key}", label=value, provenance=prov,
                attrs={"source": "spiderfoot", "detail": value},
            )
        result.nodes.append(node)


# ---------------------------------------------------------------------------
# Active OSS scanners. These send packets to in-scope infrastructure and so
# require --active plus an authorization scope (enforced by Collector.available
# and Collector.targets_in_scope). They reuse ToolRunner and the Node/Finding
# language, so the risk engine and report need no special handling.
# ---------------------------------------------------------------------------


@register
class NaabuCollector(Collector):
    """Fast active port discovery via naabu.

    naabu is a SYN/connect port scanner built for bug-bounty scale. It runs
    against in-scope hosts only and emits one JSON line per open port, which we
    turn into SERVICE nodes + EXPOSES edges - the same shape the built-in
    ``ports`` collector produces, so downstream risk scoring is identical.
    """

    name = "naabu"
    stage = "services"
    mode = ScanMode.ACTIVE
    description = "Active port scan of in-scope hosts with naabu"
    requires_bins = ("naabu",)

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()
        hosts = [
            n.label
            for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN, NodeType.IP)
            if not n.attrs.get("private")
        ]
        allowed = self.targets_in_scope(hosts)
        refused = len(hosts) - len(allowed)
        if refused:
            result.errors.append(f"naabu: skipped {refused} out-of-scope host(s)")
        if not allowed:
            return result

        raw, err = await ToolRunner(self.ctx).run(
            "naabu", ["-json", "-host", ",".join(allowed)], text=True
        )
        if raw is None:
            result.errors.append(f"naabu: {err}")
            return result

        prov = self.prov("naabu")
        open_count = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            host = str(obj.get("host") or "").strip()
            port = obj.get("port")
            if not host or not isinstance(port, int):
                continue
            open_count += 1
            svc = Node.create(
                NodeType.SERVICE,
                f"{host}:{port}",
                label=f"service/{port}",
                attrs={"ip": host, "port": port, "transport": "tcp", "source": "naabu"},
                provenance=prov,
                tags={"exposed"},
            )
            result.nodes.append(svc)
            result.edges.append(
                Edge(
                    source=Node.make_id(NodeType.IP, host)
                    if _is_ip(host)
                    else Node.make_id(NodeType.DOMAIN, host),
                    target=svc.id,
                    type=EdgeType.EXPOSES,
                    provenance=[prov],
                )
            )
        result.stats["naabu_open"] = open_count
        result.stats["naabu_hosts"] = len(allowed)
        return result


def _is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
