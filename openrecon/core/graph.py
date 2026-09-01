"""The attack surface graph: nodes, edges, findings, and the queries over them."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from openrecon.core.models import (
    Edge,
    EdgeType,
    ExposureSummary,
    Finding,
    Node,
    NodeType,
    Severity,
    utcnow,
)


class ScanMeta(BaseModel):
    target: str
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    mode: str = "passive"
    collectors_run: list[str] = Field(default_factory=list)
    collectors_skipped: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    openrecon_version: str = ""

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or utcnow()
        return (end - self.started_at).total_seconds()


class AttackSurfaceGraph(BaseModel):
    """Container for everything a scan learned about one target.

    Nodes are keyed by `Node.id` so repeated observations merge instead of
    duplicating; edges are keyed by (source, type, target) for the same reason.
    """

    meta: ScanMeta
    nodes: dict[str, Node] = Field(default_factory=dict)
    edges: dict[str, Edge] = Field(default_factory=dict)
    findings: dict[str, Finding] = Field(default_factory=dict)
    # Populated by the analysis stages that run after collection.
    risk: dict[str, Any] = Field(default_factory=dict)
    adversary: dict[str, Any] = Field(default_factory=dict)
    """Attacker cost model: cheapest routes in, and what fixing each finding buys."""
    coverage: dict[str, Any] = Field(default_factory=dict)
    """How much of the real surface this scan could observe."""
    patterns: list[dict[str, Any]] = Field(default_factory=list)
    """Findings that track a cohort - process defects rather than host defects."""
    analysis: dict[str, Any] = Field(default_factory=dict)

    # ---------------------------------------------------------------- mutation

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        existing.merge(node)
        return existing

    def add_edge(self, edge: Edge) -> Edge:
        existing = self.edges.get(edge.id)
        if existing is None:
            self.edges[edge.id] = edge
            return edge
        existing.attrs.update({k: v for k, v in edge.attrs.items() if v is not None})
        seen = {p.key() for p in existing.provenance}
        for p in edge.provenance:
            if p.key() not in seen:
                existing.provenance.append(p)
        return existing

    def add_finding(self, finding: Finding) -> Finding:
        existing = self.findings.get(finding.id)
        if existing is None:
            self.findings[finding.id] = finding
            return finding
        for nid in finding.node_ids:
            if nid not in existing.node_ids:
                existing.node_ids.append(nid)
        return existing

    def absorb(self, result: Any) -> None:
        """Fold a CollectorResult into the graph."""
        for node in result.nodes:
            self.add_node(node)
        for edge in result.edges:
            # Drop dangling edges rather than corrupting the graph.
            if edge.source in self.nodes and edge.target in self.nodes:
                self.add_edge(edge)
        for finding in result.findings:
            self.add_finding(finding)
        # Collectors sharing a memoized fetch report the same upstream failure;
        # the reader only needs to be told once.
        for error in result.errors:
            if error not in self.meta.errors:
                self.meta.errors.append(error)

    # ----------------------------------------------------------------- queries

    def nodes_of(self, *types: NodeType) -> list[Node]:
        wanted = set(types)
        return [n for n in self.nodes.values() if n.type in wanted]

    def edges_of(self, *types: EdgeType) -> list[Edge]:
        wanted = set(types)
        return [e for e in self.edges.values() if e.type in wanted]

    def neighbors(
        self, node_id: str, *, direction: str = "out", edge_types: Iterable[EdgeType] | None = None
    ) -> list[Node]:
        wanted = set(edge_types) if edge_types else None
        out: list[Node] = []
        for edge in self.edges.values():
            if wanted and edge.type not in wanted:
                continue
            if direction in ("out", "both") and edge.source == node_id:
                target = self.nodes.get(edge.target)
                if target:
                    out.append(target)
            if direction in ("in", "both") and edge.target == node_id:
                source = self.nodes.get(edge.source)
                if source:
                    out.append(source)
        return out

    def adjacency(self) -> dict[str, list[str]]:
        adj: dict[str, list[str]] = defaultdict(list)
        for edge in self.edges.values():
            adj[edge.source].append(edge.target)
        return adj

    def findings_for(self, node_id: str) -> list[Finding]:
        return [f for f in self.findings.values() if node_id in f.node_ids]

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        buckets: dict[Severity, list[Finding]] = defaultdict(list)
        for f in self.findings.values():
            buckets[f.severity].append(f)
        for items in buckets.values():
            items.sort(key=lambda f: (-f.risk_score, f.title))
        return dict(buckets)

    def findings_by_category(self) -> dict[str, list[Finding]]:
        """Findings grouped by type (category), most dangerous types first.

        Each collector tags its findings with a category - "sqli", "ssrf",
        "known-vulnerability", "web-hardening", ... A flat list sorted by score
        buries a single critical SQLi under a pile of low-severity hardening
        notes; grouping by type keeps every class of bug visible on its own.

        Groups are ordered by their most severe finding, then by top score, then
        by count; within a group, findings are ordered by risk score.
        """
        buckets: dict[str, list[Finding]] = defaultdict(list)
        for f in self.findings.values():
            buckets[f.category or "other"].append(f)
        for items in buckets.values():
            items.sort(key=lambda f: (-f.risk_score, f.title))
        ordered = sorted(
            buckets.items(),
            key=lambda kv: (
                max(f.severity.weight for f in kv[1]),
                max(f.risk_score for f in kv[1]),
                len(kv[1]),
            ),
            reverse=True,
        )
        return {category: items for category, items in ordered}

    def hostnames(self) -> list[str]:
        """Every domain/subdomain label, apex first."""
        names = [n.label for n in self.nodes_of(NodeType.DOMAIN)]
        names += sorted(n.label for n in self.nodes_of(NodeType.SUBDOMAIN))
        return names

    def iter_nodes(self) -> Iterator[Node]:
        return iter(self.nodes.values())

    # ----------------------------------------------------------------- summary

    def exposure(self) -> ExposureSummary:
        expired = 0
        now = datetime.now(UTC)
        for cert in self.nodes_of(NodeType.CERTIFICATE):
            not_after = cert.attrs.get("not_after")
            if not not_after:
                continue
            try:
                dt = datetime.fromisoformat(str(not_after))
            except ValueError:
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            if dt < now:
                expired += 1

        suspicious = len(
            [
                n
                for n in self.nodes.values()
                if n.tags & {"suspicious", "malicious", "takeover", "shadow-it"}
            ]
        )
        return ExposureSummary(
            domains=len(self.nodes_of(NodeType.DOMAIN)),
            subdomains=len(self.nodes_of(NodeType.SUBDOMAIN)),
            ip_addresses=len(self.nodes_of(NodeType.IP)),
            asns=len(self.nodes_of(NodeType.ASN)),
            technologies=len(self.nodes_of(NodeType.TECHNOLOGY)),
            exposed_services=len(self.nodes_of(NodeType.SERVICE)),
            leaked_credentials=sum(
                int(n.attrs.get("count", 1)) for n in self.nodes_of(NodeType.CREDENTIAL_LEAK)
            ),
            known_vulnerabilities=len(self.nodes_of(NodeType.VULNERABILITY)),
            suspicious_assets=suspicious,
            expired_certificates=expired,
            secrets_detected=len(self.nodes_of(NodeType.SECRET)),
        )

    # ------------------------------------------------------------- schema export

    def export_graphql_schemas(self, out_dir: str | Path) -> list[Path]:
        """Write every introspected GraphQL schema to a ``.graphql`` SDL file.

        General: walks the graph for any ``api`` node carrying a
        ``graphql_schema_sdl`` attribute (produced by the GraphQL verifier) and
        dumps it next to the HTML report. Returns the written paths. Missing the
        optional ``graphql`` collector is not an error - an empty list is fine.
        """
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for node in self.nodes_of(NodeType.API):
            sdl = node.attrs.get("graphql_schema_sdl")
            if not sdl:
                continue
            safe = re.sub(r"[^a-z0-9._-]", "_", (node.label or node.id).lower())
            path = out_dir / f"{safe}.graphql"
            path.write_text(sdl, encoding="utf-8")
            written.append(path)
        return written

    # -------------------------------------------------------------- (de)serial

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.model_dump_json())

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path) -> AttackSurfaceGraph:
        return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))

    @classmethod
    def seed(cls, target: str, mode: str = "passive", version: str = "") -> AttackSurfaceGraph:
        from openrecon.core.models import Provenance

        graph = cls(meta=ScanMeta(target=target, mode=mode, openrecon_version=version))
        graph.add_node(
            Node.create(
                NodeType.DOMAIN,
                target,
                attrs={"apex": True},
                provenance=Provenance(collector="seed", source="user-input"),
                tags={"seed"},
            )
        )
        return graph

    # ------------------------------------------------------------------ diffing

    def diff(self, previous: AttackSurfaceGraph) -> dict[str, list[str]]:
        """What changed since a previous scan of the same target."""
        old_nodes, new_nodes = set(previous.nodes), set(self.nodes)
        old_find, new_find = set(previous.findings), set(self.findings)
        return {
            "new_assets": sorted(self.nodes[i].label for i in new_nodes - old_nodes),
            "removed_assets": sorted(previous.nodes[i].label for i in old_nodes - new_nodes),
            "new_findings": sorted(self.findings[i].title for i in new_find - old_find),
            "resolved_findings": sorted(previous.findings[i].title for i in old_find - new_find),
        }
