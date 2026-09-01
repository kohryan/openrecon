"""The risk engine.

Turns a pile of findings into a ranked answer to one question: what should this
team fix first? Three inputs decide a finding's score:

  severity     how bad it is if exploited (CVSS, or our own judgement)
  likelihood   how likely exploitation actually is (EPSS, KEV, exposure)
  blast radius how much of the attack surface hangs off the affected asset

Asset risk then propagates outward, so a critical CVE on a host that fronts 40
subdomains outranks the same CVE on an orphaned test box.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Finding, Node, NodeType, Severity

# How much each category contributes when it appears at all.
CATEGORY_WEIGHT: dict[str, float] = {
    "known-vulnerability": 1.0,
    "secret-exposure": 1.0,
    "credential-exposure": 0.9,
    "graphql-exposure": 0.9,
    "api-exposure": 0.7,
    "reverse-engineering": 0.8,
    "exposed-service": 0.95,
    "subdomain-takeover": 0.9,
    "threat-intelligence": 1.0,
    "dns-exposure": 0.8,
    "tls": 0.6,
    "domain-lifecycle": 0.6,
    "email-security": 0.5,
    "web-hardening": 0.3,
    "information-disclosure": 0.3,
    "certificate-governance": 0.35,
    "attack-surface-sprawl": 0.3,
    "dns-hygiene": 0.25,
    # Deep attack categories
    "ssti": 1.0,
    "lfi": 0.9,
    "cmdi": 1.0,
    "jwt": 0.85,
    "cors": 0.5,
}

# Tags that raise the stakes on the affected asset.
ASSET_MULTIPLIER: dict[str, float] = {
    "non-production": 1.25,
    "sensitive-service": 1.35,
    "unauthenticated-risk": 1.4,
    "malicious": 1.6,
    "takeover": 1.3,
    "zone-transfer": 1.1,
    "seed": 1.2,
}

GRADES = [
    (90.0, "A", "Strong"),
    (75.0, "B", "Good"),
    (60.0, "C", "Fair"),
    (40.0, "D", "Weak"),
    (0.0, "F", "Critical"),
]


class RiskEngine:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()

    # ------------------------------------------------------------------ public

    def score(self, graph: AttackSurfaceGraph) -> dict[str, Any]:
        import time as _time
        _start = _time.monotonic()
        
        # Report progress for large graphs
        node_count = len(graph.nodes)
        if node_count > 1000:
            print(f"  [risk] computing blast radius for {node_count} nodes...")
        
        blast = self._blast_radius(graph)
        
        if node_count > 1000:
            print(f"  [risk] blast radius done in {_time.monotonic() - _start:.1f}s, scoring findings...")
        
        finding_count = len(graph.findings)
        for i, finding in enumerate(graph.findings.values()):
            finding.risk_score = self._score_finding(graph, finding, blast)
            # Progress every 1000 findings for large graphs
            if finding_count > 1000 and i > 0 and i % 1000 == 0:
                print(f"  [risk] scored {i}/{finding_count} findings...")

        node_scores: dict[str, float] = defaultdict(float)
        for finding in graph.findings.values():
            for node_id in finding.node_ids:
                node_scores[node_id] += finding.risk_score
        for node_id, node in graph.nodes.items():
            raw = node_scores.get(node_id, 0.0)
            node.risk_score = round(min(raw, 100.0), 1)
            node.risk_severity = self._severity_for(node.risk_score)

        if node_count > 1000:
            print(f"  [risk] scoring done in {_time.monotonic() - _start:.1f}s, summarizing...")

        summary = self._summarize(graph, blast)
        graph.risk = summary
        
        if node_count > 1000:
            print(f"  [risk] total scoring time: {_time.monotonic() - _start:.1f}s")
        
        return summary

    # ------------------------------------------------------------------ scoring

    def _score_finding(
        self, graph: AttackSurfaceGraph, finding: Finding, blast: dict[str, int]
    ) -> float:
        base = finding.severity.weight * 6.0  # 0..60

        likelihood = 1.0
        if finding.kev:
            likelihood = 2.0
        elif finding.epss is not None:
            # EPSS is a probability; 0.5 is extraordinarily high in practice.
            likelihood = 1.0 + min(finding.epss, 1.0) * 1.5
        elif finding.cvss and finding.cvss >= 9.0:
            likelihood = 1.3

        category = CATEGORY_WEIGHT.get(finding.category, 0.5)

        asset_mult = 1.0
        reach = 0
        for node_id in finding.node_ids:
            node = graph.nodes.get(node_id)
            if node is None:
                continue
            for tag in node.tags:
                asset_mult = max(asset_mult, ASSET_MULTIPLIER.get(tag, 1.0))
            reach = max(reach, blast.get(node_id, 0))

        reach_mult = 1.0 + min(reach, 50) / 100.0  # up to +50%
        score = base * category * likelihood * asset_mult * reach_mult
        return round(min(score, 100.0), 1)

    def _blast_radius(self, graph: AttackSurfaceGraph) -> dict[str, int]:
        """How many other assets depend on each node (reverse reachability, depth-limited).
        
        Uses memoization to avoid recomputing reachability for shared ancestors.
        Without memoization, this is O(N*E) and hangs on graphs with 5000+ nodes.
        With memoization, it's O(N + E) — each node's reachability is computed once.
        """
        incoming: dict[str, set[str]] = defaultdict(set)
        for edge in graph.edges.values():
            incoming[edge.target].add(edge.source)

        radius: dict[str, int] = {}
        memo: dict[str, set[str]] = {}  # node_id -> set of reachable ancestors

        def _reachable(node_id: str, depth: int = 0) -> set[str]:
            """Return all ancestors reachable within 3 hops, using memoization."""
            if node_id in memo:
                return memo[node_id]
            if depth >= 3:
                return set()
            
            result: set[str] = set()
            for parent in incoming.get(node_id, ()):
                result.add(parent)
                result |= _reachable(parent, depth + 1)
            
            memo[node_id] = result
            return result

        for node_id in graph.nodes:
            radius[node_id] = len(_reachable(node_id))
        return radius

    def _severity_for(self, score: float) -> Severity:
        if score >= 70:
            return Severity.CRITICAL
        if score >= 45:
            return Severity.HIGH
        if score >= 25:
            return Severity.MEDIUM
        if score > 0:
            return Severity.LOW
        return Severity.INFO

    # ------------------------------------------------------------------ summary

    def _summarize(self, graph: AttackSurfaceGraph, blast: dict[str, int]) -> dict[str, Any]:
        findings = list(graph.findings.values())
        counts = Counter(f.severity.value for f in findings)

        # Posture starts at 100 and is eroded by what we found, with diminishing
        # returns so a long tail of low findings can't out-weigh one critical.
        penalty = 0.0
        for severity, weight in (
            (Severity.CRITICAL, 22.0),
            (Severity.HIGH, 11.0),
            (Severity.MEDIUM, 4.0),
            (Severity.LOW, 1.0),
        ):
            n = counts.get(severity.value, 0)
            if n:
                penalty += weight * (1 + (n - 1) ** 0.6)
        posture = max(0.0, 100.0 - penalty)
        grade, label = next((g, name) for threshold, g, name in GRADES if posture >= threshold)

        top = sorted(findings, key=lambda f: -f.risk_score)[:15]
        critical_assets = sorted(
            (n for n in graph.nodes.values() if n.risk_score > 0),
            key=lambda n: -n.risk_score,
        )[:15]

        return {
            "posture_score": round(posture, 1),
            "grade": grade,
            "grade_label": label,
            "finding_density": round(len(findings) / max(len(graph.nodes), 1), 2),
            "finding_counts": {s.value: counts.get(s.value, 0) for s in Severity},
            "total_findings": len(findings),
            "kev_findings": sum(1 for f in findings if f.kev),
            "max_epss": max((f.epss or 0.0 for f in findings), default=0.0),
            "top_findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "score": f.risk_score,
                    "category": f.category,
                    "cve": f.cve,
                    "kev": f.kev,
                    "epss": f.epss,
                    "assets": [graph.nodes[n].label for n in f.node_ids if n in graph.nodes][:5],
                }
                for f in top
            ],
            "critical_assets": [
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.type.value,
                    "score": n.risk_score,
                    "severity": n.risk_severity.value,
                    "blast_radius": blast.get(n.id, 0),
                    "tags": sorted(n.tags),
                    "findings": len(graph.findings_for(n.id)),
                }
                for n in critical_assets
            ],
            "category_breakdown": dict(
                Counter(f.category for f in findings).most_common()
            ),
        }


# A posture grade counts findings. It cannot see that a low-severity gap is the
# only thing an attacker needs, so a cheap route caps the grade regardless.
TTC_GRADE_CEILING: list[tuple[float, str]] = [
    (1.0, "D"),
    (8.0, "C"),
    (40.0, "B"),
]

GRADE_ORDER = ["A", "B", "C", "D", "F"]


def qualify(graph: AttackSurfaceGraph) -> dict[str, Any]:
    """Reconcile the finding-count grade with attacker cost and scan coverage.

    Run after the adversary model and coverage assessment, because both can
    overrule a grade that counting findings alone would award. An A earned over
    a third of the surface is not an A, and neither is an A an attacker can
    walk past in twenty minutes.
    """
    risk = graph.risk
    if not risk:
        return risk

    grade = str(risk.get("grade", "F"))
    label = str(risk.get("grade_label", ""))
    reasons: list[str] = []

    hours = (graph.adversary or {}).get("time_to_compromise_hours")
    if hours is not None:
        ceiling = next((g for limit, g in TTC_GRADE_CEILING if hours < limit), None)
        if ceiling and GRADE_ORDER.index(ceiling) > GRADE_ORDER.index(grade):
            reasons.append(
                f"capped at {ceiling}: a modelled attacker reaches an objective in "
                f"{hours:.1f}h"
            )
            grade = ceiling
            label = "Reachable"

    confidence = (graph.coverage or {}).get("confidence")
    provisional = confidence is not None and confidence < 0.55
    if provisional:
        reasons.append(
            f"provisional: only {confidence:.0%} of the attack surface could be observed"
        )

    risk["grade"] = grade
    risk["grade_label"] = label
    risk["grade_display"] = f"{grade}?" if provisional else grade
    risk["grade_provisional"] = provisional
    risk["grade_reasons"] = reasons
    return risk


def attack_paths(graph: AttackSurfaceGraph, limit: int = 10) -> list[dict[str, Any]]:
    """Walk apex -> subdomain -> IP -> service -> vulnerability chains.

    Uses iterative DFS with early termination to avoid exponential blowup
    on large graphs (5000+ nodes).
    """
    paths: list[dict[str, Any]] = []
    outgoing: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for edge in graph.edges.values():
        outgoing[edge.source].append((edge.target, edge.type.value))

    terminals = {NodeType.VULNERABILITY, NodeType.SECRET, NodeType.THREAT, NodeType.CREDENTIAL_LEAK}
    roots = [n for n in graph.nodes.values() if n.type is NodeType.DOMAIN]
    
    # Iterative DFS with explicit stack to avoid recursion limits
    # Stack: (node, trail, depth)
    max_paths = limit * 4
    max_depth = 6
    
    for root in roots:
        stack: list[tuple[Node, list[tuple[Node, str]], int]] = [(root, [(root, "seed")], 0)]
        
        while stack and len(paths) < max_paths:
            node, trail, depth = stack.pop()
            
            if depth > max_depth:
                continue
            
            if node.type in terminals and len(trail) > 1:
                paths.append(
                    {
                        "score": round(sum(n.risk_score for n, _ in trail), 1),
                        "length": len(trail),
                        "nodes": [
                            {"label": n.label, "type": n.type.value, "via": via, "score": n.risk_score}
                            for n, via in trail
                        ],
                    }
                )
                continue
            
            # Add children to stack (reverse order for DFS)
            children = outgoing.get(node.id, ())
            for target_id, edge_type in reversed(children):
                target = graph.nodes.get(target_id)
                if target is None or any(target.id == n.id for n, _ in trail):
                    continue
                stack.append((target, [*trail, (target, edge_type)], depth + 1))

    paths.sort(key=lambda p: -p["score"])
    return paths[:limit]
