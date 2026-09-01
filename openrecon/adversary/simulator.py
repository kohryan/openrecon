"""Adversary simulation: shortest path from the internet to something worth taking.

The asset graph says what exists. This turns it into an attack graph - states an
attacker can occupy, moves they can make, and what each move costs - and then
asks two questions no inventory tool answers:

    How long would it take someone to get in?
    Which single fix makes that number go up the most?

The second question is the point. Severity tells you how bad a flaw is in
isolation; it cannot tell you that patching a critical CVE changes nothing
because an exposed .env next to it is a cheaper way to the same data. Only a
counterfactual can, and a counterfactual needs a model of cost. That is what
this module is.
"""

from __future__ import annotations

import heapq
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from openrecon.adversary.model import (
    Capability,
    Objective,
    ObjectiveKind,
    Technique,
    TechniqueCatalog,
    objectives_for,
)
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import EdgeType, NodeType

INTERNET = "internet"

# Node types an attacker can meaningfully occupy.
FOOTHOLD_TYPES = {
    NodeType.DOMAIN,
    NodeType.SUBDOMAIN,
    NodeType.IP,
    NodeType.SERVICE,
    NodeType.SECRET,
    NodeType.VULNERABILITY,
    NodeType.CREDENTIAL_LEAK,
    NodeType.THREAT,
    NodeType.TECHNOLOGY,
}

# Structural relations an attacker can ride once they are on one end.
PIVOT_EDGES = {
    EdgeType.RESOLVES_TO,
    EdgeType.EXPOSES,
    EdgeType.RUNS,
    EdgeType.VULNERABLE_TO,
    EdgeType.LEAKS,
    EdgeType.FLAGGED_AS,
    EdgeType.CNAME_TO,
}

# How many findings to run counterfactuals for. Each is a full re-solve; the
# ranking is stable well before this bound on any realistic estate.
COUNTERFACTUAL_LIMIT = 60

# Cap for sibling credential-pivot edges. Without this, a graph with N siblings
# generates O(N^2) edges and Dijkstra hangs on large estates.
SIBLING_PIVOT_CAP = 50

# Cost assigned when no route exists. Large but finite, so comparisons stay sane.
UNREACHABLE = 1e6


@dataclass
class Step:
    """One move in a campaign."""

    technique_id: str
    technique: str
    mitre: str
    from_asset: str
    to_asset: str
    hours: float
    capability: str
    success: float
    noise: float
    rationale: str
    finding_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class Campaign:
    """A priced route from the internet to one objective."""

    objective: str
    objective_kind: str
    objective_detail: str
    target: str
    hours: float
    capability: str
    detection_probability: float
    impact: int
    steps: list[Step] = field(default_factory=list)

    @property
    def priority(self) -> float:
        """Impact per attacker-hour: what a rational adversary optimises for."""
        return self.impact / max(self.hours, 0.05)

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "objective_kind": self.objective_kind,
            "objective_detail": self.objective_detail,
            "target": self.target,
            "hours": round(self.hours, 2),
            "capability": self.capability,
            "detection_probability": round(self.detection_probability, 3),
            "impact": self.impact,
            "priority": round(self.priority, 2),
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass
class Counterfactual:
    """What removing one finding does to the attacker's cheapest route."""

    finding_id: str
    title: str
    severity: str
    baseline_hours: float
    remediated_hours: float
    objective: str

    @property
    def delta(self) -> float:
        return self.remediated_hours - self.baseline_hours

    @property
    def multiplier(self) -> float:
        if self.baseline_hours <= 0:
            return 1.0
        return self.remediated_hours / self.baseline_hours

    @property
    def closes_the_path(self) -> bool:
        return self.remediated_hours >= UNREACHABLE / 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "baseline_hours": round(self.baseline_hours, 2),
            "remediated_hours": (
                None if self.closes_the_path else round(self.remediated_hours, 2)
            ),
            "delta_hours": None if self.closes_the_path else round(self.delta, 2),
            "multiplier": None if self.closes_the_path else round(self.multiplier, 2),
            "closes_the_path": self.closes_the_path,
            "objective": self.objective,
        }


@dataclass
class AdversarySimulation:
    """The full result: how they get in, and what to fix first."""

    reachable: bool
    time_to_compromise: float
    """Attacker-hours on the cheapest route to any objective."""
    easiest_capability: str
    campaigns: list[Campaign] = field(default_factory=list)
    counterfactuals: list[Counterfactual] = field(default_factory=list)
    objectives_found: int = 0
    unreachable_objectives: int = 0
    assumptions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reachable": self.reachable,
            "time_to_compromise_hours": (
                None if not self.reachable else round(self.time_to_compromise, 2)
            ),
            "easiest_capability": self.easiest_capability,
            "objectives_found": self.objectives_found,
            "unreachable_objectives": self.unreachable_objectives,
            "campaigns": [c.to_dict() for c in self.campaigns],
            "counterfactuals": [c.to_dict() for c in self.counterfactuals],
            "assumptions": self.assumptions,
        }


# --------------------------------------------------------------------- solving


@dataclass
class _Move:
    target: str
    technique: Technique
    finding_id: str = ""
    grants_credentials: bool = False


class _AttackGraph:
    """States are (asset, has-credentials). Credentials unlock reuse pivots.

    Modelling credentials as a second layer rather than a path-history flag keeps
    the search a plain shortest-path problem while still capturing the thing that
    makes real intrusions cheap: once you hold one valid credential, the next
    system is a login, not an exploit.
    """

    def __init__(
        self,
        graph: AttackSurfaceGraph,
        catalog: TechniqueCatalog,
        excluded_finding: str | None = None,
    ) -> None:
        self.graph = graph
        self.catalog = catalog
        self.entries: dict[str, list[_Move]] = defaultdict(list)
        self.objectives: dict[str, list[Objective]] = defaultdict(list)
        self._structural: dict[str, set[str]] = defaultdict(set)
        self._siblings: list[str] = []
        self._build(excluded_finding)

    def _build(self, excluded: str | None) -> None:
        for finding in self.graph.findings.values():
            if finding.id == excluded:
                continue
            for node_id in finding.node_ids:
                node = self.graph.nodes.get(node_id)
                if node is None or node.type not in FOOTHOLD_TYPES:
                    continue
                technique = self.catalog.for_finding(finding, node)
                if technique is None:
                    continue
                self.entries[node_id].append(
                    _Move(
                        target=node_id,
                        technique=technique,
                        finding_id=finding.id,
                        grants_credentials=technique.grants is ObjectiveKind.CREDENTIAL_ACCESS,
                    )
                )

        for edge in self.graph.edges.values():
            if edge.type not in PIVOT_EDGES:
                continue
            self._structural[edge.source].add(edge.target)
            self._structural[edge.target].add(edge.source)

        for node in self.graph.nodes.values():
            if node.type not in FOOTHOLD_TYPES:
                continue
            findings = [
                f
                for f in self.graph.findings_for(node.id)
                if f.id != excluded
            ]
            for objective in objectives_for(node, findings):
                self.objectives[node.id].append(objective)
            if node.type in (NodeType.DOMAIN, NodeType.SUBDOMAIN, NodeType.SERVICE):
                self._siblings.append(node.id)

    def moves_from(self, node_id: str, has_credentials: bool) -> list[tuple[str, bool, Technique]]:
        out: list[tuple[str, bool, Technique]] = []
        host_pivot = self.catalog.get("pivot/shared-host")
        cred_pivot = self.catalog.get("pivot/shared-credential")

        if host_pivot:
            for neighbour in self._structural.get(node_id, ()):
                if neighbour in self.graph.nodes:
                    out.append((neighbour, has_credentials, host_pivot))

        if has_credentials and cred_pivot:
            # Cap sibling pivots to avoid O(N^2) explosion on large graphs
            siblings = self._siblings[:SIBLING_PIVOT_CAP]
            for sibling in siblings:
                if sibling != node_id:
                    out.append((sibling, True, cred_pivot))
        return out


def _solve(attack: _AttackGraph) -> dict[str, tuple[float, list[Step], Capability, float]]:
    """Dijkstra from the internet to every reachable objective."""
    best: dict[tuple[str, bool], float] = {}
    trail: dict[tuple[str, bool], tuple[tuple[str, bool] | None, Step | None]] = {}
    queue: list[tuple[float, str, bool]] = []

    for node_id, moves in attack.entries.items():
        for move in moves:
            cost = move.technique.effective_hours
            state = (node_id, move.grants_credentials)
            if cost < best.get(state, float("inf")):
                best[state] = cost
                trail[state] = (
                    None,
                    Step(
                        technique_id=move.technique.id,
                        technique=move.technique.name,
                        mitre=move.technique.mitre,
                        from_asset=INTERNET,
                        to_asset=_label(attack.graph, node_id),
                        hours=round(cost, 2),
                        capability=move.technique.capability.label,
                        success=move.technique.success,
                        noise=move.technique.noise,
                        rationale=move.technique.rationale,
                        finding_id=move.finding_id,
                    ),
                )
                heapq.heappush(queue, (cost, node_id, move.grants_credentials))

    settled: set[tuple[str, bool]] = set()
    while queue:
        cost, node_id, creds = heapq.heappop(queue)
        state = (node_id, creds)
        if state in settled or cost > best.get(state, float("inf")):
            continue
        settled.add(state)

        for target, next_creds, technique in attack.moves_from(node_id, creds):
            new_cost = cost + technique.effective_hours
            next_state = (target, next_creds)
            if new_cost < best.get(next_state, float("inf")):
                best[next_state] = new_cost
                trail[next_state] = (
                    state,
                    Step(
                        technique_id=technique.id,
                        technique=technique.name,
                        mitre=technique.mitre,
                        from_asset=_label(attack.graph, node_id),
                        to_asset=_label(attack.graph, target),
                        hours=round(technique.effective_hours, 2),
                        capability=technique.capability.label,
                        success=technique.success,
                        noise=technique.noise,
                        rationale=technique.rationale,
                    ),
                )
                heapq.heappush(queue, (new_cost, target, next_creds))

    # Collapse the two credential layers: an objective is reached either way.
    reached: dict[str, tuple[float, list[Step], Capability, float]] = {}
    for (node_id, creds), cost in best.items():
        for objective in attack.objectives.get(node_id, ()):
            existing = reached.get(objective.id)
            if existing and existing[0] <= cost:
                continue
            steps = _reconstruct(trail, (node_id, creds))
            capability = max(
                (Capability[s.capability.upper()] for s in steps), default=Capability.OPPORTUNIST
            )
            detection = 1.0
            for step in steps:
                detection *= 1 - step.noise
            reached[objective.id] = (cost, steps, capability, 1 - detection)
    return reached


def _reconstruct(
    trail: dict[tuple[str, bool], tuple[tuple[str, bool] | None, Step | None]],
    state: tuple[str, bool],
) -> list[Step]:
    steps: list[Step] = []
    seen: set[tuple[str, bool]] = set()
    while state in trail and state not in seen:
        seen.add(state)
        previous, step = trail[state]
        if step is not None:
            steps.append(step)
        if previous is None:
            break
        state = previous
    return list(reversed(steps))


def _label(graph: AttackSurfaceGraph, node_id: str) -> str:
    node = graph.nodes.get(node_id)
    return node.label if node else node_id


# ---------------------------------------------------------------------- public


def simulate(
    graph: AttackSurfaceGraph,
    *,
    catalog: TechniqueCatalog | None = None,
    max_campaigns: int = 8,
    progress: Callable[[str, str, dict[str, Any]], None] | None = None,
) -> AdversarySimulation:
    """Price every route an attacker could take, then rank fixes by their effect."""
    catalog = catalog or TechniqueCatalog()
    
    if progress:
        progress("adversary", "build", {"nodes": len(graph.nodes), "findings": len(graph.findings)})
    
    attack = _AttackGraph(graph, catalog)
    
    if progress:
        progress("adversary", "solve", {})
    
    reached = _solve(attack)

    all_objectives = {
        objective.id: objective
        for objectives in attack.objectives.values()
        for objective in objectives
    }

    campaigns: list[Campaign] = []
    for objective_id, (cost, steps, capability, detection) in reached.items():
        objective = all_objectives[objective_id]
        campaigns.append(
            Campaign(
                objective=objective.label,
                objective_kind=objective.kind.value,
                objective_detail=objective.detail,
                target=_label(graph, objective.node_id),
                hours=cost,
                capability=capability.label,
                detection_probability=detection,
                impact=objective.impact,
                steps=steps,
            )
        )
    # Rank by what an adversary optimises for: impact per hour spent.
    campaigns.sort(key=lambda c: (-c.priority, c.hours))

    baseline = min((c.hours for c in campaigns), default=UNREACHABLE)
    reachable = bool(campaigns)

    simulation = AdversarySimulation(
        reachable=reachable,
        time_to_compromise=baseline if reachable else UNREACHABLE,
        easiest_capability=(
            min(campaigns, key=lambda c: c.hours).capability if reachable else "none modelled"
        ),
        campaigns=campaigns[:max_campaigns],
        objectives_found=len(all_objectives),
        unreachable_objectives=len(all_objectives) - len(reached),
        assumptions=_assumptions(reachable),
    )
    if reachable:
        if progress:
            progress("adversary", "counterfactuals", {"limit": COUNTERFACTUAL_LIMIT})
        simulation.counterfactuals = _counterfactuals(graph, catalog, baseline, campaigns[0], progress)
    return simulation


def _counterfactuals(
    graph: AttackSurfaceGraph,
    catalog: TechniqueCatalog,
    baseline: float,
    top: Campaign,
    progress: Callable[[str, str, dict[str, Any]], None] | None = None,
) -> list[Counterfactual]:
    """Re-solve without each finding to measure its real contribution.

    This is the part severity cannot do. A critical CVE that sits behind a
    cheaper open door scores zero here, because removing it does not slow the
    attacker down at all - and telling someone to patch it first would be wrong.
    """
    candidates = sorted(
        graph.findings.values(), key=lambda f: (-f.risk_score, f.title)
    )[:COUNTERFACTUAL_LIMIT]

    results: list[Counterfactual] = []
    for i, finding in enumerate(candidates):
        if progress and i > 0 and i % 10 == 0:
            progress("adversary", "counterfactual", {"done": i, "total": len(candidates)})
        
        attack = _AttackGraph(graph, catalog, excluded_finding=finding.id)
        reached = _solve(attack)
        remediated = min((cost for cost, *_ in reached.values()), default=UNREACHABLE)
        if remediated <= baseline + 1e-9:
            continue  # removing it changes nothing an attacker would notice
        results.append(
            Counterfactual(
                finding_id=finding.id,
                title=finding.title,
                severity=finding.severity.value,
                baseline_hours=baseline,
                remediated_hours=remediated,
                objective=top.objective,
            )
        )

    results.sort(key=lambda c: (-c.closes_the_path, -c.delta))
    return results


def _assumptions(reachable: bool) -> list[str]:
    base = [
        "Costs are modelled attacker-hours for a competent operator, not measurements.",
        "Effort is divided by success probability, so a coin-flip technique costs double.",
        "Credential reuse across sibling assets is assumed possible once any credential is held.",
        "Only weaknesses this scan actually observed are priced; unseen paths are not modelled.",
    ]
    if not reachable:
        base.append(
            "No objective was reachable from the observed findings - which reflects scan "
            "coverage as much as it reflects your defences."
        )
    return base
