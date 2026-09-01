"""The engine: runs collectors stage by stage, feeding each one the graph so far.

    DOMAIN -> registration -> dns -> subdomains -> certificates -> addresses
           -> network -> services -> fingerprint -> vulnerabilities
           -> secrets -> threat -> risk -> AI analyst

Collectors inside a stage run concurrently and are isolated from each other:
one failing collector degrades the map, it never aborts the scan.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from openrecon import __version__
from openrecon.adversary import simulate
from openrecon.collectors import STAGES, CollectorContext, all_collectors
from openrecon.collectors.base import Collector
from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import CollectorResult, ScanMode, utcnow
from openrecon.core.net import DnsClient, HttpClient
from openrecon.coverage import assess as assess_coverage
from openrecon.risk.engine import RiskEngine
from openrecon.risk.engine import qualify as qualify_grade
from openrecon.risk.patterns import mine as mine_patterns
from openrecon.scope import Scope

ProgressHook = Callable[[str, str, dict[str, Any]], None]


@dataclass
class StageReport:
    stage: str
    ran: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    failed: dict[str, str] = field(default_factory=dict)
    duration: float = 0.0
    stats: dict[str, Any] = field(default_factory=dict)


class Pipeline:
    """Orchestrates a full attack-surface scan for one target."""

    def __init__(
        self,
        config: Config,
        *,
        scope: Scope | None = None,
        progress: ProgressHook | None = None,
    ) -> None:
        self.config = config
        self.scope = scope
        self.progress = progress or (lambda *_a, **_k: None)
        self.reports: list[StageReport] = []

    async def run(self, target: str) -> AttackSurfaceGraph:
        target = target.lower().strip().rstrip(".")
        mode = "active" if self.config.active else "passive"
        graph = AttackSurfaceGraph.seed(target, mode=mode, version=__version__)

        self.progress("scan-start", target, {"stages": list(STAGES), "mode": mode})
        async with HttpClient(self.config) as http:
            ctx = CollectorContext(
                config=self.config,
                http=http,
                dns=DnsClient(self.config),
                scope=self.scope,
                progress=self.progress,
            )
            for stage in STAGES:
                report = await self._run_stage(stage, ctx, graph)
                self.reports.append(report)
                graph.meta.collectors_run.extend(report.ran)
                graph.meta.collectors_skipped.update(report.skipped)

        self.progress("risk", "risk", {})
        RiskEngine(self.config).score(graph)

        # Three analyses the asset graph makes possible, in dependency order:
        # coverage qualifies everything, the adversary model needs scored
        # findings, and pattern mining needs the finished graph.
        self.progress("analysis", "coverage", {})
        graph.coverage = assess_coverage(graph).to_dict()

        self.progress("analysis", "adversary", {})
        graph.adversary = simulate(graph, progress=self.progress).to_dict()

        self.progress("analysis", "patterns", {})
        graph.patterns = [p.to_dict() for p in mine_patterns(graph)]

        # Attacker cost and scan coverage can both overrule a grade earned by
        # counting findings, so the verdict is settled last.
        qualify_grade(graph)

        graph.meta.finished_at = utcnow()
        self.progress(
            "scan-done",
            target,
            {"nodes": len(graph.nodes), "findings": len(graph.findings)},
        )
        return graph

    # ------------------------------------------------------------------ stages

    async def _run_stage(
        self, stage: str, ctx: CollectorContext, graph: AttackSurfaceGraph
    ) -> StageReport:
        report = StageReport(stage=stage)
        started = time.monotonic()
        instances: list[Collector] = []

        for name, cls in sorted(all_collectors().items()):
            if cls.stage != stage:
                continue
            collector = cls(ctx)
            ok, reason = collector.available()
            if not ok:
                report.skipped[name] = reason
                continue
            if collector.mode is ScanMode.ACTIVE and ctx.scope is None:
                report.skipped[name] = "no authorization scope loaded"
                continue
            instances.append(collector)

        if not instances:
            report.duration = time.monotonic() - started
            self.progress("stage-done", stage, {"ran": [], "skipped": report.skipped})
            return report

        self.progress("stage", stage, {"collectors": [c.name for c in instances]})

        outcomes = await asyncio.gather(
            *(self._run_collector(c, graph) for c in instances), return_exceptions=True
        )

        for collector, outcome in zip(instances, outcomes, strict=True):
            if isinstance(outcome, BaseException):
                report.failed[collector.name] = f"{type(outcome).__name__}: {outcome}"
                graph.meta.errors.append(f"{collector.name}: {outcome}")
                continue
            graph.absorb(outcome)
            report.ran.append(collector.name)
            report.stats[collector.name] = outcome.stats
            self.progress(
                "collector",
                collector.name,
                {
                    "nodes": len(outcome.nodes),
                    "findings": len(outcome.findings),
                    "stats": outcome.stats,
                },
            )

        report.duration = time.monotonic() - started
        self.progress(
            "stage-done",
            stage,
            {"ran": report.ran, "skipped": report.skipped, "failed": report.failed,
             "duration": report.duration, "nodes": len(graph.nodes)},
        )
        return report

    async def _run_collector(
        self, collector: Collector, graph: AttackSurfaceGraph
    ) -> CollectorResult:
        try:
            return await asyncio.wait_for(collector.collect(graph), timeout=600)
        except TimeoutError:
            return CollectorResult(errors=[f"{collector.name}: timed out after 600s"])

    # ----------------------------------------------------------------- helpers

    def plan(self) -> dict[str, list[dict[str, Any]]]:
        """What would run, without running it. Used by `openrecon collectors`."""
        out: dict[str, list[dict[str, Any]]] = {}
        for stage in STAGES:
            entries = []
            for name, cls in sorted(all_collectors().items()):
                if cls.stage != stage:
                    continue
                missing = [k for k in cls.requires_keys if not self.config.key(k)]
                enabled = (
                    self.config.collector_allowed(name)
                    and not missing
                    and (cls.mode is ScanMode.PASSIVE or self.config.active)
                )
                entries.append(
                    {
                        "name": name,
                        "mode": cls.mode.value,
                        "description": cls.description,
                        "enabled": enabled,
                        "missing_keys": missing,
                    }
                )
            if entries:
                out[stage] = entries
        return out
