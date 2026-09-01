"""Scan history on disk, so change over time is a first-class question.

An attack surface is only interesting as a time series: what appeared this week
that was not there last week?
"""

from __future__ import annotations

import re
from pathlib import Path

from openrecon.core.graph import AttackSurfaceGraph

SAFE = re.compile(r"[^a-z0-9_.-]+")


class ScanHistory:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    def dir_for(self, target: str) -> Path:
        return self.root / SAFE.sub("_", target.lower())

    def save(self, graph: AttackSurfaceGraph) -> Path:
        stamp = graph.meta.started_at.strftime("%Y%m%dT%H%M%SZ")
        path = self.dir_for(graph.meta.target) / f"{stamp}.json"
        return graph.save(path)

    def scans(self, target: str) -> list[Path]:
        directory = self.dir_for(target)
        if not directory.exists():
            return []
        return sorted(directory.glob("*.json"))

    def previous(self, target: str, before: Path | None = None) -> AttackSurfaceGraph | None:
        scans = self.scans(target)
        if before is not None:
            scans = [p for p in scans if p != before]
        if not scans:
            return None
        try:
            return AttackSurfaceGraph.load(scans[-1])
        except (ValueError, OSError):
            return None
