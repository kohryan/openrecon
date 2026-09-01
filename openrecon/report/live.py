"""Live scan view: the pipeline drawing itself while it runs.

A scan takes 30-90 seconds and spends most of it waiting on other people's APIs.
A frozen cursor makes that feel broken, so the pipeline renders as a table that
fills in top to bottom - which stage is working, which collectors are in flight,
what each one found. On a non-interactive terminal it degrades to plain lines so
CI logs and `| tee` stay readable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from openrecon.report.theme import ACCENT, FAINT, GLYPHS, MUTED, humanize_duration

PENDING, RUNNING, DONE, EMPTY = "pending", "running", "done", "empty"


@dataclass
class StageState:
    name: str
    status: str = PENDING
    collectors: list[str] = field(default_factory=list)
    running: set[str] = field(default_factory=set)
    finished: dict[str, dict[str, Any]] = field(default_factory=dict)
    failed: dict[str, str] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)
    started_at: float = 0.0
    duration: float = 0.0
    probing_total: int = 0
    probing_done: int = 0
    last_activity: float = 0.0  # timestamp of last progress event

    @property
    def assets(self) -> int:
        return sum(int(d.get("nodes", 0)) for d in self.finished.values())

    @property
    def findings(self) -> int:
        return sum(int(d.get("findings", 0)) for d in self.finished.values())

    @property
    def is_stalled(self) -> bool:
        """True if running but no activity for 30+ seconds."""
        if self.status != RUNNING:
            return False
        if not self.running:
            return False
        return (time.monotonic() - self.last_activity) > 30.0


class ScanMonitor:
    """Consumes pipeline progress events and renders them."""

    def __init__(self, console: Console, target: str, mode: str, stages: list[str]) -> None:
        self.console = console
        self.target = target
        self.mode = mode
        self.stages: dict[str, StageState] = {s: StageState(s) for s in stages}
        self.started = time.monotonic()
        self.total_assets = 0
        self.total_findings = 0
        self.note = ""
        self._spinner = Spinner("dots", style=ACCENT)
        self._live: Live | None = None
        self.interactive = console.is_terminal and not console.is_jupyter
        self._last_render = 0.0
        self._render_interval = 1.0  # minimum seconds between timer-based renders

    # ------------------------------------------------------------------ events

    def __call__(self, event: str, name: str, data: dict[str, Any]) -> None:
        handler = getattr(self, f"_on_{event.replace('-', '_')}", None)
        if handler:
            handler(name, data)
        self._refresh()

    def _on_stage_start(self, name: str, data: dict[str, Any]) -> None:
        stage = self.stages.setdefault(name, StageState(name))
        stage.collectors = list(data.get("collectors") or [])
        stage.skipped = dict(data.get("skipped") or {})
        stage.started_at = time.monotonic()
        stage.last_activity = time.monotonic()
        stage.status = RUNNING if stage.collectors else EMPTY

    def _on_collector_start(self, name: str, data: dict[str, Any]) -> None:
        stage = self.stages.get(data.get("stage", ""))
        if stage:
            stage.running.add(name)
            stage.last_activity = time.monotonic()

    def _on_collector_done(self, name: str, data: dict[str, Any]) -> None:
        stage = self.stages.get(data.get("stage", ""))
        if not stage:
            return
        stage.running.discard(name)
        stage.finished[name] = data
        stage.last_activity = time.monotonic()
        self.total_assets += int(data.get("nodes", 0))
        self.total_findings += int(data.get("findings", 0))

    def _on_collector_failed(self, name: str, data: dict[str, Any]) -> None:
        stage = self.stages.get(data.get("stage", ""))
        if stage:
            stage.running.discard(name)
            stage.failed[name] = str(data.get("error", "failed"))
            stage.last_activity = time.monotonic()

    def _on_probing_start(self, name: str, data: dict[str, Any]) -> None:
        stage = self.stages.get(data.get("stage", ""))
        if stage:
            stage.probing_total = int(data.get("total", 0))
            stage.probing_done = int(data.get("done", 0))
            stage.last_activity = time.monotonic()

    def _on_probing(self, name: str, data: dict[str, Any]) -> None:
        stage = self.stages.get(data.get("stage", ""))
        if stage:
            stage.probing_done = int(data.get("done", stage.probing_done + 1))
            stage.probing_total = int(data.get("total", stage.probing_total))
            stage.last_activity = time.monotonic()

    def _on_probing_done(self, name: str, data: dict[str, Any]) -> None:
        stage = self.stages.get(data.get("stage", ""))
        if stage:
            stage.probing_done = int(data.get("done", stage.probing_total))
            stage.probing_total = int(data.get("total", stage.probing_total))
            stage.last_activity = time.monotonic()

    def _on_stage_done(self, name: str, data: dict[str, Any]) -> None:
        stage = self.stages.get(name)
        if not stage:
            return
        stage.duration = float(data.get("duration", 0.0))
        stage.running.clear()
        stage.status = DONE if (stage.finished or stage.failed) else EMPTY
        if "nodes" in data:
            self.total_assets = int(data["nodes"])

    def _on_risk(self, name: str, data: dict[str, Any]) -> None:
        self.note = "scoring risk"

    def _on_scan_done(self, name: str, data: dict[str, Any]) -> None:
        self.note = ""
        self.total_assets = int(data.get("nodes", self.total_assets))
        self.total_findings = int(data.get("findings", self.total_findings))

    def set_note(self, note: str) -> None:
        self.note = note
        self._refresh()

    # ----------------------------------------------------------------- lifecycle

    def __enter__(self) -> ScanMonitor:
        if self.interactive:
            self._live = Live(
                self._render(),
                console=self.console,
                refresh_per_second=12,
                transient=True,
            )
            self._live.__enter__()
            # Start a background timer to refresh the display even when no events
            # arrive — this is what makes a stalled collector visible.
            import threading
            self._timer = threading.Timer(5.0, self._timer_refresh)
            self._timer.daemon = True
            self._timer.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._live:
            self._live.__exit__(*exc)
            self._live = None
        if hasattr(self, '_timer'):
            self._timer.cancel()
        self.console.print(self._render(final=True))

    def _timer_refresh(self) -> None:
        """Periodic refresh so stall indicators update even without events."""
        self._refresh()
        if self._live:
            import threading
            self._timer = threading.Timer(5.0, self._timer_refresh)
            self._timer.daemon = True
            self._timer.start()

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self._render())

    # ------------------------------------------------------------------ render

    def _render(self, final: bool = False) -> RenderableType:
        table = Table.grid(padding=(0, 1))
        table.add_column(width=2, no_wrap=True)          # status glyph
        table.add_column(width=15, no_wrap=True)         # stage
        table.add_column(ratio=1, overflow="ellipsis")   # collectors
        table.add_column(width=7, justify="right", no_wrap=True)   # timing
        table.add_column(width=18, justify="right", no_wrap=True)  # yield

        for stage in self.stages.values():
            table.add_row(*self._stage_row(stage, final))

        elapsed = humanize_duration(time.monotonic() - self.started)
        footer = Text()
        footer.append(f"  {elapsed}", style=MUTED)
        footer.append("   ", style=MUTED)
        footer.append(f"{self.total_assets}", style="bold")
        footer.append(" assets", style=MUTED)
        footer.append("   ")
        footer.append(f"{self.total_findings}", style="bold" if self.total_findings else MUTED)
        footer.append(" findings", style=MUTED)
        if self.note:
            footer.append(f"   {GLYPHS.bullet} {self.note}", style=ACCENT)

        return Group(table, Text(""), footer)

    def _stage_row(self, stage: StageState, final: bool) -> tuple[RenderableType, ...]:
        if stage.status == RUNNING and not final:
            glyph: RenderableType = self._spinner
            stage_style = "bold " + ACCENT
        elif stage.status == DONE:
            if stage.failed and not stage.finished:
                glyph = Text(GLYPHS.fail, style="red")
            elif stage.failed:
                glyph = Text(GLYPHS.warn, style="yellow")
            else:
                glyph = Text(GLYPHS.ok, style="green")
            stage_style = "white"
        elif stage.status == EMPTY:
            glyph = Text(GLYPHS.skip, style=FAINT)
            stage_style = FAINT
        else:
            glyph = Text(GLYPHS.pending, style=FAINT)
            stage_style = FAINT

        detail = Text()
        if stage.status == PENDING:
            detail.append("waiting", style=FAINT)
        elif stage.status == EMPTY:
            reasons = set(stage.skipped.values())
            hint = "nothing to run"
            if reasons and all("active mode" in r for r in reasons):
                hint = "passive mode - skipped"
            elif reasons and all("API key" in r for r in reasons):
                hint = "no API key - skipped"
            detail.append(hint, style=FAINT)
        else:
            parts: list[Text] = []
            for name in stage.collectors:
                if name in stage.failed:
                    parts.append(Text(f"{name}{GLYPHS.warn}", style="red"))
                elif name in stage.finished:
                    parts.append(Text(name, style=MUTED))
                elif name in stage.running:
                    parts.append(Text(name, style=ACCENT))
                else:
                    parts.append(Text(name, style=FAINT))
            for i, part in enumerate(parts):
                if i:
                    detail.append(" ")
                detail.append_text(part)
            if stage.probing_total and stage.status == RUNNING and not final:
                pct = 100 * stage.probing_done / max(stage.probing_total, 1)
                detail.append("  ")
                detail.append(
                    Text.assemble(
                        (f"{stage.probing_done}/{stage.probing_total}", "bold " + ACCENT),
                        (" probed", FAINT),
                        (f"  {pct:.0f}%", MUTED),
                    )
                )
            # Show stall indicator if running but no activity for 30+ seconds
            if stage.is_stalled and not final:
                detail.append("  ")
                detail.append(Text("⚠ stalled", style="yellow"))

        timing = Text("", style=FAINT)
        if stage.status == DONE:
            timing = Text(humanize_duration(stage.duration), style=FAINT)
        elif stage.status == RUNNING and not final:
            timing = Text(humanize_duration(time.monotonic() - stage.started_at), style=FAINT)

        yield_text = Text()
        if stage.assets:
            yield_text.append(f"+{stage.assets}", style="green")
            yield_text.append(" assets", style=FAINT)
        if stage.findings:
            if yield_text.plain:
                yield_text.append("  ")
            yield_text.append(f"{stage.findings}", style="yellow")
            yield_text.append(" fnd", style=FAINT)

        return (glyph, Text(stage.name, style=stage_style), detail, timing, yield_text)


class PlainMonitor:
    """Non-interactive fallback: one line per stage, no cursor tricks."""

    def __init__(self, console: Console, target: str, mode: str, stages: list[str]) -> None:
        self.console = console
        self.stages = stages
        self.interactive = False

    def __call__(self, event: str, name: str, data: dict[str, Any]) -> None:
        if event == "stage-done":
            ran = data.get("ran") or []
            if not ran:
                return
            node_suffix = f", {data['nodes']} nodes" if "nodes" in data else ""
            self.console.print(
                f"  {GLYPHS.ok} {name:<15} {', '.join(ran)}  "
                f"({humanize_duration(float(data.get('duration', 0)))}{node_suffix})"
            )
        elif event == "probing":
            # Long scan, one line every 50 hosts so piped/CI logs show movement.
            done = int(data.get("done", 0))
            total = int(data.get("total", 0))
            if total and done % 50 == 0:
                self.console.print(
                    f"  {GLYPHS.bullet} {name} probing {done}/{total} "
                    f"({100 * done / total:.0f}%)"
                )
        elif event == "collector-failed":
            self.console.print(f"  {GLYPHS.warn} {name}: {data.get('error', '')}")

    def set_note(self, note: str) -> None:
        if note:
            self.console.print(f"  {GLYPHS.bullet} {note}")

    def __enter__(self) -> PlainMonitor:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def make_monitor(
    console: Console, target: str, mode: str, stages: list[str], quiet: bool
) -> Any:
    if quiet:
        return _NullMonitor()
    if console.is_terminal:
        return ScanMonitor(console, target, mode, stages)
    return PlainMonitor(console, target, mode, stages)


class _NullMonitor:
    interactive = False

    def __call__(self, *_a: Any, **_k: Any) -> None:
        return None

    def set_note(self, note: str) -> None:
        return None

    def __enter__(self) -> _NullMonitor:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None
