"""Presentation layer: design tokens, the live scan view, and the results screen.

Rendering is tested through a recording console rather than by eye, so a change
that silently drops the exposure panel or the KEV badge fails here.
"""

from __future__ import annotations

import pytest
from rich.console import Console

from openrecon.core.models import Severity
from openrecon.report.console import masthead, next_steps, render_report
from openrecon.report.live import PlainMonitor, ScanMonitor, make_monitor
from openrecon.report.theme import (
    GLYPHS,
    Glyphs,
    grade_badge,
    humanize_duration,
    meter,
    plural,
    risk_style,
    severity_badge,
    severity_distribution,
)
from openrecon.risk.engine import RiskEngine

STAGES = ["registration", "dns", "subdomains"]


def _console(width: int = 100, terminal: bool = False) -> Console:
    return Console(record=True, width=width, force_terminal=terminal, color_system="truecolor")


# --------------------------------------------------------------------- theme


@pytest.mark.parametrize(
    "score,expected_bucket",
    [(90, "critical"), (50, "high"), (30, "medium"), (5, "low"), (0, "none")],
)
def test_risk_style_buckets(score, expected_bucket):
    from openrecon.report.theme import SEVERITY_COLOR

    style = risk_style(score)
    if expected_bucket == "none":
        assert style == "white"
    else:
        assert style == SEVERITY_COLOR[expected_bucket]


def test_severity_distribution_is_exactly_the_requested_width():
    for counts in (
        {"critical": 1},
        {"critical": 2, "high": 9, "medium": 21, "low": 40, "info": 3},
        {"low": 1, "info": 1},
        {"critical": 1000, "low": 1},
    ):
        assert len(severity_distribution(counts, width=30).plain) == 30


def test_severity_distribution_keeps_a_single_finding_visible():
    """A lone critical among hundreds of lows must not round away to nothing."""
    bar = severity_distribution({"critical": 1, "low": 400}, width=30)
    from openrecon.report.theme import SEVERITY_COLOR

    spans = {str(s.style) for s in bar.spans}
    assert SEVERITY_COLOR["critical"] in spans


def test_empty_distribution_renders_an_empty_bar():
    assert severity_distribution({}, width=12).plain == GLYPHS.bar_empty * 12


def test_meter_scales_and_clamps():
    assert len(meter(5, 10, width=20).plain) == 20
    assert meter(0, 0, width=8).plain == GLYPHS.bar_empty * 8
    assert meter(99, 10, width=8).plain.count(GLYPHS.bar_full) == 8


def test_badges_carry_their_severity_colour():
    badge = severity_badge(Severity.CRITICAL)
    assert "CRITICAL" in badge.plain
    assert grade_badge("A").plain.strip() == "A"


@pytest.mark.parametrize(
    "seconds,expected", [(0.04, "0.04s"), (0.4, "0.40s"), (41.25, "41.2s"), (60, "1m00s"), (135, "2m15s")]
)
def test_humanize_duration(seconds, expected):
    assert humanize_duration(seconds) == expected


def test_plural():
    assert plural(1, "collector") == "1 collector"
    assert plural(3, "collector") == "3 collectors"
    assert plural(2, "address", "addresses") == "2 addresses"


def test_ascii_fallback_avoids_box_glyphs():
    ascii_glyphs = Glyphs(unicode=False)
    assert ascii_glyphs.ok.isascii()
    assert ascii_glyphs.arrow.isascii()
    assert ascii_glyphs.bar_full.isascii()


# ----------------------------------------------------------------- live view


def _drive(monitor: ScanMonitor) -> None:
    monitor("scan-start", "example.com", {"stages": STAGES, "mode": "passive"})
    monitor("stage-start", "registration", {"collectors": ["rdap"], "skipped": {}})
    monitor("collector-start", "rdap", {"stage": "registration"})
    monitor("collector-done", "rdap", {"stage": "registration", "nodes": 2, "findings": 1})
    monitor("stage-done", "registration", {"duration": 0.9, "ran": ["rdap"], "nodes": 3})


def test_live_view_shows_stages_collectors_and_yield():
    console = _console(terminal=True)
    monitor = ScanMonitor(console, "example.com", "passive", STAGES)
    _drive(monitor)
    console.print(monitor._render(final=True))
    out = console.export_text()

    assert "registration" in out and "rdap" in out
    assert GLYPHS.ok in out
    assert "+2" in out and "assets" in out
    assert "dns" in out and "subdomains" in out, "pending stages stay visible"


def test_live_view_marks_a_stage_that_lost_every_collector():
    console = _console(terminal=True)
    monitor = ScanMonitor(console, "example.com", "passive", STAGES)
    monitor("stage-start", "dns", {"collectors": ["dns"], "skipped": {}})
    monitor("collector-start", "dns", {"stage": "dns"})
    monitor("collector-failed", "dns", {"stage": "dns", "error": "RuntimeError: boom"})
    monitor("stage-done", "dns", {"duration": 1.0, "ran": [], "failed": {"dns": "boom"}})
    console.print(monitor._render(final=True))
    assert GLYPHS.fail in console.export_text()


def test_live_view_explains_why_a_stage_was_empty():
    console = _console(terminal=True)
    monitor = ScanMonitor(console, "example.com", "passive", ["services"])
    monitor(
        "stage-start",
        "services",
        {"collectors": [], "skipped": {"ports": "active mode disabled (use --active ...)"}},
    )
    monitor("stage-done", "services", {"duration": 0.0, "ran": [], "skipped": {}})
    console.print(monitor._render(final=True))
    assert "passive mode" in console.export_text()


def test_live_view_totals_track_the_scan():
    monitor = ScanMonitor(_console(terminal=True), "example.com", "passive", STAGES)
    _drive(monitor)
    monitor("stage-start", "subdomains", {"collectors": ["ct"], "skipped": {}})
    monitor("collector-done", "ct", {"stage": "subdomains", "nodes": 240, "findings": 0})
    monitor("scan-done", "example.com", {"nodes": 243, "findings": 1})
    assert monitor.total_assets == 243
    assert monitor.total_findings == 1


def test_unknown_events_are_ignored():
    monitor = ScanMonitor(_console(terminal=True), "example.com", "passive", STAGES)
    monitor("something-new", "x", {})  # must not raise


def test_monitor_selection_matches_the_output_stream():
    assert isinstance(make_monitor(_console(terminal=True), "x", "passive", STAGES, False), ScanMonitor)
    assert isinstance(make_monitor(_console(), "x", "passive", STAGES, False), PlainMonitor)
    quiet = make_monitor(_console(terminal=True), "x", "passive", STAGES, True)
    assert not isinstance(quiet, (ScanMonitor, PlainMonitor))


def test_plain_monitor_writes_one_line_per_stage():
    console = _console()
    monitor = PlainMonitor(console, "example.com", "passive", STAGES)
    monitor("stage-done", "registration", {"ran": ["rdap"], "duration": 0.9})
    monitor("stage-done", "services", {"ran": [], "duration": 0.0})
    monitor("collector-failed", "dns", {"error": "boom"})
    out = console.export_text()
    assert "registration" in out and "rdap" in out
    assert "services" not in out, "an empty stage adds no line in plain mode"
    assert "boom" in out


# --------------------------------------------------------------- results view


def test_masthead_names_the_target_and_mode():
    console = _console()
    console.print(masthead("example.com", "active", "0.1.0"))
    out = console.export_text()
    assert "openrecon" in out and "example.com" in out and "ACTIVE" in out


def test_report_contains_every_section(graph):
    RiskEngine().score(graph)
    console = _console(width=110)
    render_report(graph, console)
    out = console.export_text()

    for expected in (
        "DIGITAL EXPOSURE",
        "RISK POSTURE",
        "ATTACK SURFACE",
        "ATTACK PATHS",
        "FINDINGS",
        "dev.example.com",
        "CVE-2021-22205",
        "KEV",
    ):
        assert expected in out, f"missing {expected!r}"


def test_report_survives_a_narrow_terminal(graph):
    RiskEngine().score(graph)
    console = _console(width=60)
    render_report(graph, console)
    out = console.export_text()
    assert "DIGITAL EXPOSURE" in out
    assert max(len(line) for line in out.splitlines()) <= 60


def test_report_on_an_empty_graph_says_so():
    from openrecon.core.graph import AttackSurfaceGraph

    g = AttackSurfaceGraph.seed("nothing.example")
    RiskEngine().score(g)
    console = _console()
    render_report(g, console)
    out = console.export_text()
    assert "no subdomains discovered" in out
    assert "FINDINGS" not in out, "an empty findings table is noise"


def test_next_steps_offers_the_obvious_follow_up(graph):
    RiskEngine().score(graph)
    console = _console()
    console.print(next_steps(graph, "out/example.com/x.json", "out/example.com.html"))
    out = console.export_text()
    assert "out/example.com/x.json" in out
    assert "openrecon report" in out


def test_next_steps_suggests_active_only_for_a_passive_scan(graph):
    from openrecon.core.graph import AttackSurfaceGraph

    passive = AttackSurfaceGraph.seed("example.com", mode="passive")
    RiskEngine().score(passive)
    console = _console()
    console.print(next_steps(passive, "g.json", None))
    assert "--active" in console.export_text()

    RiskEngine().score(graph)  # the fixture is an active scan
    console2 = _console()
    console2.print(next_steps(graph, "g.json", None))
    assert "--active" not in console2.export_text()
