"""The terminal report: exposure panel, attack surface, findings, verdict."""

from __future__ import annotations

from typing import Any

from rich import box
from rich.columns import Columns
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import SEVERITY_ORDER, EdgeType, NodeType
from openrecon.report.theme import (
    ACCENT,
    FAINT,
    GLYPHS,
    GRADE_COLOR,
    MUTED,
    NODE_MARK,
    SEVERITY_COLOR,
    grade_badge,
    humanize_duration,
    meter,
    plural,
    risk_style,
    severity_badge,
    severity_distribution,
)
from openrecon.risk.engine import attack_paths

PANEL = box.ROUNDED

# Exposure rows that should read as alarming the moment they are non-zero.
LOUD_ROWS = {
    "Leaked credentials": SEVERITY_COLOR["critical"],
    "Secrets detected": SEVERITY_COLOR["critical"],
    "Known vulnerabilities": SEVERITY_COLOR["high"],
    "Suspicious assets": SEVERITY_COLOR["high"],
    "Exposed services": SEVERITY_COLOR["medium"],
    "Expired certificates": SEVERITY_COLOR["medium"],
}


def masthead(target: str, mode: str, version: str) -> RenderableType:
    """The lockup shown before a scan starts."""
    title = Text()
    title.append("openrecon", style=f"bold {ACCENT}")
    title.append(f"  v{version}", style=FAINT)
    title.append("   attack surface intelligence", style=MUTED)

    line = Text()
    line.append(f"{GLYPHS.arrow} ", style=FAINT)
    line.append(target, style="bold white")
    line.append("   ")
    line.append(
        f" {mode.upper()} ",
        style="bold black on #fbbf24" if mode == "active" else f"bold black on {ACCENT}",
    )
    return Group(Text(""), title, Text(""), line, Text(""))


def render_report(
    graph: AttackSurfaceGraph,
    console: Console | None = None,
    *,
    max_tree_nodes: int = 40,
    show_findings: int = 12,
) -> None:
    console = console or Console()

    console.print(_summary_line(graph))
    console.print()
    console.print(Columns([_exposure_panel(graph), _posture_panel(graph)], expand=True))

    # The two panels that answer questions an inventory cannot: how they get in,
    # and which single fix actually slows them down.
    campaigns = _campaigns_panel(graph)
    if campaigns:
        console.print()
        console.print(campaigns)

    counterfactuals = _counterfactual_panel(graph)
    if counterfactuals:
        console.print()
        console.print(counterfactuals)

    console.print()
    console.print(_surface_tree(graph, max_tree_nodes))

    if not graph.adversary.get("campaigns"):
        paths = attack_paths(graph, limit=5)
        if paths:
            console.print()
            console.print(_attack_paths_panel(graph, paths))

    if graph.findings:
        console.print()
        console.print(_findings_table(graph, show_findings))

    patterns = _patterns_panel(graph)
    if patterns:
        console.print()
        console.print(patterns)

    coverage = _coverage_panel(graph)
    if coverage:
        console.print()
        console.print(coverage)

    analysis = graph.analysis or {}
    if analysis.get("available"):
        console.print()
        console.print(_analyst_panel(analysis))
    elif analysis.get("reason"):
        console.print()
        console.print(
            Text(f"  {GLYPHS.skip} AI analyst: {analysis['reason']}", style=FAINT)
        )

    footer = _footer(graph)
    if footer:
        console.print()
        console.print(footer)


# --------------------------------------------------------------------- sections


def _summary_line(graph: AttackSurfaceGraph) -> RenderableType:
    meta = graph.meta
    line = Text()
    line.append(f"  {meta.mode} scan", style=MUTED)
    for label, value in (
        (plural(len(meta.collectors_run), "collector"), None),
        (humanize_duration(meta.duration_seconds), None),
        (f"{len(graph.nodes)} assets", "bold"),
        (f"{len(graph.edges)} relations", None),
    ):
        line.append(f"  {GLYPHS.bullet}  ", style=FAINT)
        line.append(label, style=value or MUTED)
    return Group(Rule(style=FAINT), line)


def _exposure_panel(graph: AttackSurfaceGraph) -> Panel:
    exposure = graph.exposure()
    rows = exposure.rows()
    peak = max((v for _k, v in rows), default=0)

    table = Table.grid(padding=(0, 1))
    table.add_column(ratio=1)
    table.add_column(width=12, justify="right")
    table.add_column(width=5, justify="right")

    for label, value in rows:
        color = LOUD_ROWS.get(label) if value else None
        table.add_row(
            Text(label, style=MUTED if not color else "white"),
            meter(value, peak, width=12, color=color or ACCENT) if value else Text(""),
            Text(str(value), style=f"bold {color}" if color else ("bold" if value else FAINT)),
        )
    return Panel(
        table,
        title=Text("DIGITAL EXPOSURE", style="bold"),
        title_align="left",
        border_style=FAINT,
        box=PANEL,
        padding=(1, 2),
    )


def _posture_panel(graph: AttackSurfaceGraph) -> Panel:
    risk: dict[str, Any] = graph.risk or {}
    grade = str(risk.get("grade", "?"))
    counts = risk.get("finding_counts", {})
    score = risk.get("posture_score", 0)

    adversary = graph.adversary or {}
    coverage = graph.coverage or {}

    head = Table.grid(padding=(0, 2))
    head.add_column(width=3)
    head.add_column(ratio=1)

    confidence = coverage.get("confidence")
    display = str(risk.get("grade_display", grade))
    label = str(risk.get("grade_label", "unscored"))
    if risk.get("grade_provisional"):
        label += " (provisional)"
    head.add_row(
        grade_badge(grade),
        Group(
            Text(label, style="bold white"),
            Text(
                f"{display}  ·  {score}/100 posture"
                + (
                    f"  ·  {confidence:.0%} of the surface observed"
                    if confidence is not None
                    else ""
                ),
                style=FAINT,
            ),
        ),
    )
    for reason in risk.get("grade_reasons", [])[:2]:
        head.add_row("", Text(reason, style="yellow"))

    # The headline number: severity says how bad it is, this says how long it takes.
    ttc = adversary.get("time_to_compromise_hours")
    ttc_block: list[RenderableType] = []
    if adversary:
        ttc_block.append(Text(""))
        if ttc is None:
            ttc_block.append(Text("no route modelled from what was observed", style=FAINT))
        else:
            ttc_block.append(Text("time to compromise", style=FAINT))
            ttc_block.append(
                Text.assemble(
                    (_hours(ttc), f"bold {_ttc_style(ttc)}"),
                    ("   ", ""),
                    (f"{adversary.get('easiest_capability', '')} tier", MUTED),
                )
            )

    counts_table = Table.grid(padding=(0, 1))
    counts_table.add_column(width=10)
    counts_table.add_column(ratio=1, justify="right")
    for severity in SEVERITY_ORDER:
        n = counts.get(severity.value, 0)
        counts_table.add_row(
            Text(severity.value, style=SEVERITY_COLOR[severity.value] if n else FAINT),
            Text(str(n), style="bold" if n else FAINT),
        )

    extras = Table.grid(padding=(0, 1))
    extras.add_column(ratio=1)
    extras.add_column(justify="right")
    kev = risk.get("kev_findings", 0)
    extras.add_row(
        Text("in CISA KEV", style=MUTED),
        Text(str(kev), style="bold red" if kev else FAINT),
    )
    max_epss = risk.get("max_epss", 0.0) or 0.0
    extras.add_row(
        Text("peak EPSS", style=MUTED),
        Text(f"{max_epss:.1%}", style="bold yellow" if max_epss > 0.1 else FAINT),
    )

    body = Group(
        head,
        *ttc_block,
        Text(""),
        severity_distribution(counts, width=34),
        Text(""),
        counts_table,
        Text(""),
        extras,
    )
    return Panel(
        body,
        title=Text("RISK POSTURE", style="bold"),
        title_align="left",
        border_style=GRADE_COLOR.get(grade, FAINT),
        box=PANEL,
        padding=(1, 2),
    )


def _surface_tree(graph: AttackSurfaceGraph, limit: int) -> Panel:
    apex = graph.meta.target
    root_id = f"{NodeType.DOMAIN.value}:{apex}"
    tree = Tree(Text(apex, style=f"bold {ACCENT}"), guide_style=FAINT)

    if root_id not in graph.nodes:
        tree.add(Text("nothing discovered", style=FAINT))
        return _wrap_tree(tree)

    infra = graph.neighbors(root_id, edge_types=[EdgeType.DELEGATES_TO, EdgeType.MAIL_VIA])
    if infra:
        branch = tree.add(Text(f"infrastructure ({len(infra)})", style=MUTED))
        for node in infra[:6]:
            mark = NODE_MARK.get(node.type.value, "")
            branch.add(Text(f"{mark} {node.label}".strip(), style=FAINT))

    children = sorted(
        graph.neighbors(root_id, edge_types=[EdgeType.HAS_SUBDOMAIN]),
        key=lambda n: (-n.risk_score, n.label),
    )
    shown = children[:limit]

    if not children:
        tree.add(Text("no subdomains discovered", style=FAINT))

    for node in shown:
        label = Text()
        label.append(node.label, style=risk_style(node.risk_score))
        if node.risk_score:
            label.append(f"  {node.risk_score:.0f}", style=risk_style(node.risk_score))
        for tag in sorted(
            node.tags & {"non-production", "sensitive-service", "takeover", "malicious"}
        ):
            label.append(f"  {tag}", style="yellow")
        _attach_descendants(graph, node.id, tree.add(label), depth=0)

    if len(children) > len(shown):
        tree.add(Text(f"{GLYPHS.pending} {len(children) - len(shown)} more subdomains", style=FAINT))
    return _wrap_tree(tree)


def _wrap_tree(tree: Tree) -> Panel:
    return Panel(
        tree,
        title=Text("ATTACK SURFACE", style="bold"),
        title_align="left",
        border_style=FAINT,
        box=PANEL,
        padding=(1, 2),
    )


def _attach_descendants(
    graph: AttackSurfaceGraph, node_id: str, branch: Tree, depth: int
) -> None:
    """Expand what matters under a host, and summarize what does not.

    A host with eight A records adds eight lines of noise and no insight, so
    addresses collapse to one line naming the networks they sit in. Services,
    software, vulnerabilities and secrets always expand - that is the chain the
    reader is here to follow.
    """
    if depth >= 3:
        return

    for child in graph.neighbors(node_id, edge_types=[EdgeType.CNAME_TO])[:2]:
        branch.add(Text(f"{GLYPHS.arrow} {child.label}", style=FAINT))

    addresses = graph.neighbors(node_id, edge_types=[EdgeType.RESOLVES_TO])
    if addresses:
        asns = sorted({str(a.attrs.get("asn")) for a in addresses if a.attrs.get("asn")})
        summary = Text(f"# {plural(len(addresses), 'address', 'addresses')}", style=MUTED)
        if asns:
            names = []
            for asn in asns[:2]:
                node = graph.nodes.get(f"{NodeType.ASN.value}:{asn}")
                names.append(node.label if node else f"AS{asn}")
            summary.append(f"  {', '.join(names)}", style=FAINT)
        addr_branch = branch.add(summary)
        for address in addresses:
            _attach_descendants(graph, address.id, addr_branch, depth + 1)

    expand = [
        EdgeType.EXPOSES,
        EdgeType.RUNS,
        EdgeType.VULNERABLE_TO,
        EdgeType.LEAKS,
        EdgeType.FLAGGED_AS,
    ]
    for child in graph.neighbors(node_id, edge_types=expand)[:8]:
        mark = NODE_MARK.get(child.type.value, GLYPHS.bullet)
        text = Text(f"{mark} {child.label}".strip(), style=risk_style(child.risk_score))
        if child.type is NodeType.VULNERABILITY:
            if child.attrs.get("kev"):
                text.append("  KEV ", style="bold white on #b91c1c")
            if child.attrs.get("epss"):
                text.append(f"  epss {child.attrs['epss']:.0%}", style="yellow")
        _attach_descendants(graph, child.id, branch.add(text), depth + 1)


def _hours(hours: float) -> str:
    if hours < 1:
        return f"{hours * 60:.0f} min"
    if hours < 24:
        return f"{hours:.1f} h"
    days = hours / 24
    if days < 14:
        return f"{days:.1f} days"
    return f"{days / 7:.0f} weeks"


def _ttc_style(hours: float) -> str:
    if hours < 1:
        return SEVERITY_COLOR["critical"]
    if hours < 8:
        return SEVERITY_COLOR["high"]
    if hours < 80:
        return SEVERITY_COLOR["medium"]
    return "green"


def _campaigns_panel(graph: AttackSurfaceGraph) -> Panel | None:
    """How an attacker actually gets in, priced in their hours."""
    campaigns = (graph.adversary or {}).get("campaigns") or []
    if not campaigns:
        return None

    blocks: list[RenderableType] = []
    for i, campaign in enumerate(campaigns[:4], 1):
        header = Text(f"{i}  ", style=FAINT)
        header.append(campaign["objective"], style="bold white")
        header.append(f"   {_hours(campaign['hours'])}", style=_ttc_style(campaign["hours"]))
        header.append(f"  ·  {campaign['capability']}", style=FAINT)
        header.append(f"  ·  {campaign['detection_probability']:.0%} chance you notice", style=FAINT)
        blocks.append(header)
        for step in campaign["steps"]:
            line = Text("     ", style=FAINT)
            line.append(f"{step['from_asset']} {GLYPHS.arrow} {step['to_asset']}", style=MUTED)
            blocks.append(line)
            detail = Text("       ", style=FAINT)
            detail.append(step["technique"], style="white")
            detail.append(f"  {_hours(step['hours'])}", style=FAINT)
            if step["mitre"]:
                detail.append(f"  {step['mitre']}", style=FAINT)
            blocks.append(detail)
        blocks.append(Text(""))

    if blocks and not blocks[-1].plain:
        blocks.pop()
    return Panel(
        Group(*blocks),
        title=Text("CHEAPEST WAY IN", style="bold"),
        title_align="left",
        subtitle=Text("modelled attacker-hours, not measurements", style=FAINT),
        subtitle_align="right",
        border_style=SEVERITY_COLOR["high"],
        box=PANEL,
        padding=(1, 2),
    )


def _counterfactual_panel(graph: AttackSurfaceGraph) -> Panel | None:
    """Fixes ranked by what they cost the attacker - not by severity."""
    adversary = graph.adversary or {}
    counterfactuals = adversary.get("counterfactuals") or []
    if not adversary.get("campaigns"):
        return None

    table = Table(box=None, expand=True, pad_edge=False, show_header=True, header_style=FAINT)
    table.add_column("effect", width=16)
    table.add_column("fix", ratio=1, overflow="fold")
    table.add_column("severity", width=9)

    for entry in counterfactuals[:6]:
        if entry["closes_the_path"]:
            effect = Text("closes the path", style="bold green")
        else:
            effect = Text(
                f"+{_hours(entry['delta_hours'])}  {entry['multiplier']:.0f}x", style="green"
            )
        table.add_row(effect, Text(entry["title"]), severity_badge(entry["severity"]))

    total = len(graph.findings)
    no_effect = total - len(counterfactuals)
    footer = Text()
    if no_effect > 0 and counterfactuals:
        footer.append(
            f"  {no_effect} other finding(s) do not change the attacker's cheapest route. "
            "They still matter for defence in depth - they are just not the bottleneck.",
            style=FAINT,
        )
    elif not counterfactuals:
        footer.append(
            "  No single fix changes the cheapest route - the attacker has several equally "
            "cheap options, so these must be closed together.",
            style="yellow",
        )

    return Panel(
        Group(table, Text(""), footer) if footer.plain else table,
        title=Text("FIX THIS FIRST", style="bold"),
        title_align="left",
        subtitle=Text("ranked by how much each fix costs the attacker", style=FAINT),
        subtitle_align="right",
        border_style="green",
        box=PANEL,
        padding=(1, 2),
    )


def _patterns_panel(graph: AttackSurfaceGraph) -> Panel | None:
    """Findings that belong to a process, not to a host."""
    patterns = graph.patterns or []
    if not patterns:
        return None

    blocks: list[RenderableType] = []
    for pattern in patterns[:5]:
        header = Text()
        header.append_text(severity_badge(pattern["severity"]))
        header.append("  ")
        header.append(pattern["title"], style="bold white")
        if pattern["duplicates_saved"]:
            header.append(
                f"   {pattern['duplicates_saved']} fewer tickets", style="green"
            )
        blocks.append(header)
        blocks.append(Text(f"  {pattern['inference']}", style=FAINT))
        blocks.append(Text(f"  {GLYPHS.arrow} {pattern['remediation']}", style=MUTED))
        blocks.append(Text(""))
    if blocks and not blocks[-1].plain:
        blocks.pop()

    return Panel(
        Group(*blocks),
        title=Text("SYSTEMIC PATTERNS", style="bold"),
        title_align="left",
        subtitle=Text("one cause, many symptoms", style=FAINT),
        subtitle_align="right",
        border_style=ACCENT,
        box=PANEL,
        padding=(1, 2),
    )


def _coverage_panel(graph: AttackSurfaceGraph) -> Panel | None:
    """What the scan could not see. Silence is not an all-clear."""
    coverage = graph.coverage or {}
    classes = coverage.get("classes") or []
    if not classes:
        return None

    table = Table(box=None, expand=True, pad_edge=False, show_header=True, header_style=FAINT)
    table.add_column("class", width=16)
    table.add_column("seen", width=14)
    table.add_column("", width=6, justify="right")
    table.add_column("basis", ratio=1, overflow="ellipsis", no_wrap=True, style=FAINT)

    for entry in classes:
        value = entry.get("coverage")
        if value is None:
            bar, pct = Text("not estimated", style=FAINT), Text("-", style=FAINT)
        else:
            colour = (
                "green" if value >= 0.8 else "yellow" if value >= 0.4 else SEVERITY_COLOR["high"]
            )
            bar = meter(value, 1.0, width=12, color=colour)
            pct = Text(f"{value:.0%}", style=colour)
        table.add_row(Text(entry["name"], style=MUTED), bar, pct, entry.get("note", ""))

    label = coverage.get("confidence_label", "unknown")
    confidence = coverage.get("confidence", 0.0)
    summary = Text()
    summary.append("  overall confidence  ", style=FAINT)
    summary.append(
        f"{confidence:.0%} ({label})",
        style="green" if confidence >= 0.8 else "yellow" if confidence >= 0.55 else "bold yellow",
    )
    if confidence < 0.8:
        summary.append(
            "  - treat the grade above as provisional", style=FAINT
        )

    return Panel(
        Group(table, Text(""), summary),
        title=Text("SCAN COVERAGE", style="bold"),
        title_align="left",
        subtitle=Text("what this scan could not see", style=FAINT),
        subtitle_align="right",
        border_style="yellow" if confidence < 0.55 else FAINT,
        box=PANEL,
        padding=(1, 2),
    )


def _attack_paths_panel(graph: AttackSurfaceGraph, paths: list[dict[str, Any]]) -> Panel:
    lines = []
    for i, path in enumerate(paths, 1):
        text = Text(f"{i}  ", style=FAINT)
        for j, node in enumerate(path["nodes"]):
            if j:
                text.append(f" {GLYPHS.arrow} ", style=FAINT)
            text.append(node["label"], style=risk_style(node["score"]))
        text.append(f"   {path['score']:.0f}", style=FAINT)
        lines.append(text)
    return Panel(
        Group(*lines),
        title=Text("ATTACK PATHS", style="bold"),
        subtitle=Text("internet to impact, ranked by risk", style=FAINT),
        subtitle_align="right",
        title_align="left",
        border_style=SEVERITY_COLOR["high"],
        box=PANEL,
        padding=(1, 2),
    )


def _findings_table(graph: AttackSurfaceGraph, limit: int) -> Panel:
    findings = sorted(graph.findings.values(), key=lambda f: -f.risk_score)[:limit]
    table = Table(box=None, expand=True, pad_edge=False, show_header=True, header_style=FAINT)
    table.add_column("#", width=3, justify="right", style=FAINT)
    table.add_column("severity", width=10)
    table.add_column("score", width=5, justify="right")
    table.add_column("finding", ratio=1, overflow="fold")
    table.add_column("asset", width=26, overflow="ellipsis", style=FAINT)

    for i, f in enumerate(findings, 1):
        assets = [graph.nodes[n].label for n in f.node_ids if n in graph.nodes]
        title = Text(f.title)
        if f.kev:
            title.append("  KEV ", style="bold white on #b91c1c")
        if f.epss:
            title.append(f"  epss {f.epss:.0%}", style="yellow")
        table.add_row(
            str(i),
            severity_badge(f.severity),
            Text(f"{f.risk_score:.0f}", style=risk_style(f.risk_score)),
            title,
            ", ".join(assets[:2]),
        )

    total = len(graph.findings)
    subtitle = f"showing {len(findings)} of {total}" if total > len(findings) else ""
    return Panel(
        table,
        title=Text("FINDINGS", style="bold"),
        title_align="left",
        subtitle=Text(subtitle, style=FAINT) if subtitle else None,
        subtitle_align="right",
        border_style=FAINT,
        box=PANEL,
        padding=(1, 2),
    )


def _analyst_panel(analysis: dict[str, Any]) -> Panel:
    report = analysis.get("report") or {}
    blocks: list[RenderableType] = []

    if analysis.get("warning"):
        blocks.append(
            Panel(
                Text(analysis["warning"], style="yellow"),
                border_style="yellow",
                box=PANEL,
                padding=(0, 1),
                title=Text("read with care", style="bold yellow"),
                title_align="left",
            )
        )
        blocks.append(Text(""))

    if report.get("posture_verdict"):
        blocks.append(Text(report["posture_verdict"], style="bold white"))
        blocks.append(Text(""))
    if report.get("executive_summary"):
        blocks.append(Text(report["executive_summary"], style=MUTED))
        blocks.append(Text(""))

    scenarios = report.get("attack_scenarios") or []
    if scenarios:
        blocks.append(Text("attack scenarios", style=f"bold {SEVERITY_COLOR['high']}"))
        for s in scenarios[:3]:
            line = Text(f"  {s.get('name', '')}", style="bold white")
            line.append(f"   {s.get('likelihood', '?')} likelihood", style=FAINT)
            blocks.append(line)
            blocks.append(Text(f"  entry: {s.get('entry_point', '?')}", style=FAINT))
            for step in (s.get("steps") or [])[:4]:
                blocks.append(Text(f"    {GLYPHS.arrow} {step}", style=MUTED))
            blocks.append(Text(""))

    actions = report.get("prioritized_actions") or []
    if actions:
        blocks.append(Text("do this first", style="bold green"))
        table = Table.grid(padding=(0, 2))
        table.add_column(width=2, justify="right", style="bold green")
        table.add_column(ratio=1)
        table.add_column(width=22, justify="right", style=FAINT)
        for a in sorted(actions, key=lambda x: x.get("priority", 99))[:6]:
            timing = ", ".join(x for x in (a.get("timeline"), a.get("effort")) if x)
            table.add_row(str(a.get("priority", "")), Text(a.get("action", "")), timing)
        blocks.append(table)
        blocks.append(Text(""))

    blind = report.get("blind_spots") or []
    if blind:
        blocks.append(Text("what this scan could not see", style="bold yellow"))
        for item in blind[:5]:
            blocks.append(Text(f"  {GLYPHS.pending} {item}", style=FAINT))

    usage = analysis.get("usage") or {}
    tokens = ""
    if usage.get("input_tokens") or usage.get("output_tokens"):
        tokens = f"  {usage.get('input_tokens') or '?'} in / {usage.get('output_tokens') or '?'} out"
    badge = " free" if analysis.get("free") else " paid"
    subtitle = f"{analysis.get('provider', '')}{badge}  {GLYPHS.bullet}  {analysis.get('model', '')}{tokens}"
    return Panel(
        Group(*blocks),
        title=Text("AI ANALYST", style="bold"),
        title_align="left",
        subtitle=Text(subtitle, style=FAINT),
        subtitle_align="right",
        border_style="green",
        box=PANEL,
        padding=(1, 2),
    )


def _footer(graph: AttackSurfaceGraph) -> RenderableType | None:
    meta = graph.meta
    lines: list[Text] = []
    if meta.collectors_skipped:
        by_reason: dict[str, list[str]] = {}
        for name, reason in sorted(meta.collectors_skipped.items()):
            key = (
                "needs --active"
                if "active mode" in reason
                else "needs an API key"
                if "API key" in reason
                else reason
            )
            by_reason.setdefault(key, []).append(name)
        for reason, names in by_reason.items():
            line = Text(f"  {GLYPHS.skip} ", style=FAINT)
            line.append(", ".join(names), style=MUTED)
            line.append(f"  {reason}", style=FAINT)
            lines.append(line)
    if meta.errors:
        lines.append(
            Text(
                f"  {GLYPHS.warn} {plural(len(meta.errors), 'collector warning')} "
                "- see the JSON output",
                style="yellow",
            )
        )
    return Group(*lines) if lines else None


def next_steps(
    graph: AttackSurfaceGraph,
    graph_path: str,
    html_path: str | None,
    pdf_path: str | None = None,
    schema_paths: list[str] | None = None,
) -> RenderableType:
    """Tell the reader what to run next. A CLI should never end at a dead end."""
    target = graph.meta.target
    table = Table.grid(padding=(0, 2))
    table.add_column(width=10, style=FAINT)
    table.add_column(ratio=1)

    table.add_row("graph", Text(graph_path, style=MUTED))
    if html_path:
        table.add_row("report", Text(html_path, style=MUTED))
    if pdf_path:
        table.add_row("pdf", Text(pdf_path, style=MUTED))
    for sp in schema_paths or []:
        table.add_row("sdl", Text(str(sp), style=MUTED))

    hints: list[tuple[str, str]] = []
    if graph.meta.mode != "active":
        hints.append(("deeper", f"openrecon scan {target} --active --i-own-this"))
    if not (graph.analysis or {}).get("available"):
        hints.append(("analyst", "openrecon ai"))
    hints.append(("re-render", f"openrecon report {graph_path} --html out/{target}.html"))

    rows = [table, Text("")]
    for label, command in hints:
        row = Table.grid(padding=(0, 2))
        row.add_column(width=10, style=FAINT)
        row.add_column(ratio=1)
        row.add_row(label, Text(command, style=ACCENT))
        rows.append(row)
    return Group(*rows)
