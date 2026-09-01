"""PDF report export.

Renders the same report the console and HTML surfaces draw, but into a portable
PDF via reportlab - no browser and no system graphics libraries required, so the
``[pdf]`` extra stays light. We reuse the graph's own data accessors (exposure
summary, risk posture, findings, the attack-surface tree, and the AI analyst
block) so the three formats never drift.
"""

from __future__ import annotations

from typing import Any

# reportlab is the optional ``[pdf]`` extra. Import it lazily so the whole CLI
# can start (and every other surface still works) when it is not installed - the
# module stays importable and only ``render_pdf`` raises if the extra is missing.
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable,
        ListFlowable,
        ListItem,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    # Severity palette, mirrored from theme.SEVERITY_COLOR for parity across formats.
    _SEV = {
        "critical": colors.HexColor("#ef4444"),
        "high": colors.HexColor("#f97316"),
        "medium": colors.HexColor("#eab308"),
        "low": colors.HexColor("#38bdf8"),
        "info": colors.HexColor("#94a3b8"),
    }
    _ACCENT = colors.HexColor("#22d3ee")
    _FAINT = colors.HexColor("#64748b")
    _WHITE = colors.HexColor("#e2e8f0")

    _HAS_REPORTLAB = True
except ModuleNotFoundError:  # pragma: no cover - exercised via the CLI fallback
    _HAS_REPORTLAB = False

from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import SEVERITY_ORDER, EdgeType, NodeType
from openrecon.report.theme import NODE_MARK


def render_pdf(graph: AttackSurfaceGraph, path: str) -> str:
    """Write a PDF report for ``graph`` to ``path``; return ``path``."""
    if not _HAS_REPORTLAB:
        raise ImportError(
            "PDF export needs the [pdf] extra: uv pip install '.[pdf]'"
        )
    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=1.4 * cm,
        bottomMargin=1.4 * cm,
        title=f"openrecon - {graph.meta.target}",
        author="openrecon",
    )
    story = _build_story(graph)
    doc.build(story)
    return path


# --------------------------------------------------------------------------- styles


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], textColor=_ACCENT, fontSize=18, spaceAfter=2),
        "sub": ParagraphStyle("sub", parent=base["Normal"], textColor=_FAINT, fontSize=9, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], textColor=_WHITE, fontSize=12, spaceBefore=12, spaceAfter=4),
        "body": ParagraphStyle("body", parent=base["Normal"], textColor=_WHITE, fontSize=9, leading=12),
        "muted": ParagraphStyle("muted", parent=base["Normal"], textColor=_FAINT, fontSize=8, leading=11),
        "cell": ParagraphStyle("cell", parent=base["Normal"], textColor=_WHITE, fontSize=8, leading=10),
        "cellm": ParagraphStyle("cellm", parent=base["Normal"], textColor=_FAINT, fontSize=8, leading=10),
    }


# --------------------------------------------------------------------------- build


def _build_story(graph: AttackSurfaceGraph) -> list[Any]:
    s = _styles()
    meta = graph.meta
    story: list[Any] = []

    story.append(Paragraph("openrecon", s["title"]))
    story.append(
        Paragraph(
            f"attack surface intelligence &nbsp;·&nbsp; <b>{meta.target}</b> &nbsp;·&nbsp; "
            f"{meta.mode.upper()} scan &nbsp;·&nbsp; v{meta.openrecon_version or '?'}",
            s["sub"],
        )
    )
    story.append(HRFlowable(width="100%", thickness=0.6, color=_FAINT, spaceAfter=8))

    story += _exposure_block(graph, s)
    story += _posture_block(graph, s)
    story += _surface_block(graph, s)
    story += _findings_block(graph, s)
    story += _analyst_block(graph, s)
    story += _footer_block(graph, s)
    return story


def _exposure_block(graph: AttackSurfaceGraph, s: dict[str, ParagraphStyle]) -> list[Any]:
    exposure = graph.exposure()
    rows = exposure.rows()
    peak = max((v for _k, v in rows), default=0) or 1
    data = [[Paragraph("DIGITAL EXPOSURE", s["h2"]), ""]]
    for label, value in rows:
        bar = _meter(value, peak)
        data.append(
            [
                Paragraph(label, s["cellm"]),
                Paragraph(f"{value}", s["cell"] if value else s["cellm"]),
                bar,
            ]
        )
    table = Table(data, colWidths=[6 * cm, 1.6 * cm, 9.5 * cm])
    table.setStyle(
        TableStyle(
            [
                ("SPAN", (0, 0), (1, 0)),
                ("LINEBELOW", (0, 0), (-1, 0), 0.4, _FAINT),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    return [table]


def _sev_hex(sev: str) -> str:
    return "#" + _SEV[sev].hexval()[2:]


def _meter(value: int, peak: int) -> Paragraph:
    if not value:
        return Paragraph("", _styles()["cellm"])
    filled = int(round(28 * value / peak))
    fill = "█" * filled
    return Paragraph(f'<font color="#22d3ee">{fill}</font>', _styles()["cellm"])


def _posture_block(graph: AttackSurfaceGraph, s: dict[str, ParagraphStyle]) -> list[Any]:
    risk = graph.risk or {}
    grade = str(risk.get("grade", "?"))
    display = str(risk.get("grade_display", grade))
    score = risk.get("posture_score", 0)
    label = str(risk.get("label", risk.get("grade_label", "unscored")))
    if risk.get("grade_provisional"):
        label += " (provisional)"

    head = (
        f'<b>{grade}</b> &nbsp; {label} &nbsp;·&nbsp; {display} &nbsp;·&nbsp; {score}/100 posture'
    )
    blocks = [Paragraph(head, s["body"])]
    for reason in risk.get("grade_reasons", [])[:2]:
        blocks.append(Paragraph(reason, s["muted"]))

    counts = risk.get("finding_counts", {})
    sev_cells = []
    for sev in SEVERITY_ORDER:
        n = counts.get(sev.value, 0)
        sev_cells.append(Paragraph(f'<font color="{_sev_hex(sev.value)}">{sev.value}: {n}</font>', s["cell"]))
    blocks.append(Spacer(1, 3))
    blocks.append(Table([sev_cells], colWidths=[3.4 * cm] * len(sev_cells)))

    kev = risk.get("kev_findings", 0)
    epss = risk.get("max_epss", 0.0) or 0.0
    extras = (
        f'in CISA KEV: <b>{kev}</b> &nbsp;·&nbsp; peak EPSS: '
        f'<b>{epss:.1%}</b>' if epss else f'in CISA KEV: <b>{kev}</b>'
    )
    blocks.append(Paragraph(extras, s["muted"]))
    return [Paragraph("RISK POSTURE", s["h2"])] + blocks


def _surface_block(graph: AttackSurfaceGraph, s: dict[str, ParagraphStyle]) -> list[Any]:
    apex = graph.meta.target
    root_id = f"{NodeType.DOMAIN.value}:{apex}"
    items: list[str] = []
    if root_id not in graph.nodes:
        items.append("nothing discovered")
    else:
        children = sorted(
            graph.neighbors(root_id, edge_types=[EdgeType.HAS_SUBDOMAIN]),
            key=lambda n: (-n.risk_score, n.label),
        )
        for node in children[:40]:
            mark = NODE_MARK.get(node.type.value, "")
            line = f"{mark} {node.label}".strip()
            if node.risk_score:
                line += f"  [{node.risk_score:.0f}]"
            if node.tags & {"non-production", "sensitive-service", "takeover", "malicious"}:
                line += "  *" + "/".join(sorted(node.tags & {"non-production", "sensitive-service", "takeover", "malicious"}))
            items.append(line)
        if len(children) > 40:
            items.append(f"... {len(children) - 40} more subdomains")
    flow = ListFlowable(
        [ListItem(Paragraph(it, s["cell"]), leftIndent=6) for it in items],
        bulletType="bullet",
        start="square",
        leftIndent=10,
    )
    return [Paragraph("ATTACK SURFACE", s["h2"]), flow]


def _findings_block(graph: AttackSurfaceGraph, s: dict[str, ParagraphStyle]) -> list[Any]:
    if not graph.findings:
        return []
    findings = sorted(graph.findings.values(), key=lambda f: -f.risk_score)[:25]
    data = [[Paragraph("#", s["cellm"]), Paragraph("sev", s["cellm"]), Paragraph("finding", s["cellm"]), Paragraph("asset", s["cellm"])]]
    for i, f in enumerate(findings, 1):
        assets = [graph.nodes[n].label for n in f.node_ids if n in graph.nodes]
        sev = f.severity.value
        title = f.title
        if getattr(f, "kev", False):
            title += "  [KEV]"
        if getattr(f, "epss", None):
            title += f"  epss {f.epss:.0%}"
        data.append(
            [
                Paragraph(str(i), s["cell"]),
                Paragraph(f'<font color="{_sev_hex(sev)}">{sev}</font>', s["cell"]),
                Paragraph(title, s["cell"]),
                Paragraph(", ".join(assets[:2]), s["cellm"]),
            ]
        )
    table = Table(data, colWidths=[0.8 * cm, 1.8 * cm, 9.6 * cm, 5 * cm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("LINEBELOW", (0, 0), (-1, 0), 0.4, _FAINT),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0f172a"), colors.HexColor("#111c33")]),
            ]
        )
    )
    total = len(graph.findings)
    sub = f"showing {len(findings)} of {total}" if total > len(findings) else ""
    return [Paragraph("FINDINGS", s["h2"]), table, Paragraph(sub, s["muted"])]


def _analyst_block(graph: AttackSurfaceGraph, s: dict[str, ParagraphStyle]) -> list[Any]:
    analysis = graph.analysis or {}
    if analysis.get("reason") and not analysis.get("available"):
        return [Paragraph("AI ANALYST", s["h2"]), Paragraph(f"skipped: {analysis['reason']}", s["muted"])]
    report = analysis.get("report") or {}
    if not report:
        return []
    blocks: list[Any] = [Paragraph("AI ANALYST", s["h2"])]
    if analysis.get("warning"):
        blocks.append(Paragraph(f"read with care: {analysis['warning']}", s["muted"]))
    if report.get("posture_verdict"):
        blocks.append(Paragraph(report["posture_verdict"], s["body"]))
    if report.get("executive_summary"):
        blocks.append(Paragraph(report["executive_summary"], s["muted"]))
    for sc in (report.get("attack_scenarios") or [])[:3]:
        blocks.append(Paragraph(f"scenario: {sc.get('name', '')} ({sc.get('likelihood', '?')})", s["cell"]))
        if sc.get("entry_point"):
            blocks.append(Paragraph(f"  entry: {sc['entry_point']}", s["muted"]))
    for a in sorted(report.get("prioritized_actions") or [], key=lambda x: x.get("priority", 99))[:6]:
        timing = ", ".join(x for x in (a.get("timeline"), a.get("effort")) if x)
        blocks.append(Paragraph(f"{a.get('priority', '')}. {a.get('action', '')}  ({timing})", s["cell"]))
    for item in (report.get("blind_spots") or [])[:5]:
        blocks.append(Paragraph(f"blind spot: {item}", s["muted"]))
    return blocks


def _footer_block(graph: AttackSurfaceGraph, s: dict[str, ParagraphStyle]) -> list[Any]:
    meta = graph.meta
    lines: list[str] = []
    if meta.collectors_skipped:
        for name, reason in sorted(meta.collectors_skipped.items()):
            short = (
                "needs --active"
                if "active mode" in reason
                else "needs an API key"
                if "API key" in reason
                else reason
            )
            lines.append(f"skipped {name}: {short}")
    if meta.errors:
        lines.append(f"{len(meta.errors)} collector warning(s) - see the JSON output")
    if not lines:
        return []
    return [Spacer(1, 6), HRFlowable(width="100%", thickness=0.4, color=_FAINT), Paragraph("<br/>".join(lines), s["muted"])]
