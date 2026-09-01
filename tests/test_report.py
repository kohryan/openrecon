from __future__ import annotations

import json
import re

from rich.console import Console

from openrecon.ai.analyst import AiAnalyst, build_digest
from openrecon.config import Config
from openrecon.report.console import render_report
from openrecon.report.html import build_payload, render_html
from openrecon.risk.engine import RiskEngine


def test_console_report_renders_the_exposure_panel(graph):
    RiskEngine().score(graph)
    console = Console(record=True, width=100, force_terminal=False)
    render_report(graph, console)
    out = console.export_text()
    assert "DIGITAL EXPOSURE" in out
    assert "ATTACK SURFACE" in out
    assert "RISK POSTURE" in out
    assert "dev.example.com" in out
    assert "CVE-2021-22205" in out


def test_html_report_is_self_contained(graph, tmp_path):
    RiskEngine().score(graph)
    path = render_html(graph, tmp_path / "r.html")
    html = path.read_text(encoding="utf-8")
    assert "<script" in html and "</html>" in html
    # No external requests: a strict-CSP or air-gapped viewer must still work.
    assert not re.search(r'(src|href)\s*=\s*["\']https?://', html)
    assert "dev.example.com" in html


def test_html_payload_is_json_serializable(graph):
    RiskEngine().score(graph)
    payload = build_payload(graph)
    json.dumps(payload, default=str)
    assert payload["meta"]["target"] == "example.com"
    assert len(payload["nodes"]) == len(graph.nodes)
    assert payload["findings"][0]["score"] >= payload["findings"][-1]["score"]


def test_html_escapes_hostile_content(graph, tmp_path):
    """Banners come from machines we do not control - they must not become markup."""
    from openrecon.core.models import Node, NodeType

    graph.add_node(
        Node.create(
            NodeType.SERVICE,
            "1.2.3.4:80",
            label="<img src=x onerror=alert(1)>",
            attrs={"banner": "</script><script>alert(2)</script>"},
        )
    )
    RiskEngine().score(graph)
    html = render_html(graph, tmp_path / "x.html").read_text(encoding="utf-8")
    # The payload is embedded in a JSON script block, so raw </script> must not survive.
    assert "</script><script>alert(2)</script>" not in html
    assert "alert(1)" in html  # present as data...
    assert "<img src=x onerror=alert(1)>" not in html.split('id="data"')[0]  # ...never as markup


def test_digest_is_bounded_and_grounded(graph):
    RiskEngine().score(graph)
    digest = build_digest(graph)
    assert digest["target"] == "example.com"
    assert digest["posture"]["grade"]
    assert len(digest["top_findings"]) <= 40
    assert digest["attack_paths"]
    serialized = json.dumps(digest, default=str)
    assert len(serialized) < 200_000, "digest must stay small enough to be cheap to send"


def test_ai_analyst_enabled_flag(monkeypatch):
    assert AiAnalyst(Config()).enabled
    assert not AiAnalyst(Config(ai_enabled=False)).enabled


def test_html_payload_groups_findings_by_category(graph):
    RiskEngine().score(graph)
    payload = build_payload(graph)
    groups = payload["findings_by_category"]
    # The grouped index covers exactly the same findings as the flat list.
    assert sum(g["count"] for g in groups) == len(payload["findings"])
    grouped_ids = [fid for g in groups for fid in g["finding_ids"]]
    assert sorted(grouped_ids) == sorted(f["id"] for f in payload["findings"])
    # Most dangerous type first, and each group carries a severity breakdown.
    assert groups[0]["max_severity"] == "critical"
    assert all(sum(g["severities"].values()) == g["count"] for g in groups)


def test_html_report_renders_finding_type_groups(graph, tmp_path):
    RiskEngine().score(graph)
    html = render_html(graph, tmp_path / "g.html").read_text(encoding="utf-8")
    # The grouped rendering and its category headers ship in the report.
    assert "renderFindings" in html
    assert "fgroup-h" in html
    assert '"category": "known-vulnerability"' in html or '"category":"known-vulnerability"' in html
