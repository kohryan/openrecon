"""Self-contained HTML report: an interactive attack surface graph.

No CDN, no build step, no external requests - one file you can email, attach to
a ticket, or open on an air-gapped laptop.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import NodeType
from openrecon.report.theme import NODE_KIND_COLOR, NODE_KIND_GLYPH
from openrecon.risk.engine import attack_paths


def _escape_text(value: str) -> str:
    """Minimal HTML escaping for the handful of values interpolated as markup."""
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


NODE_COLORS: dict[str, str] = {
    "domain": "#22d3ee",
    "subdomain": "#60a5fa",
    "ip": "#a78bfa",
    "netblock": "#818cf8",
    "asn": "#f472b6",
    "certificate": "#34d399",
    "service": "#fbbf24",
    "technology": "#fb923c",
    "vulnerability": "#ef4444",
    "secret": "#e11d48",
    "credential_leak": "#be123c",
    "api": "#f59e0b",
    "organization": "#94a3b8",
    "nameserver": "#64748b",
    "mailserver": "#64748b",
    "cloud_resource": "#2dd4bf",
    "threat": "#dc2626",
}


def build_payload(graph: AttackSurfaceGraph) -> dict[str, Any]:
    exposure = graph.exposure()
    nodes = [
        {
            "id": n.id,
            "label": n.label,
            "type": n.type.value,
            "risk": n.risk_score,
            "severity": n.risk_severity.value,
            "tags": sorted(n.tags),
            "attrs": {k: v for k, v in n.attrs.items() if v not in (None, "", [], {})},
            "sources": n.sources,
            "findings": [f.id for f in graph.findings_for(n.id)],
        }
        for n in graph.nodes.values()
    ]
    edges = [
        {"source": e.source, "target": e.target, "type": e.type.value}
        for e in graph.edges.values()
    ]
    findings = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "score": f.risk_score,
            "category": f.category,
            "description": f.description,
            "remediation": f.remediation,
            "evidence": f.evidence,
            "references": f.references,
            "cve": f.cve,
            "cvss": f.cvss,
            "epss": f.epss,
            "kev": f.kev,
            "assets": [graph.nodes[n].label for n in f.node_ids if n in graph.nodes],
            "node_ids": f.node_ids,
        }
        for f in sorted(graph.findings.values(), key=lambda f: -f.risk_score)
    ]
    findings_by_category = [
        {
            "category": category,
            "count": len(items),
            "max_severity": max(items, key=lambda f: f.severity.weight).severity.value,
            "top_score": round(max(f.risk_score for f in items), 1),
            "severities": {
                sev: n
                for sev in ("critical", "high", "medium", "low", "info")
                if (n := sum(1 for f in items if f.severity.value == sev))
            },
            "finding_ids": [f.id for f in items],
        }
        for category, items in graph.findings_by_category().items()
    ]
    return {
        "meta": {
            "target": graph.meta.target,
            "mode": graph.meta.mode,
            "started_at": graph.meta.started_at.isoformat(),
            "duration": round(graph.meta.duration_seconds, 1),
            "collectors_run": sorted(set(graph.meta.collectors_run)),
            "collectors_skipped": graph.meta.collectors_skipped,
            "version": graph.meta.openrecon_version,
        },
        "exposure": exposure.model_dump(),
        "exposure_rows": exposure.rows(),
        "risk": graph.risk,
        "analysis": graph.analysis,
        "nodes": nodes,
        "edges": edges,
        "findings": findings,
        "findings_by_category": findings_by_category,
        "paths": attack_paths(graph, limit=12),
        "colors": NODE_COLORS,
        "kind_colors": NODE_KIND_COLOR,
        "kind_glyphs": NODE_KIND_GLYPH,
        "node_types": [t.value for t in NodeType],
        }


def _embed(payload: dict[str, Any]) -> str:
    """Serialize for embedding inside a <script> block.

    Scan data contains bytes from machines the target may not control - a banner
    or page title holding `</script>` would otherwise close the block early and
    execute as markup in whoever opens the report. Escaping the three characters
    that can start a tag keeps the payload valid JSON (JSON.parse decodes the
    escapes) while making breakout impossible.
    """
    text = json.dumps(payload, default=str)
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_html(graph: AttackSurfaceGraph, path: str | Path) -> Path:
    html = _TEMPLATE.replace("__PAYLOAD__", _embed(build_payload(graph))).replace(
        "__TARGET__", _escape_text(graph.meta.target)
    )
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>openrecon - __TARGET__</title>
<style>
:root{
  --bg:#0b1020; --panel:#111731; --panel2:#161d3b; --line:#243056;
  --text:#e6ecff; --dim:#8b97bf; --accent:#22d3ee;
  --crit:#ef4444; --high:#fb7185; --med:#fbbf24; --low:#38bdf8; --info:#64748b;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);
  font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
#app{display:grid;grid-template-columns:320px 1fr 380px;height:100vh;gap:1px;background:var(--line)}
aside,main{background:var(--bg);overflow:auto}
aside{padding:16px}
h1{font-size:15px;margin:0 0 2px;letter-spacing:.08em}
h2{font-size:11px;text-transform:uppercase;letter-spacing:.14em;color:var(--dim);
  margin:22px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.sub{color:var(--dim);font-size:12px;margin-bottom:4px}
.kv{display:flex;justify-content:space-between;padding:3px 0;font-size:13px}
.kv b{font-weight:600}
.grade{display:flex;align-items:center;gap:12px;background:var(--panel);
  border:1px solid var(--line);border-radius:8px;padding:12px;margin-top:10px}
.grade .g{font-size:38px;font-weight:700;line-height:1}
.bar{height:6px;background:var(--panel2);border-radius:3px;overflow:hidden;margin-top:6px}
.bar>i{display:block;height:100%}
.pill{display:inline-block;padding:1px 7px;border-radius:99px;font-size:10px;
  text-transform:uppercase;letter-spacing:.08em;font-weight:700}
.sev-critical{background:var(--crit);color:#fff}
.sev-high{background:var(--high);color:#2b0b12}
.sev-medium{background:var(--med);color:#3b2600}
.sev-low{background:var(--low);color:#062033}
.sev-info{background:var(--info);color:#fff}
canvas{display:block;width:100%;height:100%;cursor:grab}
canvas:active{cursor:grabbing}
main{position:relative}
#toolbar{position:absolute;top:12px;left:12px;right:12px;display:flex;gap:6px;
  flex-wrap:wrap;z-index:5;pointer-events:none}
#toolbar>*{pointer-events:auto}
button,select,input{background:var(--panel);color:var(--text);border:1px solid var(--line);
  border-radius:6px;padding:5px 10px;font:inherit;font-size:12px;cursor:pointer}
button:hover{border-color:var(--accent)}
button.on{border-color:var(--accent);color:var(--accent)}
#legend{position:absolute;bottom:12px;left:12px;background:rgba(17,23,49,.92);
  border:1px solid var(--line);border-radius:8px;padding:10px 12px;font-size:11px;
  display:grid;grid-template-columns:repeat(2,auto);gap:2px 14px;z-index:5}
#legend i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
#hint{position:absolute;bottom:12px;right:12px;color:var(--dim);font-size:11px;z-index:5}
.item{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:10px;margin-bottom:8px;cursor:pointer}
.item:hover{border-color:var(--accent)}
.item h3{margin:0 0 4px;font-size:13px;font-weight:600;line-height:1.35}
.item .meta{color:var(--dim);font-size:11px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.item .body{margin:8px 0 0;font-size:12px;color:var(--dim);display:none}
.item.open .body{display:block}
.item .body b{color:var(--text)}
.fgroup{margin-bottom:16px}
.fgroup-h{display:flex;justify-content:space-between;align-items:center;gap:8px;
  position:sticky;top:0;background:var(--bg);padding:6px 0 6px;margin-bottom:8px;
  border-bottom:1px solid var(--line);z-index:2}
.fgroup-name{font-size:11px;text-transform:uppercase;letter-spacing:.12em;
  color:var(--accent);font-weight:700}
.fgroup-meta{display:flex;gap:5px;align-items:center;flex-wrap:wrap}
.fgroup-meta .count{background:var(--panel2);border:1px solid var(--line);
  border-radius:99px;padding:0 8px;font-size:11px;color:var(--dim)}
.path{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:8px 10px;margin-bottom:6px;font-size:11px;word-break:break-all}
.path .arrow{color:var(--dim);margin:0 4px}
.empty{color:var(--dim);font-style:italic;font-size:12px}
pre{background:var(--panel2);border-radius:6px;padding:8px;overflow:auto;font-size:11px;
  margin:6px 0 0;max-height:220px;color:var(--dim)}
.tag{background:var(--panel2);border:1px solid var(--line);border-radius:4px;
  padding:0 5px;font-size:10px;color:var(--dim)}
#ai{background:linear-gradient(180deg,rgba(34,211,238,.07),transparent);
  border:1px solid var(--line);border-radius:8px;padding:12px;margin-top:10px}
#ai h3{margin:14px 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--accent)}
#ai h3:first-child{margin-top:0}
#ai ol,#ai ul{margin:0;padding-left:18px;font-size:12px;color:var(--dim)}
#ai li{margin-bottom:6px}
#ai li b{color:var(--text)}
.warn{background:rgba(251,191,36,.12);border:1px solid var(--med);border-radius:8px;
  padding:10px 12px;margin-bottom:12px;font-size:12px;color:var(--med)}
.warn b{color:var(--text)}
@media(max-width:1100px){
  #app{grid-template-columns:1fr;grid-template-rows:auto 65vh auto}
  /* One row that scrolls, so controls never eat the canvas. */
  #toolbar{flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none}
  #toolbar::-webkit-scrollbar{display:none}
  #toolbar>*{flex:0 0 auto}
  #search{min-width:120px}
  #legend,#hint{display:none}
}
/* Print-to-PDF: hide the live controls, expand the canvas to a static snapshot. */
@media print{
  @page{margin:12mm}
  html,body{height:auto;background:#fff;color:#111}
  #app{display:block;height:auto;background:#fff}
  aside,main{background:#fff;color:#111;overflow:visible}
  #toolbar,#legend,#hint{display:none!important}
  main{position:static;height:auto}
  canvas{height:70vh}
  *{box-shadow:none!important}
  .sev-critical{background:#ef4444;color:#fff}
  .sev-high{background:#fb7185;color:#2b0b12}
  .sev-medium{background:#fbbf24;color:#3b2600}
  .sev-low{background:#38bdf8;color:#062033}
  .sev-info{background:#64748b;color:#fff}
}
</style>
</head>
<body>
<div id="app">
  <aside id="left">
    <h1>openrecon</h1>
    <div class="sub" id="target"></div>
    <div class="sub" id="scanmeta"></div>
    <div class="grade" id="grade"></div>
    <h2>Digital exposure</h2>
    <div id="exposure"></div>
    <h2>Findings by severity</h2>
    <div id="sevcounts"></div>
    <h2>Attack paths</h2>
    <div id="paths"></div>
    <h2 id="ai-title" style="display:none">AI analyst</h2>
    <div id="ai"></div>
  </aside>

  <main>
    <div id="toolbar">
      <input id="search" placeholder="filter assets..." style="flex:1;min-width:160px">
      <button data-filter="all" class="on">all</button>
      <button data-filter="risk">at risk</button>
      <button data-filter="service">services</button>
      <button data-filter="vulnerability">vulns</button>
      <button data-filter="secret">secrets</button>
      <button id="pdf">save PDF</button>
      <button id="freeze">pause</button>
      <button id="reset">reset view</button>
    </div>
    <canvas id="c"></canvas>
    <div id="legend"></div>
    <div id="hint">drag to pan &middot; scroll to zoom &middot; click a node</div>
  </main>

  <aside id="right">
    <h2 id="rtitle">Findings</h2>
    <div id="detail"></div>
    <div id="list"></div>
  </aside>
</div>

<script id="data" type="application/json">__PAYLOAD__</script>
<script>
"use strict";
const D = JSON.parse(document.getElementById("data").textContent);
const COLORS = D.colors, SEV = ["critical","high","medium","low","info"];
const KINDCOLORS = D.kind_colors || {}, KINDGLYPHS = D.kind_glyphs || {};
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => (
  {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

/* ---------------------------------------------------------------- left rail */
$("#target").textContent = D.meta.target;
$("#scanmeta").textContent =
  `${D.meta.mode} scan · ${D.meta.duration}s · ${D.nodes.length} assets · ${D.edges.length} relations`;

const risk = D.risk || {};
const gradeColor = {A:"#34d399",B:"#a3e635",C:"#fbbf24",D:"#fb923c",F:"#ef4444"}[risk.grade] || "#64748b";
$("#grade").innerHTML =
  `<div class="g" style="color:${gradeColor}">${esc(risk.grade || "?")}</div>
   <div style="flex:1">
     <div class="kv"><span>${esc(risk.grade_label || "unscored")}</span>
       <b>${risk.posture_score ?? 0}/100</b></div>
     <div class="bar"><i style="width:${risk.posture_score ?? 0}%;background:${gradeColor}"></i></div>
   </div>`;

$("#exposure").innerHTML = (D.exposure_rows || [])
  .map(([k, v]) => `<div class="kv"><span style="color:var(--dim)">${esc(k)}</span><b>${v}</b></div>`)
  .join("");

const counts = risk.finding_counts || {};
$("#sevcounts").innerHTML = SEV.map(s =>
  `<div class="kv"><span class="pill sev-${s}">${s}</span><b>${counts[s] || 0}</b></div>`).join("");

$("#paths").innerHTML = (D.paths || []).length
  ? D.paths.slice(0, 6).map(p =>
      `<div class="path">` +
      p.nodes.map(n => `<span style="color:${COLORS[n.type] || "#fff"}">${esc(n.label)}</span>`)
        .join('<span class="arrow">&rarr;</span>') + `</div>`).join("")
  : '<div class="empty">no end-to-end paths reconstructed</div>';

const legendTypeEntries = Object.entries(COLORS)
  .filter(([t]) => D.nodes.some(n => n.type === t));
// General API-kind entries: any node that tagged itself with a `kind` in
// KINDCOLORS (graphql, openapi, grpc, ...) gets a separate legend chip. This is
// collector-agnostic - a future gRPC/Swagger collector reuses the same hook.
const usedKinds = new Set(D.nodes.map(n => (n.attrs && n.attrs.kind) || null).filter(Boolean));
const legendKindEntries = Object.entries(KINDCOLORS)
  .filter(([k]) => usedKinds.has(k));
$("#legend").innerHTML = legendTypeEntries
  .map(([t, c]) => `<div><i style="background:${c}"></i>${esc(t)}</div>`).join("")
  + legendKindEntries
  .map(([k, c]) => `<div><i style="background:${c}"></i>${esc(k)}</div>`).join("");

/* -------------------------------------------------------------- right rail */
function findingCard(f) {
  const ev = Object.keys(f.evidence || {}).length
    ? `<pre>${esc(JSON.stringify(f.evidence, null, 2))}</pre>` : "";
  return `<div class="item" data-nodes='${esc(JSON.stringify(f.node_ids))}'>
    <h3>${esc(f.title)}</h3>
    <div class="meta">
      <span class="pill sev-${f.severity}">${f.severity}</span>
      <span>score ${f.score}</span>
      ${f.kev ? '<span class="pill sev-critical">KEV</span>' : ""}
      ${f.epss ? `<span>epss ${(f.epss * 100).toFixed(1)}%</span>` : ""}
      <span class="tag">${esc(f.category)}</span>
    </div>
    <div class="body">${f.description ? esc(f.description) + "<br><br>" : ""}
       ${f.remediation ? "<b>Fix:</b> " + esc(f.remediation) : ""}
       ${f.assets && f.assets.length ? "<br><br><b>Assets:</b> " + esc(f.assets.join(", ")) : ""}
       ${ev}</div>
  </div>`;
}
/* Group the findings by type so every class of bug stays visible instead of
   sinking under a pile of higher-scored hardening notes. */
const findingById = new Map((D.findings || []).map(f => [f.id, f]));
function groupHeader(g) {
  const pills = SEV
    .filter(s => g.severities && g.severities[s])
    .map(s => `<span class="pill sev-${s}">${g.severities[s]}</span>`)
    .join("");
  return `<div class="fgroup-h">
      <span class="fgroup-name">${esc(g.category)}</span>
      <span class="fgroup-meta">${pills}<span class="count">${g.count}</span></span>
    </div>`;
}
function renderFindings() {
  if (!(D.findings || []).length) {
    $("#list").innerHTML = '<div class="empty">no findings recorded</div>';
    return;
  }
  const groups = D.findings_by_category && D.findings_by_category.length
    ? D.findings_by_category
    : [{ category: "findings", count: D.findings.length,
         finding_ids: D.findings.map(f => f.id), severities: {} }];
  $("#list").innerHTML = groups.map(g => {
    const cards = g.finding_ids
      .map(id => findingById.get(id)).filter(Boolean).map(findingCard).join("");
    return `<div class="fgroup">${groupHeader(g)}${cards}</div>`;
  }).join("");
}
renderFindings();

$("#list").addEventListener("click", (e) => {
  const card = e.target.closest(".item");
  if (!card) return;
  card.classList.toggle("open");
  try {
    const ids = JSON.parse(card.dataset.nodes || "[]");
    if (ids.length) focusNode(ids[0]);
  } catch (_) {}
});

/* AI analyst block - lives in the left overview rail so it survives node
   clicks and the reset-view button (which is now scoped to the graph canvas). */
const a = D.analysis || {};
if (a.available && a.report) {
  const r = a.report;
  const sec = [];
  if (r.posture_verdict) sec.push(`<h3>Verdict</h3><p style="margin:0;font-size:12px">${esc(r.posture_verdict)}</p>`);
  if (r.executive_summary) sec.push(`<h3>Summary</h3><p style="margin:0;font-size:12px;color:var(--dim)">${esc(r.executive_summary)}</p>`);
  if ((r.attack_scenarios || []).length) sec.push(`<h3>Attack scenarios</h3><ul>` +
    r.attack_scenarios.map(s => `<li><b>${esc(s.name)}</b> — entry: ${esc(s.entry_point)} (${esc(s.likelihood)})<br>` +
      (s.steps || []).map(x => esc(x)).join(" &rarr; ") + `</li>`).join("") + `</ul>`);
  if ((r.prioritized_actions || []).length) sec.push(`<h3>Do this first</h3><ol>` +
    r.prioritized_actions.sort((x, y) => x.priority - y.priority)
      .map(x => `<li><b>${esc(x.action)}</b><br>${esc(x.rationale)} <i>(${esc(x.timeline)})</i></li>`).join("") + `</ol>`);
  if ((r.blind_spots || []).length) sec.push(`<h3>Blind spots</h3><ul>` +
    r.blind_spots.map(x => `<li>${esc(x)}</li>`).join("") + `</ul>`);
  const badge = `<div class="meta" style="margin-top:12px">` +
    `<span class="tag">${esc(a.provider || "")}${a.free ? " · free" : ""}</span>` +
    `<span class="tag">${esc(a.model || "")}</span></div>`;
  // A model that invents findings is worse than no analysis - lead with that.
  const warn = a.warning
    ? `<div class="warn"><b>Read with care.</b> ${esc(a.warning)}</div>` : "";
  document.getElementById("ai-title").style.display = "";
  $("#ai").innerHTML = warn + sec.join("") + badge;
} else if (a.reason) {
  document.getElementById("ai-title").style.display = "";
  $("#ai").innerHTML = `<div class="empty">${esc(a.reason)}</div>`;
}

/* ------------------------------------------------------------- force graph */
const canvas = $("#c"), ctx = canvas.getContext("2d");
const byId = new Map();
const nodes = D.nodes.map((n, i) => {
  const angle = (i / D.nodes.length) * Math.PI * 2;
  const o = {
    ...n, x: Math.cos(angle) * 260 + (i % 7) * 9, y: Math.sin(angle) * 260 + (i % 5) * 9,
    vx: 0, vy: 0, r: 4 + Math.min(n.risk, 100) / 12 + (n.type === "domain" ? 6 : 0),
    visible: true,
  };
  byId.set(n.id, o);
  return o;
});
const links = D.edges
  .map(e => ({ s: byId.get(e.source), t: byId.get(e.target), type: e.type }))
  .filter(l => l.s && l.t);

const degree = new Map();
links.forEach(l => {
  degree.set(l.s.id, (degree.get(l.s.id) || 0) + 1);
  degree.set(l.t.id, (degree.get(l.t.id) || 0) + 1);
});

let view = { x: 0, y: 0, k: 1 }, running = true, selected = null, hovered = null;
let filter = "all", query = "";

function resize() {
  const dpr = window.devicePixelRatio || 1;
  canvas.width = canvas.clientWidth * dpr;
  canvas.height = canvas.clientHeight * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
window.addEventListener("resize", resize);

function applyFilter() {
  nodes.forEach(n => {
    let ok = true;
    if (filter === "risk") ok = n.risk > 0;
    else if (filter !== "all") ok = n.type === filter;
    if (ok && query) ok = n.label.toLowerCase().includes(query);
    n.visible = ok;
  });
  // Keep a filtered node's neighbours visible so the graph still reads as a graph.
  if (filter !== "all" || query) {
    const keep = new Set(nodes.filter(n => n.visible).map(n => n.id));
    links.forEach(l => {
      if (keep.has(l.s.id)) l.t.visible = true;
      if (keep.has(l.t.id)) l.s.visible = true;
    });
  }
}

function step() {
  const REPULSE = 2400, SPRING = 0.012, CENTER = 0.0016, DAMP = 0.86;
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i];
    if (!a.visible) continue;
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j];
      if (!b.visible) continue;
      let dx = b.x - a.x, dy = b.y - a.y;
      let d2 = dx * dx + dy * dy;
      if (d2 < 1) { d2 = 1; dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); }
      if (d2 > 360000) continue;
      const f = REPULSE / d2, d = Math.sqrt(d2);
      const fx = (dx / d) * f, fy = (dy / d) * f;
      a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
    }
  }
  for (const l of links) {
    if (!l.s.visible || !l.t.visible) continue;
    const dx = l.t.x - l.s.x, dy = l.t.y - l.s.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 1;
    const rest = 70 + l.s.r + l.t.r;
    const f = (d - rest) * SPRING;
    const fx = (dx / d) * f, fy = (dy / d) * f;
    l.s.vx += fx; l.s.vy += fy; l.t.vx -= fx; l.t.vy -= fy;
  }
  for (const n of nodes) {
    if (!n.visible || n.pinned) { n.vx = n.vy = 0; continue; }
    n.vx -= n.x * CENTER; n.vy -= n.y * CENTER;
    n.vx *= DAMP; n.vy *= DAMP;
    n.x += Math.max(-14, Math.min(14, n.vx));
    n.y += Math.max(-14, Math.min(14, n.vy));
  }
}

function draw() {
  const w = canvas.clientWidth, h = canvas.clientHeight;
  ctx.clearRect(0, 0, w, h);
  ctx.save();
  ctx.translate(w / 2 + view.x, h / 2 + view.y);
  ctx.scale(view.k, view.k);

  ctx.lineWidth = 1;
  for (const l of links) {
    if (!l.s.visible || !l.t.visible) continue;
    const hot = selected && (l.s.id === selected.id || l.t.id === selected.id);
    ctx.strokeStyle = hot ? "rgba(34,211,238,.75)" : "rgba(80,100,160,.22)";
    ctx.beginPath();
    ctx.moveTo(l.s.x, l.s.y);
    ctx.lineTo(l.t.x, l.t.y);
    ctx.stroke();
  }

  for (const n of nodes) {
    if (!n.visible) continue;
    const nodeKind = (n.attrs && n.attrs.kind) || null;
    const color = (nodeKind && KINDCOLORS[nodeKind]) || COLORS[n.type] || "#94a3b8";
    if (n.risk >= 45) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r + 7, 0, Math.PI * 2);
      ctx.fillStyle = n.risk >= 70 ? "rgba(239,68,68,.18)" : "rgba(251,191,36,.15)";
      ctx.fill();
    }
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    // API-kind glyph (graphql hexagon, openapi star, ...) drawn inside the node.
    if (nodeKind && KINDGLYPHS[nodeKind] && n.r > 6) {
      ctx.fillStyle = "rgba(8,12,28,.85)";
      ctx.font = `${Math.max(8, n.r)}px ui-monospace,monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(KINDGLYPHS[nodeKind], n.x, n.y + 0.5);
      ctx.textAlign = "start";
      ctx.textBaseline = "alphabetic";
    }
    if (selected && selected.id === n.id) {
      ctx.strokeStyle = "#fff"; ctx.lineWidth = 2; ctx.stroke(); ctx.lineWidth = 1;
    }
    const big = n.type === "domain" || n.r > 8 || (degree.get(n.id) || 0) > 3;
    if (view.k > 0.75 && (big || hovered === n || selected === n)) {
      ctx.fillStyle = "rgba(230,236,255,.85)";
      ctx.font = `${Math.max(9, 11 / view.k > 14 ? 14 : 11)}px ui-monospace,monospace`;
      ctx.fillText(n.label.length > 34 ? n.label.slice(0, 33) + "…" : n.label, n.x + n.r + 4, n.y + 3);
    }
  }
  ctx.restore();
}

function loop() {
  if (running) step();
  draw();
  requestAnimationFrame(loop);
}

/* ------------------------------------------------------------ interaction */
function toWorld(px, py) {
  const rect = canvas.getBoundingClientRect();
  return {
    x: (px - rect.left - canvas.clientWidth / 2 - view.x) / view.k,
    y: (py - rect.top - canvas.clientHeight / 2 - view.y) / view.k,
  };
}
function nodeAt(px, py) {
  const p = toWorld(px, py);
  let best = null, bestD = Infinity;
  for (const n of nodes) {
    if (!n.visible) continue;
    const d = (n.x - p.x) ** 2 + (n.y - p.y) ** 2;
    if (d < (n.r + 6) ** 2 && d < bestD) { best = n; bestD = d; }
  }
  return best;
}

let drag = null, panning = null;
canvas.addEventListener("mousedown", (e) => {
  const n = nodeAt(e.clientX, e.clientY);
  if (n) { drag = n; n.pinned = true; select(n); }
  else panning = { x: e.clientX - view.x, y: e.clientY - view.y };
});
canvas.addEventListener("mousemove", (e) => {
  if (drag) {
    const p = toWorld(e.clientX, e.clientY);
    drag.x = p.x; drag.y = p.y;
  } else if (panning) {
    view.x = e.clientX - panning.x; view.y = e.clientY - panning.y;
  } else {
    hovered = nodeAt(e.clientX, e.clientY);
    canvas.title = hovered ? `${hovered.label} (${hovered.type}) risk ${hovered.risk}` : "";
  }
});
window.addEventListener("mouseup", () => {
  if (drag) drag.pinned = false;
  drag = null; panning = null;
});
canvas.addEventListener("wheel", (e) => {
  e.preventDefault();
  view.k = Math.max(0.15, Math.min(5, view.k * (e.deltaY < 0 ? 1.12 : 0.89)));
}, { passive: false });

function select(n) {
  selected = n;
  const rows = Object.entries(n.attrs || {}).slice(0, 20)
    .map(([k, v]) => `<div class="kv"><span style="color:var(--dim)">${esc(k)}</span>
        <b style="max-width:60%;text-align:right;word-break:break-all">${esc(
          Array.isArray(v) ? v.slice(0, 6).join(", ") : typeof v === "object" ? JSON.stringify(v) : v)}</b></div>`)
    .join("");
  const fs = D.findings.filter(f => (n.findings || []).includes(f.id));
  $("#rtitle").textContent = n.label;
  $("#detail").innerHTML =
    `<div class="item open" style="cursor:default">
       <div class="meta">
         <span class="pill sev-${n.severity}">${esc(n.type)}</span>
         <span>risk ${n.risk}</span>
         ${(n.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join("")}
       </div>
       <div class="body">${rows || '<span class="empty">no attributes recorded</span>'}
          <br><span class="tag">sources: ${esc((n.sources || []).join(", "))}</span></div>
     </div>` +
    (fs.length ? `<h2>Findings on this asset</h2>` + fs.map(findingCard).join("") : "");
}

function focusNode(id) {
  const n = byId.get(id);
  if (!n) return;
  n.visible = true;
  select(n);
  view.k = 1.6;
  view.x = -n.x * view.k;
  view.y = -n.y * view.k;
}

document.querySelectorAll("[data-filter]").forEach(b => {
  b.addEventListener("click", () => {
    document.querySelectorAll("[data-filter]").forEach(x => x.classList.remove("on"));
    b.classList.add("on");
    filter = b.dataset.filter;
    applyFilter();
  });
});
$("#search").addEventListener("input", (e) => { query = e.target.value.toLowerCase().trim(); applyFilter(); });
$("#freeze").addEventListener("click", (e) => {
  running = !running;
  e.target.textContent = running ? "pause" : "resume";
  e.target.classList.toggle("on", !running);
});
$("#reset").addEventListener("click", () => {
  view = { x: 0, y: 0, k: 1 }; selected = null;
  $("#rtitle").textContent = "Findings"; $("#detail").innerHTML = "";
});
$("#pdf").addEventListener("click", () => {
  running = false;          // freeze the force graph so the snapshot is stable
  // Give one frame for the frozen layout to settle, then open the print dialog.
  requestAnimationFrame(() => requestAnimationFrame(() => window.print()));
});

resize();
applyFilter();
loop();
</script>
</body>
</html>
"""
