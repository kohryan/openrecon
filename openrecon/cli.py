"""openrecon command line."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import typer
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from openrecon import __version__
from openrecon.ai.analyst import AiAnalyst
from openrecon.collectors import STAGES
from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.pipeline import Pipeline
from openrecon.report.console import masthead, next_steps, render_report
from openrecon.report.html import render_html
from openrecon.report.live import make_monitor
from openrecon.report.pdf import render_pdf
from openrecon.report.theme import (
    ACCENT,
    FAINT,
    GLYPHS,
    MUTED,
    SEVERITY_COLOR,
)
from openrecon.scope import Scope
from openrecon.store import ScanHistory

HELP = """\
[bold cyan]openrecon[/bold cyan] - attack surface intelligence.

Give it a domain; it builds the security map: DNS, certificates, subdomains,
addresses, hosting, exposed services, known vulnerabilities, and threat intel -
scored, ranked, and explained.

[dim]Passive by default. Active checks require an authorization scope.[/dim]
"""

SCAN_EPILOG = """\
[bold]Examples[/bold]

  [cyan]openrecon scan example.com[/cyan]
      Passive scan. Never sends a packet to the target.

  [cyan]openrecon scan example.com --active --i-own-this[/cyan]
      Adds port scanning, TLS handshakes, and exposed-path checks.

  [cyan]openrecon scan example.com --active --scope scope.yaml[/cyan]
      Active scan bounded by a written authorization scope.

  [cyan]openrecon scan example.com --only ct,dns --no-ai[/cyan]
      Just the collectors you name, no AI analysis.

  [cyan]openrecon scan example.com --ai gemini --no-ai[/cyan]
      AI analyst runs on gemini (the default free backend) when GEMINI_API_KEY is set.
      Pass a provider after --ai (groq, openrouter, anthropic, ollama), or --no-ai to skip.

[bold]Exit codes[/bold]  [dim]0 clean  ·  1 high findings  ·  2 critical findings[/dim]
"""

app = typer.Typer(
    name="openrecon",
    help=HELP,
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
scope_app = typer.Typer(
    help="Manage authorization scope files for active scanning.", rich_markup_mode="rich"
)
app.add_typer(scope_app, name="scope")

console = Console()
err = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"openrecon {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    pass


# ------------------------------------------------------------------------ scan


@app.command(epilog=SCAN_EPILOG)
def scan(
    target: str = typer.Argument(..., help="Apex domain to map, e.g. example.com"),
    active: bool = typer.Option(
        False, "--active", help="Enable collectors that send traffic to the target."
    ),
    scope_file: Path | None = typer.Option(
        None, "--scope", help="Authorization scope file (YAML). Required for --active."
    ),
    i_own_this: bool = typer.Option(
        False,
        "--i-own-this",
        help="Assert ownership; uses an implicit scope of the apex and its subdomains.",
    ),
    only: str | None = typer.Option(None, "--only", help="Comma-separated collectors to run."),
    exclude: str | None = typer.Option(None, "--exclude", help="Comma-separated collectors to skip."),
    no_ai: bool = typer.Option(
        False, "--no-ai", help="Skip the AI analyst stage."
    ),
    ai_provider: str | None = typer.Option(
        None, "--ai", "--ai-provider",
        help="AI backend (default gemini): gemini | groq | openrouter | ollama | anthropic.",
    ),
    ai_base_url: str | None = typer.Option(
        None, "--ai-base-url", help="Custom OpenAI-compatible endpoint (vLLM, LM Studio, ...)."
    ),
    model: str | None = typer.Option(None, "--model", help="Model name for the AI analyst."),
    effort: str | None = typer.Option(
        None, "--effort", help="Analyst reasoning effort (Claude only): low..max."
    ),
    out: Path = typer.Option(Path("out"), "--out", "-o", help="Output directory."),
    html: bool = typer.Option(True, "--html/--no-html", help="Write the interactive graph report."),
    json_only: bool = typer.Option(False, "--json", help="Print the graph as JSON and nothing else."),
    pdf: Path | None = typer.Option(None, "--pdf", help="Also write a PDF report to this path."),
    concurrency: int = typer.Option(20, "--concurrency", "-c", help="Parallel requests."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the on-disk response cache."),
    config_file: Path | None = typer.Option(None, "--config", help="YAML config file."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Map the attack surface of a domain."""
    target = _normalize_target(target)

    config = Config.load(
        config_file,
        active=active,
        concurrency=concurrency,
        use_cache=not no_cache,
        output_dir=out,
        ai_enabled=not no_ai,
        ai_provider=ai_provider,
        ai_base_url=ai_base_url,
        ai_model=model,
        ai_effort=effort,
    )
    if only:
        config.enabled_collectors = {s.strip() for s in only.split(",") if s.strip()}
    if exclude:
        config.disabled_collectors = {s.strip() for s in exclude.split(",") if s.strip()}

    scope = _resolve_scope(target, active, scope_file, i_own_this)
    show_ui = not (quiet or json_only)

    if show_ui:
        console.print(masthead(target, config.mode_label, __version__))
        if scope:
            console.print(
                Text(f"  scope  {scope.summary()}", style=FAINT),
            )
            console.print(
                Text(
                    "  active mode sends traffic to the target - proceed only where authorized",
                    style="yellow",
                )
            )
            console.print()

    monitor = make_monitor(console, target, config.mode_label, list(STAGES), not show_ui)
    pipeline = Pipeline(config, scope=scope, progress=monitor)

    try:
        with monitor:
            graph = asyncio.run(pipeline.run(target))
            graph.analysis = _run_analyst(config, graph, monitor, json_only)
    except KeyboardInterrupt:
        err.print(f"\n[yellow]{GLYPHS.warn} interrupted[/yellow]")
        raise typer.Exit(130) from None

    history = ScanHistory(config.output_dir)
    saved = history.save(graph)

    if json_only:
        payload = graph.to_dict()
        # Surface findings grouped by type alongside the raw findings map, so a
        # consumer can pull out every bug of a class (sqli, ssrf, ...) directly.
        payload["findings_by_category"] = [
            {
                "category": category,
                "count": len(items),
                "max_severity": max(items, key=lambda f: f.severity.weight).severity.value,
                "finding_ids": [f.id for f in items],
            }
            for category, items in graph.findings_by_category().items()
        ]
        console.print_json(json.dumps(payload, default=str))
        raise typer.Exit(_exit_code(graph))

    render_report(graph, console)

    html_path = str(render_html(graph, config.output_dir / f"{target}.html")) if html else None
    schema_paths = graph.export_graphql_schemas(config.output_dir)
    pdf_path = None
    if pdf is not None:
        try:
            pdf_path = str(render_pdf(graph, str(pdf)))
        except ImportError:
            err.print(
                "[yellow]PDF export needs the [pdf] extra: uv pip install '.[pdf]'[/yellow]"
            )
    console.print()
    console.print(next_steps(graph, str(saved), html_path, pdf_path, [str(p) for p in schema_paths]))

    previous = history.previous(target, before=saved)
    if previous:
        _print_delta(graph.diff(previous))

    raise typer.Exit(_exit_code(graph))


# ------------------------------------------------------------------ collectors


@app.command()
def collectors(
    active: bool = typer.Option(False, "--active", help="Show what --active would enable."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Include full descriptions."),
    config_file: Path | None = typer.Option(None, "--config"),
) -> None:
    """List every collector, its stage, and whether it can run right now."""
    config = Config.load(config_file, active=active)
    plan = Pipeline(config).plan()

    table = Table(box=box.SIMPLE_HEAD, header_style=FAINT, pad_edge=False, expand=True)
    table.add_column("stage", width=15, style=MUTED)
    table.add_column("collector", width=15, style="bold")
    table.add_column("mode", width=8)
    table.add_column("status", width=22)
    # overflow only takes effect when wrapping is off, so one line per collector
    # unless --verbose is asked for.
    table.add_column(
        "what it finds",
        ratio=1,
        style=FAINT,
        no_wrap=not verbose,
        overflow="fold" if verbose else "ellipsis",
    )

    ready = blocked = 0
    for stage, entries in plan.items():
        for i, entry in enumerate(entries):
            if entry["enabled"]:
                status = Text(f"{GLYPHS.ok} ready", style="green")
                ready += 1
            elif entry["missing_keys"]:
                status = Text(f"{GLYPHS.skip} key: {','.join(entry['missing_keys'])}", style="yellow")
                blocked += 1
            elif entry["mode"] == "active":
                status = Text(f"{GLYPHS.skip} needs --active", style=MUTED)
                blocked += 1
            else:
                status = Text(f"{GLYPHS.skip} disabled", style=FAINT)
                blocked += 1
            table.add_row(
                stage if i == 0 else "",
                entry["name"],
                Text(entry["mode"], style="yellow" if entry["mode"] == "active" else "green"),
                status,
                entry["description"],
            )

    console.print()
    console.print(table)
    console.print(
        Text(f"  {ready} ready", style="green")
        + Text(f"  {GLYPHS.bullet}  {blocked} blocked", style=FAINT)
        + Text(f"  {GLYPHS.bullet}  {len(plan)} stages", style=FAINT)
    )
    console.print()
    console.print(_keys_line(config))
    console.print()


# ---------------------------------------------------------------------- ai


@app.command()
def ai(config_file: Path | None = typer.Option(None, "--config")) -> None:
    """Show which AI backends are usable, and which one would be picked."""
    from openrecon.ai.providers import (
        PREFERENCE,
        PROVIDERS,
        is_small_model,
        ollama_models,
        select_provider,
    )
    from openrecon.core.net import HttpClient

    config = Config.load(config_file)

    async def probe() -> tuple[list[str] | None, str | None, str]:
        async with HttpClient(config) as http:
            local = await ollama_models(http, config)
            provider, reason = await select_provider(http, config)
            return local, (provider.spec.name if provider else None), reason

    local, chosen, reason = asyncio.run(probe())

    table = Table(box=box.SIMPLE_HEAD, header_style=FAINT, pad_edge=False, expand=True)
    table.add_column("", width=2)
    table.add_column("backend", width=12, style="bold")
    table.add_column("cost", width=6)
    table.add_column("status", width=26)
    table.add_column("default model", width=24, style=FAINT)

    for name in PREFERENCE:
        spec = PROVIDERS[name]
        if name == "ollama":
            ok = bool(local)
            detail = (
                f"running, {len(local)} model(s)"
                if local
                else ("running, no models" if local is not None else "not running")
            )
        else:
            ok = bool(spec.key_provider and config.key(spec.key_provider))
            detail = "key set" if ok else "no key"
        selected = name == chosen
        table.add_row(
            Text(GLYPHS.arrow, style=ACCENT) if selected else "",
            Text(name, style=ACCENT if selected else "bold"),
            Text("free", style="green") if spec.free else Text("paid", style="yellow"),
            Text(detail, style="green" if ok else FAINT),
            spec.default_model,
        )

    console.print()
    console.print(table)

    if local:
        console.print(Text("  local models  ", style=FAINT) + Text(", ".join(local), style=MUTED))
    if local and all(is_small_model(m) for m in local):
        console.print(
            Text(
                f"  {GLYPHS.warn} these are small models - they satisfy the schema but invent "
                "findings.\n     ollama pull qwen2.5:7b, or set a free cloud key.",
                style="yellow",
            )
        )
    console.print()

    if chosen:
        console.print(
            Text("  selected  ", style=FAINT) + Text(chosen, style=f"bold {ACCENT}")
        )
    else:
        console.print(
            Panel(
                Group(
                    Text(reason, style="yellow"),
                    Text(""),
                    Text("Cheapest fix - a local model, no key, nothing leaves your machine:", style=MUTED),
                    Text("  ollama serve && ollama pull qwen2.5:7b", style=ACCENT),
                    Text(""),
                    Text("Or a free cloud tier:", style=MUTED),
                    Text("  export GEMINI_API_KEY=...   # or GROQ_API_KEY, OPENROUTER_API_KEY", style=ACCENT),
                ),
                title=Text("no AI backend available", style="bold yellow"),
                title_align="left",
                border_style="yellow",
                box=box.ROUNDED,
                padding=(1, 2),
            )
        )
    console.print()


# -------------------------------------------------------------- report / diff


@app.command()
def report(
    graph_file: Path = typer.Argument(..., help="A saved openrecon graph JSON file."),
    html: Path | None = typer.Option(None, "--html", help="Also write an HTML report here."),
    pdf: Path | None = typer.Option(None, "--pdf", help="Also write a PDF report here."),
) -> None:
    """Re-render a report from a saved graph without re-scanning."""
    try:
        graph = AttackSurfaceGraph.load(graph_file)
    except (OSError, ValueError) as exc:
        err.print(f"[red]could not read {graph_file}: {exc}[/red]")
        raise typer.Exit(2) from exc

    console.print(masthead(graph.meta.target, graph.meta.mode, __version__))
    render_report(graph, console)
    if html:
        console.print()
        console.print(Text(f"  report  {render_html(graph, html)}", style=FAINT))
    if pdf:
        try:
            written = render_pdf(graph, str(pdf))
        except ImportError as exc:  # reportlab not installed
            err.print(
                "[yellow]PDF export needs the [pdf] extra: uv pip install '.[pdf]'[/yellow]"
            )
            raise typer.Exit(1) from exc
        console.print(Text(f"  pdf     {written}", style=FAINT))
    console.print()


@app.command()
def diff(
    old: Path = typer.Argument(..., help="Earlier graph JSON."),
    new: Path = typer.Argument(..., help="Later graph JSON."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Show what changed between two scans of the same target."""
    before, after = AttackSurfaceGraph.load(old), AttackSurfaceGraph.load(new)
    delta: dict[str, Any] = after.diff(before)
    if as_json:
        console.print_json(json.dumps(delta))
        return

    console.print()
    console.print(
        Text("  ", style=FAINT)
        + Text(before.meta.started_at.strftime("%Y-%m-%d %H:%M"), style=FAINT)
        + Text(f"  {GLYPHS.arrow}  ", style=FAINT)
        + Text(after.meta.started_at.strftime("%Y-%m-%d %H:%M"), style=MUTED)
    )
    console.print()
    _print_delta(delta, limit=40, always=True)
    console.print()


# --------------------------------------------------------------------- scope


@scope_app.command("init")
def scope_init(
    target: str = typer.Argument(..., help="Domain the scope will authorize."),
    path: Path = typer.Option(Path("scope.yaml"), "--path", "-p"),
) -> None:
    """Write an authorization scope template for active scanning."""
    if path.exists():
        err.print(f"[yellow]{path} already exists - not overwriting.[/yellow]")
        raise typer.Exit(1)
    written = Scope.write_template(path, target)
    console.print()
    console.print(Text(f"  {GLYPHS.ok} wrote {written}", style="green"))
    console.print()
    console.print(Text("  Edit it, confirm you are authorized to test every listed", style=MUTED))
    console.print(Text("  asset, then run:", style=MUTED))
    console.print(
        Text(f"    openrecon scan {target} --active --scope {written}", style=ACCENT)
    )
    console.print()


@scope_app.command("check")
def scope_check(
    path: Path = typer.Argument(..., help="Scope file to validate."),
    asset: list[str] = typer.Argument(None, help="Assets to test against the scope."),
) -> None:
    """Validate a scope file and test whether specific assets fall inside it."""
    try:
        scope = Scope.load(path)
    except (FileNotFoundError, ValueError) as exc:
        err.print(f"[red]{GLYPHS.fail} {exc}[/red]")
        raise typer.Exit(1) from exc

    console.print()
    console.print(Text(f"  {GLYPHS.ok} valid", style="green") + Text(f"  {scope.summary()}", style=FAINT))
    if asset:
        console.print()
        for item in asset:
            allowed = scope.allows(item)
            console.print(
                Text(f"  {GLYPHS.ok if allowed else GLYPHS.fail} ", style="green" if allowed else "red")
                + Text(f"{'allow' if allowed else 'deny ':<6}", style="green" if allowed else "red")
                + Text(f"  {item}", style=MUTED)
            )
    console.print()


# --------------------------------------------------------------------- install


@app.command()
def install_tools(
    only: list[str] = typer.Option(None, "--only", help="Install just these tools."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Fetch the free open-source tools openrecon drives (katana, nuclei, ...).

    This shell-out installer handles one tool at a time. For a single one-shot
    setup that also installs the Python tool (sqlmap) and runs `go install`
    for every Go tool, prefer:

        make tools          # or: ./install-tools.sh

    API-key tools (securitytrails, hibp, ...) are never fetched - this command
    only prints how to enable them. Re-run `openrecon collectors` to see what is
    ready afterwards.
    """
    from openrecon.tooling import TOOL_REGISTRY, install_oss_tool, oss_tools

    wanted = only or oss_tools()
    go_tools = [t for t in wanted if TOOL_REGISTRY.get(t, {}).get("kind") == "go"]
    pip_tools = [t for t in wanted if TOOL_REGISTRY.get(t, {}).get("kind") == "pip"]
    key_tools = [t for t in wanted if TOOL_REGISTRY.get(t, {}).get("kind") == "key"]

    console.print()
    console.print(Text("  openrecon tool installer", style=f"bold {ACCENT}"))
    if go_tools:
        console.print(Text(f"  go tools : {', '.join(go_tools)}", style=MUTED))
    if pip_tools:
        console.print(Text(f"  pip tools: {', '.join(pip_tools)}", style=MUTED))
    if key_tools:
        console.print(Text(f"  api keys : {', '.join(key_tools)} (documented, not fetched)", style=FAINT))

    if not yes:
        console.print(Text("  install the free OSS tools above? [y/N] ", style=MUTED), end="")
        if input().strip().lower() not in ("y", "yes"):
            console.print(Text("  aborted.", style=FAINT))
            raise typer.Exit(0)

    console.print()
    for name in wanted:
        info = TOOL_REGISTRY.get(name, {})
        if info.get("kind") == "key":
            console.print(
                Text(f"  {GLYPHS.skip} {name}  ", style=FAINT)
                + Text(f"set {info['env']} -> {info['signup']}", style=ACCENT)
            )
            continue
        ok, msg = install_oss_tool(name)
        style = "green" if ok else "yellow"
        console.print(Text(f"  {GLYPHS.ok if ok else GLYPHS.warn} {name}  ", style=style) + Text(msg, style=MUTED))

    console.print()
    console.print(Text("  done. Verify with: ", style=MUTED) + Text("openrecon collectors", style=ACCENT))
    console.print()


# --------------------------------------------------------------------- helpers


def _normalize_target(target: str) -> str:
    cleaned = target.strip().lower().rstrip(".")
    for prefix in ("https://", "http://"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
    cleaned = cleaned.split("/")[0].split("@")[-1].lstrip("*.")
    if not cleaned or " " in cleaned or "." not in cleaned:
        err.print(f"[red]{GLYPHS.fail} {target!r} is not a domain. Try: openrecon scan example.com[/red]")
        raise typer.Exit(2)
    return cleaned


def _run_analyst(config: Config, graph, monitor, json_only: bool) -> dict[str, Any]:
    analyst = AiAnalyst(config)
    if not analyst.enabled:
        return {"available": False, "reason": "AI analyst disabled (--no-ai)"}
    monitor.set_note("ai analyst")
    result = asyncio.run(analyst.analyze(graph))
    monitor.set_note("")
    return result


def _exit_code(graph) -> int:
    counts = (graph.risk or {}).get("finding_counts", {})
    if counts.get("critical"):
        return 2
    if counts.get("high"):
        return 1
    return 0


def _print_delta(delta: dict[str, list[str]], limit: int = 8, always: bool = False) -> None:
    shapes = [
        ("new_findings", GLYPHS.warn, SEVERITY_COLOR["high"], "new findings"),
        ("new_assets", "+", "green", "new assets"),
        ("resolved_findings", GLYPHS.ok, "green", "resolved findings"),
        ("removed_assets", "-", FAINT, "removed assets"),
    ]
    if not always and not any(delta.get(k) for k, *_ in shapes):
        return

    console.print()
    console.print(Text("  since the previous scan", style="bold"))
    for key, marker, style, label in shapes:
        items = delta.get(key) or []
        if not items and not always:
            continue
        console.print(
            Text(f"  {len(items):>4} ", style="bold" if items else FAINT)
            + Text(label, style=MUTED if items else FAINT)
        )
        for item in items[:limit]:
            console.print(Text(f"       {marker} {item}", style=style))
        if len(items) > limit:
            console.print(Text(f"       {GLYPHS.pending} {len(items) - limit} more", style=FAINT))


def _keys_line(config: Config) -> Group:
    """Lead with what is configured; the unset list is a footnote, not the headline."""
    keys = config.describe_keys()
    have = sorted(n for n, present in keys.items() if present)
    missing = sorted(n for n, present in keys.items() if not present)

    line = Text("  api keys  ", style=FAINT)
    if have:
        line.append("  ".join(f"{GLYPHS.ok} {n}" for n in have), style="green")
    else:
        line.append("none set", style=FAINT)

    rest = Text("            ", style=FAINT)
    shown = ", ".join(missing[:6])
    rest.append(
        f"{len(missing)} unset" + (f"  ({shown}{', ...' if len(missing) > 6 else ''})" if missing else ""),
        style=FAINT,
    )
    return Group(line, rest) if missing else Group(line)


def _resolve_scope(
    target: str, active: bool, scope_file: Path | None, i_own_this: bool
) -> Scope | None:
    if not active:
        return None
    if scope_file:
        try:
            scope = Scope.load(scope_file)
        except (FileNotFoundError, ValueError) as exc:
            err.print(f"[red]{GLYPHS.fail} {exc}[/red]")
            raise typer.Exit(2) from exc
        if not scope.allows_host(target):
            err.print(
                f"[red]{GLYPHS.fail} {target} is not covered by {scope_file}. "
                "Add it to `include` before scanning.[/red]"
            )
            raise typer.Exit(2)
        return scope
    if i_own_this:
        return Scope.implicit(target)

    err.print(
        Panel(
            Group(
                Text("Active scanning sends traffic to the target, so openrecon needs", style=MUTED),
                Text("you to state that you are authorized to test it.", style=MUTED),
                Text(""),
                Text("  You own the domain:", style=FAINT),
                Text(f"    openrecon scan {target} --active --i-own-this", style=ACCENT),
                Text(""),
                Text("  You are testing on someone's behalf:", style=FAINT),
                Text(f"    openrecon scope init {target}", style=ACCENT),
                Text(f"    openrecon scan {target} --active --scope scope.yaml", style=ACCENT),
            ),
            title=Text("authorization required", style="bold red"),
            title_align="left",
            border_style="red",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )
    raise typer.Exit(2)


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
