"""AI analyst: backend selection, response handling, and schema repair.

Nothing here reaches a real model. Ollama and the OpenAI-compatible providers are
exercised against a local aiohttp-free stub server; the Anthropic path is stubbed
at the SDK boundary.
"""

from __future__ import annotations

import json

import pytest

from openrecon.ai.analyst import AiAnalyst, AnalystReport, _validate, build_digest
from openrecon.ai.providers import (
    PROVIDERS,
    GeminiProvider,
    OpenAiCompatibleProvider,
    extract_json,
    select_provider,
)
from openrecon.config import Config
from openrecon.risk.engine import RiskEngine

GOOD_REPORT = {
    "executive_summary": "Two internet-facing criticals need attention today.",
    "posture_verdict": "Materially exposed.",
    "key_risks": [
        {
            "title": "Unauthenticated Elasticsearch",
            "severity": "critical",
            "affected_assets": ["93.184.216.34:9200"],
            "why_it_matters": "Full read of indexed data with no credentials.",
            "confidence": "high",
        }
    ],
    "attack_scenarios": [
        {
            "name": "Data exfiltration via exposed datastore",
            "entry_point": "93.184.216.34:9200",
            "steps": ["Query the open index", "Dump documents"],
            "impact": "Full disclosure of indexed records",
            "likelihood": "high",
            "prerequisites": [],
        }
    ],
    "prioritized_actions": [
        {
            "priority": 1,
            "action": "Firewall port 9200 to the VPC",
            "rationale": "Removes the highest-scoring finding outright.",
            "effort": "hours",
            "timeline": "within 24h",
        }
    ],
    "blind_spots": ["Passive scan cannot confirm authentication state."],
    "notable_observations": [],
}


# --------------------------------------------------------------- JSON recovery


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps(GOOD_REPORT),
        "```json\n" + json.dumps(GOOD_REPORT) + "\n```",
        "Here is the assessment:\n" + json.dumps(GOOD_REPORT) + "\nHope that helps!",
        "```\n" + json.dumps(GOOD_REPORT) + "\n```",
    ],
)
def test_extract_json_survives_how_small_models_actually_answer(raw):
    assert extract_json(raw) == GOOD_REPORT


def test_extract_json_handles_braces_inside_strings():
    payload = {"executive_summary": 'contains { and } and "quotes"'}
    assert extract_json("noise " + json.dumps(payload) + " trailing") == payload


@pytest.mark.parametrize("raw", ["", "no json here", "{unclosed: ", "[1, 2, 3]"])
def test_extract_json_returns_none_when_there_is_nothing_usable(raw):
    assert extract_json(raw) is None


# ------------------------------------------------------------- schema handling


def test_valid_output_passes_through_untouched():
    report, warning = _validate(GOOD_REPORT)
    assert warning == ""
    assert report["posture_verdict"] == "Materially exposed."


def test_partially_malformed_output_is_salvaged_not_discarded():
    """One unusable item must not cost the operator the whole assessment."""
    broken = json.loads(json.dumps(GOOD_REPORT))
    broken["key_risks"].append({"nope": True})                  # no title/severity
    broken["attack_scenarios"].append({"steps": ["orphan"]})     # no name/entry_point

    report, warning = _validate(broken)
    assert report["executive_summary"] == GOOD_REPORT["executive_summary"]
    assert len(report["key_risks"]) == 1, "the unusable risk is dropped"
    assert len(report["attack_scenarios"]) == 1
    assert len(report["prioritized_actions"]) == 1, "valid items survive"
    assert "2 item(s) were dropped" in warning


def test_report_schema_is_json_serializable():
    schema = AnalystReport.model_json_schema()
    json.dumps(schema)
    assert "properties" in schema
    assert set(schema["properties"]) >= {
        "executive_summary",
        "posture_verdict",
        "key_risks",
        "attack_scenarios",
        "prioritized_actions",
        "blind_spots",
    }


# ------------------------------------------------------------ backend selection


class _StubHttp:
    """Minimal HttpClient stand-in: canned routes, recorded calls."""

    def __init__(self, routes: dict[str, tuple[int, dict]]):
        self.routes = routes
        self.calls: list[dict] = []

    async def request(self, method, url, *, json=None, headers=None, retries=1, **kw):
        self.calls.append({"method": method, "url": url, "json": json, "headers": headers})
        for prefix, (status, body) in self.routes.items():
            if url.startswith(prefix):
                return _StubResponse(status, body)
        return None

    async def get_json(self, url, **kw):
        resp = await self.request("GET", url)
        return resp.json() if resp and resp.status_code < 400 else None


class _StubResponse:
    def __init__(self, status: int, body: dict):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


async def test_gemini_is_preferred_when_its_key_is_set(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gem-test")
    provider, reason = await select_provider(_StubHttp({}), Config())  # type: ignore[arg-type]
    assert reason == ""
    assert provider.spec.name == "gemini", "gemini is the default backend"
    assert provider.spec.free


async def test_falls_back_to_another_free_tier_when_gemini_key_is_absent(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    provider, reason = await select_provider(_StubHttp({}), Config())  # type: ignore[arg-type]
    assert provider.spec.name == "groq"
    assert provider.spec.free


async def test_paid_backend_is_only_used_when_explicit(monkeypatch):
    for env in ("GEMINI_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    provider, _ = await select_provider(_StubHttp({}), Config(ai_provider="anthropic"))  # type: ignore[arg-type]
    assert provider.spec.name == "anthropic"
    assert not provider.spec.free


async def test_no_backend_produces_actionable_guidance(monkeypatch):
    for env in ("GEMINI_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(env, raising=False)
    provider, reason = await select_provider(_StubHttp({}), Config())  # type: ignore[arg-type]
    assert provider is None
    assert "gemini" in reason and "GEMINI_API_KEY" in reason


async def test_ollama_is_the_fallback_when_no_cloud_key_is_set(monkeypatch):
    for env in ("GEMINI_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(env, raising=False)
    http = _StubHttp(
        {"http://localhost:11434/api/tags": (200, {"models": [{"name": "qwen2.5:7b"}]})}
    )
    provider, reason = await select_provider(http, Config())  # type: ignore[arg-type]
    assert reason == ""
    assert provider.spec.name == "ollama", "ollama is the fallback when no cloud key is set"
    assert provider.spec.free


async def test_explicit_ollama_with_no_server_is_reported(monkeypatch):
    for env in ("GEMINI_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(env, raising=False)
    provider, reason = await select_provider(
        _StubHttp({}), Config(ai_provider="ollama")  # type: ignore[arg-type]
    )
    assert provider is None
    assert "ollama" in reason and "ollama serve" in reason


async def test_explicit_provider_is_honoured_and_its_absence_reported(monkeypatch):
    provider, reason = await select_provider(
        _StubHttp({}), Config(ai_provider="gemini")  # type: ignore[arg-type]
    )
    assert provider is None
    assert "needs a key" in reason


async def test_unknown_provider_is_rejected():
    provider, reason = await select_provider(
        _StubHttp({}), Config(ai_provider="nope")  # type: ignore[arg-type]
    )
    assert provider is None and "unknown AI provider" in reason


async def test_custom_endpoint_is_accepted_as_openai_compatible():
    provider, reason = await select_provider(
        _StubHttp({}),  # type: ignore[arg-type]
        Config(ai_provider="vllm", ai_base_url="http://gpu.internal:8000/v1", ai_model="qwen"),
    )
    assert reason == ""
    assert isinstance(provider, OpenAiCompatibleProvider)
    assert provider.model == "qwen"


# --------------------------------------------------------------- request shapes


async def test_gemini_request_shape(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "gem-test")
    http = _StubHttp(
        {
            "https://generativelanguage.googleapis.com": (
                200,
                {
                    "model": "gemini-3.6-flash",
                    "choices": [{"message": {"content": json.dumps(GOOD_REPORT)}}],
                    "usage": {"prompt_tokens": 1200, "completion_tokens": 400},
                },
            )
        }
    )
    provider = GeminiProvider(Config(), PROVIDERS["gemini"])
    parsed, meta = await provider.complete(
        http, "sys", "user", AnalystReport.model_json_schema()  # type: ignore[arg-type]
    )
    call = http.calls[0]
    assert call["url"] == (
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    )
    assert call["headers"]["Authorization"] == "Bearer gem-test"
    assert call["json"]["response_format"] == {"type": "json_object"}
    assert "schema" in call["json"]["messages"][1]["content"].lower()
    assert parsed == GOOD_REPORT
    assert meta["output_tokens"] == 400


@pytest.mark.parametrize(
    "status,expected",
    [(401, "credentials rejected"), (429, "quota exhausted"), (500, "500")],
)
async def test_openai_compatible_errors_are_explained(monkeypatch, status, expected):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    http = _StubHttp({"https://api.groq.com": (status, {"error": "x"})})
    provider = OpenAiCompatibleProvider(Config(), PROVIDERS["groq"])
    parsed, meta = await provider.complete(http, "s", "u", {})  # type: ignore[arg-type]
    assert parsed is None
    assert expected in meta["error"]


# ------------------------------------------------------------------ end to end


async def test_analyze_end_to_end_over_a_stubbed_gemini(graph, monkeypatch):
    RiskEngine().score(graph)
    captured: dict = {}

    class _Http(_StubHttp):
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

    stub = _Http(
        {
            "https://generativelanguage.googleapis.com": (
                200,
                {
                    "model": "gemini-3.6-flash",
                    "choices": [{"message": {"content": json.dumps(GOOD_REPORT)}}],
                },
            )
        }
    )
    monkeypatch.setenv("GEMINI_API_KEY", "gem-test")
    monkeypatch.setattr("openrecon.ai.analyst.HttpClient", lambda config: stub)

    result = await AiAnalyst(Config(ai_provider="gemini")).analyze(graph)
    captured.update(result)

    assert result["available"] is True
    assert result["provider"] == "gemini"
    assert result["free"] is True
    assert result["report"]["posture_verdict"] == "Materially exposed."

    prompt = next(
        c for c in stub.calls if c["url"].endswith("/chat/completions")
    )["json"]["messages"][1]
    digest = json.loads(
        prompt["content"].split("<scan_digest>")[1].split("</scan_digest>")[0]
    )
    assert digest["target"] == "example.com"
    assert any(f["cve"] == "CVE-2021-22205" for f in digest["top_findings"])


async def test_analyze_is_a_no_op_when_disabled(graph):
    result = await AiAnalyst(Config(ai_enabled=False)).analyze(graph)
    assert result == {"available": False, "reason": "AI analyst disabled (--no-ai)"}


async def test_report_renders_in_both_outputs(graph, tmp_path, monkeypatch):
    from rich.console import Console

    from openrecon.report.console import render_report
    from openrecon.report.html import render_html

    RiskEngine().score(graph)
    graph.analysis = {
        "available": True,
        "provider": "gemini",
        "free": True,
        "model": "gemini-3.6-flash",
        "report": GOOD_REPORT,
        "warning": "",
        "usage": {"input_tokens": 900, "output_tokens": 300},
    }

    console = Console(record=True, width=100, force_terminal=False)
    render_report(graph, console)
    text = console.export_text()
    assert "AI ANALYST" in text
    assert "Firewall port 9200" in text
    assert "gemini" in text and "free" in text

    html = render_html(graph, tmp_path / "r.html").read_text(encoding="utf-8")
    assert "Firewall port 9200" in html
    assert "gemini" in html


def test_digest_stays_bounded_on_a_large_graph():
    from openrecon.core.graph import AttackSurfaceGraph
    from openrecon.core.models import Finding, Node, NodeType, Severity

    g = AttackSurfaceGraph.seed("big.example")
    for i in range(3000):
        g.add_node(Node.create(NodeType.SUBDOMAIN, f"host{i}.big.example"))
    for i in range(500):
        g.add_finding(
            Finding(
                title=f"finding {i}",
                severity=Severity.MEDIUM,
                category="web-hardening",
                node_ids=[Node.make_id(NodeType.SUBDOMAIN, f"host{i}.big.example")],
            )
        )
    RiskEngine().score(g)
    size = len(json.dumps(build_digest(g), default=str))
    assert size < 250_000, f"digest grew to {size} bytes - it must stay cheap to send"


async def test_custom_endpoint_sends_a_key_only_when_one_is_configured(monkeypatch):
    monkeypatch.delenv("OPENRECON_AI_API_KEY", raising=False)
    config = Config(ai_provider="lmstudio", ai_base_url="http://127.0.0.1:1234/v1", ai_model="q")
    http = _StubHttp(
        {
            "http://127.0.0.1:1234": (
                200, {"choices": [{"message": {"content": json.dumps(GOOD_REPORT)}}]}
            )
        }
    )
    provider, _ = await select_provider(http, config)  # type: ignore[arg-type]
    await provider.complete(http, "s", "u", {})  # type: ignore[arg-type]
    assert "Authorization" not in http.calls[0]["headers"]

    monkeypatch.setenv("OPENRECON_AI_API_KEY", "local-token")
    http2 = _StubHttp(
        {
            "http://127.0.0.1:1234": (
                200, {"choices": [{"message": {"content": json.dumps(GOOD_REPORT)}}]}
            )
        }
    )
    provider2, _ = await select_provider(http2, config)  # type: ignore[arg-type]
    await provider2.complete(http2, "s", "u", {})  # type: ignore[arg-type]
    assert http2.calls[0]["headers"]["Authorization"] == "Bearer local-token"


@pytest.mark.parametrize(
    "model,small",
    [("llama3.2:1b", True), ("qwen2.5:3b", True), ("qwen2.5:7b", False),
     ("llama-3.3-70b-versatile", False), ("claude-opus-5", False)],
)
def test_small_model_detection(model, small):
    from openrecon.ai.providers import is_small_model

    assert is_small_model(model) is small


async def test_small_models_get_a_reliability_warning(graph, monkeypatch):
    RiskEngine().score(graph)

    class _Http(_StubHttp):
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

    # A custom OpenAI-compatible endpoint serving a tiny model: the analyst must
    # flag that its output is not to be trusted at face value.
    stub = _Http(
        {
            "http://127.0.0.1:1234": (
                200, {"choices": [{"message": {"content": json.dumps(GOOD_REPORT)}}]}
            )
        }
    )
    monkeypatch.setattr("openrecon.ai.analyst.HttpClient", lambda config: stub)

    result = await AiAnalyst(
        Config(ai_provider="lmstudio", ai_base_url="http://127.0.0.1:1234/v1", ai_model="tiny1b")
    ).analyze(graph)
    assert result["available"] is True
    assert "small model" in result["warning"]
    assert "Verify every claim" in result["warning"]

    from rich.console import Console

    from openrecon.report.console import render_report

    graph.analysis = result
    console = Console(record=True, width=100, force_terminal=False)
    render_report(graph, console)
    assert "small model" in console.export_text()


def test_repair_warning_names_the_offending_fields():
    """A vague 'needed repair' tells the operator nothing they can act on."""
    broken = json.loads(json.dumps(GOOD_REPORT))
    broken["key_risks"][0].pop("title")

    report, warning = _validate(broken)
    assert "key_risks" in warning and "title" in warning
    assert report["executive_summary"] == GOOD_REPORT["executive_summary"]


def test_optional_fields_no_longer_count_as_malformed():
    """Dropping confidence or blind_spots is sparseness, not a schema violation."""
    sparse = json.loads(json.dumps(GOOD_REPORT))
    del sparse["blind_spots"]
    sparse["key_risks"][0].pop("confidence")

    _report, warning = _validate(sparse)
    assert warning == ""


def test_missing_optional_sections_are_not_treated_as_failure():
    minimal = {
        "executive_summary": "s",
        "posture_verdict": "v",
        "key_risks": [],
        "attack_scenarios": [],
        "prioritized_actions": [],
        "blind_spots": [],
    }
    report, warning = _validate(minimal)
    assert warning == ""
    assert report["notable_observations"] == []


@pytest.mark.parametrize(
    "raw,expected",
    [
        (["a", "b"], ["a", "b"]),
        ("single", ["single"]),
        (None, []),
        ([{"detail": "ports were not probed"}], ["ports were not probed"]),
        ([{"area": "tls", "description": "no handshake"}], ["no handshake"]),
        ([{"host": "api.example.com", "port": 443}], ["host: api.example.com; port: 443"]),
        ({"description": "wrapped in an object"}, ["wrapped in an object"]),
        (["  ", "kept"], ["kept"]),
        ([1, 2], ["1", "2"]),
    ],
)
def test_list_fields_accept_strings_or_objects(raw, expected):
    """Models legitimately disagree on how to render a list of things."""
    from openrecon.ai.analyst import _as_string_list

    assert _as_string_list(raw) == expected


def test_object_shaped_lists_validate_without_a_warning():
    """Regression: Gemini returns blind_spots as objects, which used to trip repair."""
    payload = json.loads(json.dumps(GOOD_REPORT))
    payload["blind_spots"] = [
        {"area": "active scanning", "detail": "ports were not probed"},
        {"area": "auth", "detail": "authentication state unknown"},
    ]
    payload["key_risks"][0]["affected_assets"] = [{"name": "93.184.216.34:9200"}]
    payload["attack_scenarios"][0]["steps"] = [{"description": "query the open index"}]

    report, warning = _validate(payload)
    assert warning == ""
    assert report["blind_spots"] == ["ports were not probed", "authentication state unknown"]
    assert report["key_risks"][0]["affected_assets"] == ["93.184.216.34:9200"]
    assert report["attack_scenarios"][0]["steps"] == ["query the open index"]


def test_sparse_output_is_accepted_rather_than_repaired():
    """A model that omits optional detail is not malformed."""
    report, warning = _validate(
        {
            "executive_summary": "s",
            "posture_verdict": "v",
            "prioritized_actions": [{"action": "patch it"}],
        }
    )
    assert warning == ""
    assert report["prioritized_actions"][0]["action"] == "patch it"
    assert report["key_risks"] == []
