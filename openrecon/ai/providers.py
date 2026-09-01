"""LLM backends for the AI analyst.

openrecon does not require a paid API. The analyst runs on whatever is available,
in this order of preference:

  1. `gemini`     - Google's free tier via its OpenAI-compatible endpoint. The
                    default: no local install, the digest leaves only when you
                    have a key, and Google's flash models are strong enough to
                    read.
  2. `groq`       - free tier, OpenAI-compatible, very fast.
  3. `openrouter` - free-tier models (the `:free` suffix), OpenAI-compatible.
  4. `ollama`     - local models via `ollama serve`. No key, nothing leaves the
                    machine. Used as a fallback when no cloud key is set and
                    Ollama is running; small models get a reliability warning.
  5. `anthropic`  - paid, and the strongest analysis of the set; only used when
                    explicitly requested with `--ai anthropic`.

All cloud providers are OpenAI-compatible chat completions, so one client covers
them; only the base URL, model, and key differ. Ollama speaks the same
`/chat/completions` protocol at its local endpoint.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from openrecon.config import Config
from openrecon.core.net import HttpClient


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    base_url: str
    default_model: str
    key_provider: str | None
    free: bool
    note: str


PROVIDERS: dict[str, ProviderSpec] = {
    "gemini": ProviderSpec(
        "gemini", "https://generativelanguage.googleapis.com/v1beta/openai",
        "gemini-3.1-flash-lite", "gemini", True,
        "free tier, needs GEMINI_API_KEY",
    ),
    "groq": ProviderSpec(
        "groq", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile", "groq", True,
        "free tier, needs GROQ_API_KEY",
    ),
    "openrouter": ProviderSpec(
        "openrouter", "https://openrouter.ai/api/v1",
        "meta-llama/llama-3.3-70b-instruct:free", "openrouter", True,
        "free-tier models, needs OPENROUTER_API_KEY",
    ),
    "anthropic": ProviderSpec(
        "anthropic", "", "claude-opus-5", "anthropic", False,
        "paid, strongest analysis",
    ),
    "ollama": ProviderSpec(
        "ollama", "http://localhost:11434/v1", "qwen2.5:7b", None, True,
        "local models via ollama serve; nothing leaves the machine",
    ),
}

PREFERENCE = ["gemini", "groq", "openrouter", "ollama", "anthropic"]

JSON_INSTRUCTION = """\

Respond with a single JSON object and nothing else - no prose before or after, no \
markdown fence. It must match this schema exactly:

{schema}
"""


def _ollama_base(config: Config) -> str:
    return (config.ai_base_url or "http://localhost:11434").rstrip("/")


async def ollama_models(http: HttpClient, config: Config) -> list[str] | None:
    """List running Ollama models, or None if Ollama is not serving.

    Returns the model names (e.g. ``["qwen2.5:7b"]``) so the CLI can show what
    the user has locally, and ``select_provider`` can tell "running" from
    "not installed".
    """
    data = await http.get_json(f"{_ollama_base(config)}/api/tags", retries=0)
    if not data:
        return None
    return [str(m.get("name", "")) for m in data.get("models", []) if m.get("name")]


async def _ollama_available(http: HttpClient, config: Config) -> bool:
    return bool(await ollama_models(http, config))


def is_small_model(model: str) -> bool:
    """True for models below ~4B parameters, inferred from the tag.

    Small models satisfy the schema but invent findings that are not in the
    digest. For a security tool that is worse than no analysis, so the report
    says so out loud rather than presenting it as fact.
    """
    match = re.search(r"(\d+(?:\.\d+)?)\s*b\b", model.lower())
    return bool(match) and float(match.group(1)) < 4


def extract_json(text: str) -> dict[str, Any] | None:
    """Pull a JSON object out of a model response.

    Small models wrap JSON in prose or a ```json fence even when told not to, so
    this is deliberately forgiving: strip fences, then take the outermost
    balanced object.
    """
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
    if fenced:
        text = fenced.group(1)
    text = text.strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    if start == -1:
        return None
    depth, in_string, escaped = 0, False, False
    for i, ch in enumerate(text[start:], start):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(text[start : i + 1])
                    return parsed if isinstance(parsed, dict) else None
                except json.JSONDecodeError:
                    return None
    return None


class Provider:
    """Base contract: turn (system, user, schema) into a validated dict."""

    def __init__(self, config: Config, spec: ProviderSpec) -> None:
        self.config = config
        self.spec = spec
        self.model = config.ai_model or spec.default_model

    async def complete(
        self, http: HttpClient, system: str, user: str, schema: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        raise NotImplementedError


class OpenAiCompatibleProvider(Provider):
    """Groq, OpenRouter, Gemini, Together, vLLM - anything speaking /chat/completions."""

    @property
    def base_url(self) -> str:
        return (self.config.ai_base_url or self.spec.base_url).rstrip("/")

    async def complete(
        self, http: HttpClient, system: str, user: str, schema: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        # A named provider requires its own key; a custom endpoint takes an
        # optional generic one.
        key = self.config.key(self.spec.key_provider or "openai_compatible")
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        if self.spec.name == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/kohryan/openrecon"
            headers["X-Title"] = "openrecon"

        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": 0.2,
            "max_tokens": 8000,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user + JSON_INSTRUCTION.format(
                    schema=json.dumps(schema, indent=2)[:6000]
                )},
            ],
            # Free-tier endpoints support json_object far more widely than
            # json_schema, and the schema is repeated in the prompt anyway.
            "response_format": {"type": "json_object"},
        }

        resp = await http.request(
            "POST", f"{self.base_url}/chat/completions",
            json=payload, headers=headers, retries=1, timeout=300.0,
        )
        if resp is None:
            return None, {"error": f"{self.spec.name} request failed"}
        if resp.status_code >= 400:
            detail = resp.text[:300]
            if resp.status_code == 401:
                detail = "credentials rejected"
            elif resp.status_code == 429:
                detail = "rate limited / free-tier quota exhausted"
            return None, {"error": f"{self.spec.name} returned {resp.status_code}: {detail}"}
        try:
            body = resp.json()
        except ValueError:
            return None, {"error": f"{self.spec.name} returned a non-JSON body"}

        choices = body.get("choices") or []
        if not choices:
            return None, {"error": f"{self.spec.name} returned no choices"}
        content = (choices[0].get("message") or {}).get("content", "")
        usage = body.get("usage") or {}
        return extract_json(content), {
            "model": body.get("model", self.model),
            "input_tokens": usage.get("prompt_tokens"),
            "output_tokens": usage.get("completion_tokens"),
        }


class GeminiProvider(OpenAiCompatibleProvider):
    """Gemini via its OpenAI-compatible endpoint, with live model resolution.

    Google retires model names aggressively - a pinned default goes 404 within
    months. So a 404 triggers a lookup of what the key can actually reach, and
    the request is retried against the newest stable flash model. A 503 (the
    free tier's way of saying "busy") falls through to the next candidate.
    """

    STABLE_FLASH = re.compile(r"^gemini-(\d+(?:\.\d+)?)-flash$")
    MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"

    async def candidates(self, http: HttpClient) -> list[str]:
        data = await http.get_json(
            self.MODELS_URL,
            headers={"x-goog-api-key": self.config.key("gemini") or ""},
            retries=1,
        )
        found: list[tuple[float, str]] = []
        for model in (data or {}).get("models", []):
            name = str(model.get("name", "")).removeprefix("models/")
            if "generateContent" not in (model.get("supportedGenerationMethods") or []):
                continue
            match = self.STABLE_FLASH.match(name)
            if match:
                found.append((float(match.group(1)), name))
        # Newest first; a flash model is the one covered by the free tier.
        return [name for _v, name in sorted(found, reverse=True)]

    async def complete(
        self, http: HttpClient, system: str, user: str, schema: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        parsed, meta = await super().complete(http, system, user, schema)
        error = meta.get("error", "")
        if parsed is not None or not ("404" in error or "503" in error):
            return parsed, meta

        tried = {self.model}
        for candidate in (await http.memoize("gemini:models", lambda: self.candidates(http)))[:3]:
            if candidate in tried:
                continue
            tried.add(candidate)
            self.model = candidate
            parsed, meta = await super().complete(http, system, user, schema)
            if parsed is not None:
                meta["note"] = f"fell back to {candidate}"
                return parsed, meta
        meta["error"] = (
            f"no reachable Gemini model (tried {', '.join(sorted(tried))}): "
            + meta.get("error", "")
        )
        return None, meta


class AnthropicProvider(Provider):
    """Claude via the official SDK, using structured outputs."""

    async def complete(
        self, http: HttpClient, system: str, user: str, schema: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        try:
            import anthropic
        except ImportError:
            return None, {"error": "anthropic SDK not installed (pip install 'openrecon[ai]')"}

        from openrecon.ai.analyst import AnalystReport

        client = anthropic.AsyncAnthropic(api_key=self.config.key("anthropic"))
        try:
            response = await client.messages.parse(
                model=self.model,
                max_tokens=16000,
                system=system,
                thinking={"type": "adaptive"},
                output_config={"effort": self.config.ai_effort},
                messages=[{"role": "user", "content": user}],
                output_format=AnalystReport,
            )
        except anthropic.AuthenticationError:
            return None, {"error": "ANTHROPIC_API_KEY was rejected"}
        except anthropic.RateLimitError as exc:
            retry = exc.response.headers.get("retry-after", "60")
            return None, {"error": f"rate limited by the API (retry after {retry}s)"}
        except anthropic.APIConnectionError:
            return None, {"error": "could not reach the Anthropic API"}
        except anthropic.APIStatusError as exc:
            return None, {"error": f"API error {exc.status_code}: {exc.message}"}
        finally:
            await client.close()

        parsed = response.parsed_output
        return (parsed.model_dump() if parsed else None), {
            "model": self.model,
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        }


def build_provider(config: Config, spec: ProviderSpec) -> Provider:
    if spec.name == "anthropic":
        return AnthropicProvider(config, spec)
    if spec.name == "gemini":
        return GeminiProvider(config, spec)
    return OpenAiCompatibleProvider(config, spec)


async def select_provider(
    http: HttpClient, config: Config
) -> tuple[Provider | None, str]:
    """Pick a backend. Returns (provider, reason-if-none)."""
    if config.ai_provider:
        spec = PROVIDERS.get(config.ai_provider)
        if spec is None:
            if not config.ai_base_url:
                return None, (
                    f"unknown AI provider {config.ai_provider!r} "
                    f"(known: {', '.join(PROVIDERS)}; or pass --ai-base-url for a custom endpoint)"
                )
            # A custom OpenAI-compatible endpoint: self-hosted vLLM, LM Studio,
            # llama.cpp server. These usually take no auth at all, so no key is
            # required - one is sent only if OPENRECON_AI_API_KEY is set.
            spec = ProviderSpec(
                config.ai_provider, config.ai_base_url, config.ai_model or "local",
                None, True, "custom OpenAI-compatible endpoint",
            )
        if spec.name == "ollama":
            # No key to check; the only failure mode is Ollama not running.
            if not await _ollama_available(http, config):
                return None, (
                    "ollama is not running - start it with `ollama serve` "
                    "(or set a cloud key: GEMINI_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY)"
                )
            return build_provider(config, spec), ""
        if spec.key_provider and not config.key(spec.key_provider):
            return None, f"{spec.name} needs a key ({spec.note})"
        return build_provider(config, spec), ""

    tried: list[str] = []
    for name in PREFERENCE:
        spec = PROVIDERS[name]
        if spec.name == "ollama":
            # Fallback only when no cloud key is set: probe whether it is serving.
            if await _ollama_available(http, config):
                return build_provider(config, spec), ""
            tried.append("ollama (not running)")
            continue
        if spec.key_provider and config.key(spec.key_provider):
            return build_provider(config, spec), ""
        tried.append(f"{name} (no key)")

    return None, (
        "no AI backend available - tried " + ", ".join(tried) + ". "
        "Free option: set GEMINI_API_KEY (or GROQ_API_KEY / OPENROUTER_API_KEY), "
        "or run `ollama serve` for a local model; "
        "paid option: set ANTHROPIC_API_KEY and pass --ai anthropic."
    )
