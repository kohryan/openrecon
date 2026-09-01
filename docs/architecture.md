# Architecture

## The idea in one line

An attack surface is a **graph**, not a list. openrecon's whole design follows from
that: every collector speaks in nodes and edges, the risk engine scores the graph,
and the report draws it.

## Three types, and nothing else

| Type | What it is | Example |
|---|---|---|
| `Node` | an asset | `subdomain:dev.example.com`, `service:203.0.113.10:9200`, `vulnerability:CVE-2021-22205` |
| `Edge` | a typed relation | `dev.example.com --resolves_to--> 203.0.113.10` |
| `Finding` | a judgement about one or more nodes | "elasticsearch exposed on 203.0.113.10:9200" |

Node IDs are `{type}:{key.lower()}`, so two collectors that discover the same host
produce the same ID and their observations **merge** rather than duplicate. Merging
unions list attributes, unions tags, keeps the earliest `first_seen` and the latest
`last_seen`, and appends provenance.

Every node, edge, and finding carries `Provenance`: which collector claimed it,
from which source, when, and with what confidence. Nothing in the graph is
anonymous - if a report says a host exists, you can trace which source said so.

## The pipeline

`openrecon/pipeline.py` walks eleven stages in a fixed order:

```
registration -> dns -> subdomains -> certificates -> addresses
             -> network -> services -> fingerprint
             -> vulnerabilities -> secrets -> threat
             -> attack
```

Then the risk engine, then the AI analyst.

The `attack` stage is the bug-bounty engine: graph-scoped, active, and split into two families:

**OSS-subprocess** collectors drive best-of-breed Go scanners (katana, nuclei, ffuf, dalfox, sqlmap, interactsh) against the exact endpoints the crawler found. They need `make tools`.

**Native Python** collectors need no external binaries: `api_surface` discovers exposed API endpoints, `graphql_verify` grades introspection disclosure, `reverse_engineering` finds source maps, and the deep-attack collectors (`ssti`, `lfi`, `cmdi`, `jwt`, `cors`) probe crawled endpoints for critical server-side bugs.

The deep-attack collectors are read-only: SSTI uses arithmetic payloads (`{{7*7}}` → "49"), LFI reads system files via path traversal, CMDI uses `sleep` for time-based blind and `id`/`whoami` for error-based detection, JWT decodes and checks for `alg:none` or weak HMAC secrets, and CORS sends crafted `Origin` headers.

Ordering is the whole point: `vulnerabilities` can only correlate CVEs because
`fingerprint` already identified software versions, which was only possible because
`services` found the open ports, which needed `addresses` to resolve the hostnames
that `subdomains` discovered. The dependency chain from the README is not a diagram
of intent - it is the execution order.

Within a stage, collectors run **concurrently**. Between stages there is a barrier:
a collector always sees a complete picture from every earlier stage.

### Error isolation

A collector that raises is caught, recorded in `graph.meta.errors`, and excluded
from `collectors_run`. The scan continues. A dead upstream (crt.sh returns 502 for
long stretches) degrades the map; it never aborts it. Each collector also has a
600-second hard timeout.

## Passive by default

`ScanMode.PASSIVE` collectors read third-party sources and never send a packet to
the target. `ScanMode.ACTIVE` collectors talk to target-owned infrastructure and
are gated twice:

1. `Config.active` must be true (the `--active` flag), **and**
2. a `Scope` must be loaded.

`Scope` is an allow-list of hostname patterns and CIDR networks the operator
asserts they are authorized to test. Every active collector filters its targets
through `targets_in_scope()` before touching anything. A resolved IP is only in
scope if an in-scope hostname resolved to it (`Scope.authorize_ip`, called by the
`resolve` collector) or it falls inside a declared network.

Loopback, link-local, and multicast addresses are never scannable. RFC1918 and
reserved space is opt-in via `allow_private: true` for teams running openrecon
against internal estates.

**Managed platforms are excluded from derivation.** When a hostname CNAMEs into
Vercel, Netlify, CloudFront, GitHub Pages and the like, its addresses belong to
that platform. `ResolveCollector` recognises those CNAME targets, tags the
addresses `shared-infrastructure`, and does *not* call `authorize_ip`. The port
scanner additionally refuses them unless `Scope.covered_by_network` says the
operator declared that CIDR by hand. Derivation is a convenience; scanning a
third party has to be a decision.

## Presentation

`openrecon/report/theme.py` holds the design tokens - severity colours, grade
colours, glyphs, bars - and every surface reads from it, so the live scan view,
the results screen, and the HTML report cannot drift apart. Glyphs fall back to
ASCII when the terminal encoding is not UTF-8 (or `OPENRECON_ASCII` is set).

`openrecon/report/live.py` turns pipeline progress events into a `rich.Live`
table that fills in top to bottom. It is transient: the animation is replaced by
a single static render when the scan ends, so scrollback holds a record and not a
flicker. `make_monitor` picks `ScanMonitor` for a TTY, `PlainMonitor` for a pipe
or CI log, and a null monitor for `--quiet`.

The pipeline emits `scan-start`, `stage-start`, `collector-start`,
`collector-done`, `collector-failed`, `stage-done`, `risk`, and `scan-done`. Any
consumer with a `(event, name, data)` signature can be passed as `progress=`.

## Adding a collector

```python
@register
class MyCollector(Collector):
    name = "mysource"          # unique; also the --only/--exclude key
    stage = "subdomains"       # decides when it runs
    mode = ScanMode.PASSIVE    # ACTIVE requires a scope
    description = "..."        # shown by `openrecon collectors`
    requires_keys = ("myprovider",)   # skipped cleanly when absent

    async def collect(self, graph) -> CollectorResult:
        ...
```

Rules:

- **Never mutate `graph`.** Return a `CollectorResult`; the pipeline absorbs it.
  This is what makes concurrent execution within a stage safe.
- Use `self.http` and `self.dns`, never a bare client. They carry the shared cache,
  per-host rate limiting, retries, and the user agent.
- Attach `self.prov(source)` to everything you return.
- For active collectors, filter through `self.targets_in_scope(...)`.
- Edges whose endpoints are not in the graph are dropped at absorb time, so it is
  safe to emit an edge speculatively.

Use `http.memoize(key, factory)` when two collectors need the same expensive
fetch - the CT collectors share one crt.sh/Cert Spotter round trip this way.

## Risk scoring

```
finding score = severity x category weight x likelihood x asset multiplier x blast radius
```

- **likelihood** comes from CISA KEV (2.0x - someone is exploiting it right now)
  and EPSS (up to 2.5x). A CVSS 10.0 nobody exploits scores below a CVSS 7.5 in KEV.
- **asset multiplier** raises the stakes on non-production hosts, admin panels,
  unauthenticated datastores, and anything threat intel already flagged.
- **blast radius** is reverse reachability, depth-limited to 3 hops: how many other
  assets depend on this one.

Asset risk is the sum of its findings' scores, capped at 100. Posture is 100 minus
a penalty per severity band with an exponent of 0.6, so forty low findings can
never outweigh one critical.

`attack_paths()` walks apex -> subdomain -> IP -> service -> vulnerability chains
and ranks them, which is what produces the `example.com -> dev.xxx -> GitLab ->
secret` picture.

## The AI analyst

The analyst receives `build_digest(graph)` - a bounded summary capped at roughly
10k tokens - not the raw graph. It returns a Pydantic-validated `AnalystReport`.

The backend is pluggable (`openrecon/ai/providers.py`) and free by default. Auto-
selection order is `gemini` -> `groq` -> `openrouter` -> `anthropic`:

- **gemini** (default) - Google's free tier via its OpenAI-compatible endpoint,
  using a flash model. No local install, the digest leaves only when you have a
  key, and flash models are strong enough to read. Google retires model names
  aggressively, so a 404 triggers a lookup of what the key can actually reach and
  the request retries against the newest stable flash model.
- **groq** / **openrouter** - free tiers, OpenAI-compatible, very fast. They use
  `:free` models (OpenRouter) and need an API key.
- **anthropic** - paid, and the strongest analysis of the set; only used when
  explicitly requested with `--ai anthropic`. Uses the SDK's `messages.parse`
  with `output_format`, adaptive thinking, and configurable effort.

(Local Ollama support was removed - the project standardised on cloud free tiers
plus the paid Claude backend for the strongest analysis.)

Three provider shapes cover everything:

- **OpenAI-compatible** (`/chat/completions`) covers Gemini, Groq, OpenRouter, and
  any self-hosted vLLM / LM Studio endpoint. These get `response_format:
  json_object` plus the schema in the prompt, since `json_schema` support is
  uneven across free tiers.
- **Anthropic** uses the SDK's `messages.parse` with `output_format`, adaptive
  thinking, and configurable effort.

Because small models drift, `extract_json` recovers an object from fenced or
prose-wrapped output, and `_validate` salvages partially-malformed reports rather
than discarding them - valid items are kept, malformed ones dropped, and the result
is annotated with what was lost.

**Security note.** Banners, page titles, certificate subjects, and file contents in
the digest were produced by machines the target may not control. They are untrusted
input. Two defences:

1. The system prompt states the data boundary explicitly and instructs the model to
   report - never follow - instructions found in scan data.
2. The HTML report escapes `<`, `>`, and `&` in the embedded JSON payload, so a
   banner containing `</script>` cannot break out of the data block and execute in
   whoever opens the report. This is covered by a regression test.

## Output

- `out/<target>/<timestamp>.json` - the full graph, the durable artifact
- `out/<target>.html` - a self-contained interactive report (no CDN, no build step)
- `openrecon diff old.json new.json` - what appeared and disappeared between scans

The JSON is the source of truth: `openrecon report` re-renders any saved scan
without re-scanning.
