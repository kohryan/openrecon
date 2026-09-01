"""GraphQL exposure verification + schema extractor.

Picks up where ``api_exposure`` leaves off. That collector flags a host as
*having* a GraphQL endpoint; this one proves what that endpoint actually lets an
attacker do. Three independent checks, each using only tool-free, read-only
queries that never touch live data:

1. introspection      - ``__schema`` / ``__type`` disclosure (full backend map)
2. mutation_surface   - whether mutations are offered (write/state-changing)
3. field_suggestion   - leaky `` Did you mean ...?`` diagnostics (user enumeration,
                        stack-trace leakage, tech fingerprinting)

For an introspectable endpoint we extract the schema into a queryable model
(types, fields, args, mutations, deprecations) so the rest of openrecon - and an
operator - can reason about the actual attack surface, not just "graphql exists".

Everything here is VERIFY-ONLY. No arbitrary operations are executed against the
target, and queries are sent with the standard GraphQL ``query`` operation type
and the well-known introspection fragments only.

Relies on a dedicated ``graphql`` attack-stage node so findings anchor to a real
node, and folds a genuinely introspectable endpoint back into the graph as a
searchable ``secret``-style node carrying the extracted schema.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any

from openrecon.collectors.base import Collector, register
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import (
    CollectorResult,
    Edge,
    EdgeType,
    Finding,
    Node,
    NodeType,
    ScanMode,
    Severity,
)

# A short, rotating set of introspection probes. We send the classic
# ``__schema`` query first; if that is disabled (common hardening) we fall back
# to ``__type`` on a name every GraphQL server reserves (``Query``), which leaks
# the root operation type and its fields even when full introspection is off.
INTROSPECTION_QUERIES: list[dict[str, str]] = [
    {
        "name": "schema",
        "query": (
            "query __openrecon_introspection {"
            "  __schema {"
            "    queryType { name }"
            "    mutationType { name }"
            "    subscriptionType { name }"
            "    types { name kind description }"
            "    directives { name }"
            "  }"
            "}"
        ),
    },
    {
        "name": "type_query",
        "query": (
            "query __openrecon_type {"
            "  __type(name: \"Query\") {"
            "    name kind"
            "    fields { name type { name kind ofType { name kind } } }"
            "  }"
            "}"
        ),
    },
]

# Mutations are the dangerous half of GraphQL; a query-only API is far less
# interesting than one that accepts writes. We ask the schema directly rather
# than guessing endpoint names.
MUTATION_QUERY: dict[str, str] = {
    "name": "mutations",
    "query": (
        "query __openrecon_mutations {"
        "  __schema {"
        "    mutationType { name fields { name type { name kind } } }"
        "  }"
        "}"
    ),
}

# Field-suggestion leakage: a misspelled field on the root Query type should
# return a "Did you mean ..." error. The presence of that hint (vs a generic 400)
# tells us the server ships an unhardened developer experience to the internet.
SUGGESTION_QUERY: dict[str, str] = {
    "name": "suggestion",
    "query": "query __openrecon_suggest { thisFieldDefinitelyDoesNotExist12345 }",
}

# Severities, in increasing order of concern.
SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# Keywords that indicate a GraphQL response is an authentication/authorization
# error. GraphQL servers commonly return HTTP 200 with an error body instead of
# 401, so we inspect error messages to detect auth-locked endpoints. This lets
# us distinguish a genuinely open endpoint from one that is reachable but
# locked down — the difference between a real exposure and a "yes it's there
# but you can't touch it" note.
_AUTH_ERROR_KEYWORDS = (
    "unauthorized",
    "authentication required",
    "must be authenticated",
    "forbidden",
    "not authenticated",
    "auth error",
    "login required",
    "access denied",
    "json web token",
    "jwt",
    "bearer",
)


def is_auth_locked(body: str, status: int) -> bool:
    """Detect whether a GraphQL response indicates an auth-locked endpoint.

    GraphQL servers commonly return HTTP 200 with an error body instead of 401,
    so we inspect both the status code and error messages. This distinguishes
    a genuinely open endpoint from one that is reachable but locked down.
    """
    if status in (401, 403):
        return True
    if not body:
        return False
    lowered = body[:400_000].lower()
    return any(kw in lowered for kw in _AUTH_ERROR_KEYWORDS)


# A stable map of known API "kinds" to a (color, glyph) pair. Any collector can
# claim a distinct node colour in the graph by setting ``attrs.kind`` to one of
# these keys (e.g. the Swagger/OpenAPI probe, a gRPC reflection collector, ...).
# This is the general hook: it is not GraphQL-specific. Unknown kinds fall back to
# the ``api`` colour defined in ``theme.NODE_COLOR``.
API_KIND_COLOR: dict[str, str] = {
    "graphql": "#f472b6",        # pink - matches the screenshot's secret/red family? no: distinct pink
    "graphql-introspectable": "#ef4444",  # red when the schema is fully disclosed
    "openapi": "#a3e635",        # green
    "swagger": "#a3e635",
    "grpc": "#c084fc",           # purple
    "api-root": "#fb923c",       # orange
}
API_KIND_GLYPH: dict[str, str] = {
    "graphql": "⬡",              # hexagon - GraphQL's mark
    "graphql-introspectable": "⬢",
    "openapi": "✦",
    "swagger": "✦",
    "grpc": "▣",
    "api-root": "⌘",
}


@dataclass
class GqlField:
    name: str
    type: str | None = None
    args: list[str] = field(default_factory=list)
    description: str | None = None
    deprecated: bool = False
    deprecation_reason: str | None = None


@dataclass
class GqlType:
    name: str
    kind: str | None = None
    description: str | None = None
    fields: list[GqlField] = field(default_factory=list)
    of_type: str | None = None


@dataclass
class ExtractedSchema:
    """A minimal, queryable model of an introspected GraphQL schema.

    Built to be serialised into a graph node and inspected by operators without
    needing a GraphQL client. Mirrors just enough of the spec to reason about the
    endpoint's real attack surface.
    """

    query_type: str | None = None
    mutation_type: str | None = None
    subscription_type: str | None = None
    types: dict[str, GqlType] = field(default_factory=dict)
    mutations: list[dict[str, Any]] = field(default_factory=list)
    deprecated: list[dict[str, Any]] = field(default_factory=list)
    directives: list[str] = field(default_factory=list)
    field_count: int = 0

    @property
    def introspectable(self) -> bool:
        return bool(self.types or self.query_type)

    def to_node_attrs(self) -> dict[str, Any]:
        # `kind` is the general hook the graph UI keys off (see API_KIND_COLOR):
        # an introspectable endpoint reads as a distinct, red-shifted node.
        kind = "graphql-introspectable" if self.introspectable else "graphql"
        attrs: dict[str, Any] = {
            "kind": kind,
            "graphql_query_type": self.query_type,
            "graphql_mutation_type": self.mutation_type,
            "graphql_subscription_type": self.subscription_type,
            "graphql_type_count": len(self.types),
            "graphql_field_count": self.field_count,
            "graphql_mutation_count": len(self.mutations),
            "graphql_deprecated_count": len(self.deprecated),
            "graphql_directives": self.directives,
            "graphql_mutations": self.mutations[:50],
            "graphql_deprecated": self.deprecated[:50],
        }
        if self.introspectable:
            attrs["graphql_schema_sdl"] = to_sdl(self)
        return attrs


def _unwrap(type_ref: dict[str, Any] | None) -> str | None:
    """Follow ``ofType`` chains (LIST / NON_NULL wrappers) to the named type."""
    if not type_ref:
        return None
    seen = 0
    while type_ref.get("ofType") and seen < 8:
        type_ref = type_ref["ofType"]
        seen += 1
    return type_ref.get("name")


def classify_endpoint(body: str, status: int) -> tuple[bool, bool, str | None, dict[str, Any]]:
    """Classify a GraphQL response: is it GraphQL, is it auth-locked, and what
    does it leak.

    Returns ``(is_graphql, auth_locked, error_hint, introspection_hit)`` where
    ``auth_locked`` is True when the endpoint requires authentication for the
    probed query (so the exposure is not freely exploitable), and
    ``introspection_hit`` is the parsed ``__schema``/``__type`` data when the
    server answered introspection.
    """
    is_gql, hint, payload = classify_body(body, status)
    if not is_gql:
        return False, False, hint, {}
    locked = is_auth_locked(body, status)
    return is_gql, locked, hint, payload


def classify_body(body: str, status: int) -> tuple[bool, str | None, dict[str, Any]]:
    """Decide whether a response is a live GraphQL endpoint and what it leaks.

    Returns ``(is_graphql, error_hint, introspection_hit)`` where
    ``introspection_hit`` is the parsed ``__schema``/``__type`` data when the
    server answered introspection, else ``{}``.

    This is deliberately schema-agnostic: it keys off the markers a real GraphQL
    server emits (``"data"`` + ``"__schema"`` / ``"__type"``, or ``errors`` with
    ``"locations"``) rather than expecting any specific shape, so it stays
    accurate across server implementations (graphql-go, Apollo, Strawberry, ...).
    """
    if not body:
        return False, None, {}
    lowered = body[:400_000].lower()
    try:
        parsed = json.loads(body[:400_000])
    except ValueError:
        parsed = None

    # Soft-404 / generic HTML pages are not GraphQL regardless of status.
    if "<html" in lowered[:200] and parsed is None:
        return False, None, {}

    if parsed is not None and isinstance(parsed, dict):
        has_data = isinstance(parsed.get("data"), dict)
        has_graphql_marker = (
            "__schema" in parsed.get("data", {}) or "__type" in parsed.get("data", {})
            if has_data
            else False
        )
        errors = parsed.get("errors")
        has_gql_errors = isinstance(errors, list) and any(
            isinstance(e, dict) and ("locations" in e or "message" in e) for e in errors
        )
        if has_graphql_marker:
            return True, None, parsed.get("data", {})
        if has_data or has_gql_errors:
            return True, None, {}

    # Fall back to text markers for non-JSON GraphQL responses.
    if '"__schema"' in lowered or '"__type"' in lowered or '"data"' in lowered:
        return True, None, {}
    if status == 400 and "graphql" in lowered:
        return True, None, {}
    return False, None, {}


def extract_schema(payload: dict[str, Any]) -> ExtractedSchema:
    """Turn an introspection ``data`` payload into an ExtractedSchema."""
    schema = ExtractedSchema()
    schema_root = payload.get("__schema") if isinstance(payload, dict) else None
    if not isinstance(schema_root, dict):
        # Possibly a ``__type``-only response.
        t = payload.get("__type") if isinstance(payload, dict) else None
        if isinstance(t, dict):
            qname = str(t.get("name") or "Query")
            schema.query_type = qname
            flds = [f for f in (t.get("fields") or []) if isinstance(f, dict)]
            schema.types[qname] = GqlType(
                name=qname,
                kind="OBJECT",
                description=t.get("description"),
                fields=[_simplify_field(f) for f in flds],
            )
            schema.field_count = len(flds)
        return schema

    qt = schema_root.get("queryType") or {}
    mt = schema_root.get("mutationType") or {}
    st = schema_root.get("subscriptionType") or {}
    schema.query_type = (qt.get("name") if isinstance(qt, dict) else None) or None
    schema.mutation_type = (mt.get("name") if isinstance(mt, dict) else None) or None
    schema.subscription_type = (st.get("name") if isinstance(st, dict) else None) or None
    schema.directives = [str(d.get("name")) for d in schema_root.get("directives", []) if isinstance(d, dict) and d.get("name")]

    for raw in schema_root.get("types", []):
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        if not name or name.startswith("__"):
            continue  # skip introspection meta-types
        gtype = GqlType(
            name=name,
            kind=raw.get("kind"),
            description=raw.get("description"),
        )
        fields = raw.get("fields") or []
        for f in fields:
            if not isinstance(f, dict):
                continue
            gtype.fields.append(_simplify_field(f))
            # Track deprecated fields (carry sensitive data / old auth paths).
            directives = f.get("isDeprecated") or any(
                d.get("name") == "deprecated"
                for d in (f.get("directives") or [])
                if isinstance(d, dict)
            )
            if directives:
                schema.deprecated.append(
                    {
                        "type": name,
                        "field": f.get("name"),
                        "reason": (f.get("deprecationReason") if isinstance(f, dict) else None),
                    }
                )
        schema.types[name] = gtype
        schema.field_count += len(gtype.fields)

    # Mutations from the schema root (more reliable than the separate probe).
    if isinstance(mt, dict):
        for m in mt.get("fields", []) or []:
            if isinstance(m, dict):
                schema.mutations.append({"name": m.get("name"), "type": _unwrap(m.get("type"))})
    return schema


def _simplify_field(f: dict[str, Any]) -> GqlField:
    args = [a.get("name") for a in (f.get("args") or []) if isinstance(a, dict) and a.get("name")]
    directives = f.get("isDeprecated") or any(
        d.get("name") == "deprecated" for d in (f.get("directives") or []) if isinstance(d, dict)
    )
    reason = (f.get("deprecationReason") if isinstance(f, dict) else None)
    if not directives:
        reason = None
    return GqlField(
        name=f.get("name") or "",
        type=_unwrap(f.get("type")),
        args=[str(a) for a in args],
        description=f.get("description"),
        deprecated=bool(directives),
        deprecation_reason=reason,
    )


def to_sdl(schema: ExtractedSchema) -> str:
    """Render an ExtractedSchema to standard GraphQL SDL.

    General-purpose: feed it any introspection result and get a portable
    ``.graphql`` document an operator can load into any GraphQL IDE (GraphiQL,
    Altair, Insomnia) to continue manual testing. Scalar/enum/input bodies are
    emitted as stubs (we don't introspect their values), but OBJECT types carry
    full field/argument definitions, which is the part that matters for review.
    """
    lines: list[str] = ["# Extracted by openrecon GraphQL verification (introspection).", ""]
    if schema.query_type:
        lines.append("schema {")
        if schema.query_type:
            lines.append(f"  query: {schema.query_type}")
        if schema.mutation_type:
            lines.append(f"  mutation: {schema.mutation_type}")
        if schema.subscription_type:
            lines.append(f"  subscription: {schema.subscription_type}")
        lines.append("}\n")

    # Directives first, then objects, then stubs for other kinds.
    for name, gtype in sorted(schema.types.items()):
        if gtype.kind == "OBJECT":
            lines.append(f"type {name} {{")
            for fld in gtype.fields:
                argstr = ""
                if fld.args:
                    argstr = "(" + ", ".join(f"{a}: String" for a in fld.args) + ")"
                suffix = f" @deprecated(reason: \"{fld.deprecation_reason}\")" if fld.deprecated and fld.deprecation_reason else (" @deprecated" if fld.deprecated else "")
                lines.append(f"  {fld.name}{argstr}: {fld.type or 'String'}{suffix}")
            lines.append("}\n")
        elif gtype.kind in ("SCALAR", "ENUM", "INPUT_OBJECT"):
            lines.append(f"# {gtype.kind} (values not introspected)")
            lines.append(f"{gtype.kind} {name}\n")
        elif gtype.kind == "INTERFACE":
            lines.append(f"interface {name} {{")
            for fld in gtype.fields:
                lines.append(f"  {fld.name}: {fld.type or 'String'}")
            lines.append("}\n")

    if schema.directives:
        lines.append("# Directives offered by the server:")
        for d in schema.directives:
            lines.append(f"#   @{d}")
    return "\n".join(lines).rstrip() + "\n"


def grep_mutations(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull mutation names from a dedicated mutation introspection response."""
    if not isinstance(payload, dict):
        return []
    root = payload.get("__schema", {})
    mt = root.get("mutationType") if isinstance(root, dict) else None
    if not isinstance(mt, dict):
        return []
    return [{"name": m.get("name"), "type": _unwrap(m.get("type"))} for m in mt.get("fields", []) or []]


def suggest_marker(body: str) -> str | None:
    """Return the leaked suggestion string if the server echoed one, else None."""
    if not body:
        return None
    # GraphQL servers return: "message": "Cannot query field
    # 'thisField...' on type 'Query'. Did you mean 'x', 'y'?"
    m = re.search(r"Did you mean[^'\"]*['\"]([^'\"]+)['\"]", body)
    if m:
        return m.group(1)
    if "Cannot query field" in body or "did you mean" in body.lower():
        return "suggestion-leaked"
    return None


@register
class GraphQLVerifier(Collector):
    """Verify a discovered GraphQL endpoint: introspection, mutations, leakage.

    Operates on the ``api`` nodes ``api_exposure`` flagged as GraphQL, plus the
    standard ``/graphql`` path on every in-scope web host (so it is not blind to
    endpoints the spec-probe missed). Read-only, introspection-fragment-only,
    verify-only - no arbitrary operations are executed.
    """

    name = "graphql_verify"
    stage = "attack"
    mode = ScanMode.ACTIVE
    description = "Verify GraphQL endpoints: introspection disclosure, mutation surface, field-suggestion leakage, and extract the schema"

    async def collect(self, graph: AttackSurfaceGraph) -> CollectorResult:
        result = CollectorResult()

        # Candidate (host, path) pairs: known GraphQL api nodes + /graphql on
        # every web host. Dedup on (host, path).
        targets = self._candidates(graph)
        if not targets:
            result.errors.append(
                "graphql_verify: no discovered GraphQL endpoints and no in-scope "
                "web hosts to probe (run api_exposure or the crawler first)"
            )
            return result

        sem = asyncio.Semaphore(max(1, self.config.concurrency // 2))
        tasks = [self._verify(sem, graph, host, path, result) for host, path in targets]
        await asyncio.gather(*tasks)
        result.stats["graphql_targets"] = len(targets)
        return result

    # -------------------------------------------------------------- candidates

    def _candidates(self, graph: AttackSurfaceGraph) -> list[tuple[str, str]]:
        seen: set[tuple[str, str]] = set()
        out: list[tuple[str, str]] = []

        # GraphQL api nodes from api_exposure.
        for n in graph.nodes_of(NodeType.API):
            if "graphql" in (n.attrs.get("kind", "") or "").lower() or "graphql" in n.label.lower():
                host = n.attrs.get("host") or self._host_of(n.attrs.get("url", ""))
                path = self._path_of(n.attrs.get("url", "")) or "/graphql"
                if host:
                    key = (host, path)
                    if key not in seen:
                        seen.add(key)
                        out.append((host, path))

        # Every in-scope web host, standard path.
        hosts = [
            n.label
            for n in graph.nodes_of(NodeType.DOMAIN, NodeType.SUBDOMAIN)
            if "web" in n.tags or n.attrs.get("http_status") or n.attrs.get("resolves")
        ]
        hosts = self.targets_in_scope(hosts)[:100]
        for host in hosts:
            key = (host, "/graphql")
            if key not in seen:
                seen.add(key)
                out.append((host, "/graphql"))
        return out

    # ------------------------------------------------------------------- verify

    async def _verify(self, sem: asyncio.Semaphore, graph: AttackSurfaceGraph, host: str, path: str, result: CollectorResult) -> None:
        url = f"https://{host}{path}"
        async with sem:
            # 1) Try introspection (schema, then type fallback).
            introspect_payload: dict[str, Any] = {}
            reachable = False
            auth_locked = False
            for probe in INTROSPECTION_QUERIES:
                resp = await self.http.request(
                    "POST", url,
                    json={"query": probe["query"]},
                    headers={"Content-Type": "application/json"},
                    retries=0,
                )
                if resp is None:
                    continue
                is_gql, locked, _, payload = classify_endpoint(resp.text, resp.status_code)
                if not is_gql:
                    continue
                reachable = True
                auth_locked = auth_locked or locked
                if payload:
                    introspect_payload = payload
                    break

            if not reachable:
                # Not a GraphQL endpoint (or fully locked down). Nothing to grade.
                return

            host_id = Node.make_id(
                NodeType.DOMAIN if host == graph.meta.target else NodeType.SUBDOMAIN, host
            )
            node_id = Node.make_id(NodeType.API, url)
            prov = self.prov(url)

            findings: list[Finding] = []
            attrs: dict[str, Any] = {
                "host": host,
                "path": path,
                "url": url,
                "kind": "graphql",
                "status": "reachable",
                "introspectable": False,
                "mutations_exposed": False,
                "suggestion_leak": False,
                "auth_locked": auth_locked,
            }

            # 2) Mutation surface (only if introspection gave us a schema).
            mutations: list[dict[str, Any]] = []
            if introspect_payload:
                schema = extract_schema(introspect_payload)
                attrs.update(schema.to_node_attrs())
                attrs["introspectable"] = True
                mutations = list(schema.mutations)
            else:
                # Introspection off but endpoint alive: probe mutations directly.
                mresp = await self.http.request(
                    "POST", url,
                    json={"query": MUTATION_QUERY["query"]},
                    headers={"Content-Type": "application/json"},
                    retries=0,
                )
                if mresp is not None:
                    _, locked, _, mpayload = classify_endpoint(mresp.text, mresp.status_code)
                    auth_locked = auth_locked or locked
                    mutations = grep_mutations(mpayload) if mpayload else []

            if mutations:
                attrs["mutations_exposed"] = True
                attrs["graphql_mutations"] = mutations[:50]
                findings.append(
                    self._finding(
                        f"GraphQL mutations exposed at {host}{path}",
                        Severity.HIGH,
                        "graphql-exposure",
                        node_id, host_id, prov, attrs,
                        description=(
                            f"{host}{path} advertises {len(mutations)} mutation(s) "
                            f"(e.g. {', '.join(m['name'] for m in mutations[:5])}). "
                            "A writable GraphQL surface widens the attack surface well "
                            "beyond read-only recon: state-changing operations, auth "
                            "bypass on write paths, and batching/abuse vectors."
                        ),
                        remediation=(
                            "Disable introspection in production, restrict mutations to "
                            "authenticated roles, and apply a depth/complexity limit to "
                            "every operation."
                        ),
                        evidence=[
                            {"type": "url", "value": url},
                            {"type": "mutations", "value": mutations[:50]},
                        ],
                    )
                )

            # 3) Field-suggestion leakage.
            sresp = await self.http.request(
                "POST", url,
                json={"query": SUGGESTION_QUERY["query"]},
                headers={"Content-Type": "application/json"},
                retries=0,
            )
            suggestion = suggest_marker(sresp.text) if sresp is not None else None
            if suggestion:
                attrs["suggestion_leak"] = True
                findings.append(
                    self._finding(
                        f"GraphQL verbose errors leaked at {host}{path}",
                        Severity.MEDIUM,
                        "graphql-exposure",
                        node_id, host_id, prov, attrs,
                        description=(
                            f"{host}{path} echoes developer-style error hints "
                            f"(\\\"Did you mean '{suggestion}'?\\\"). Verbose GraphQL errors "
                            "aid field enumeration, tech fingerprinting, and can leak "
                            "internal type/field names or stack detail to unauthenticated"
                            " callers."
                        ),
                        remediation=(
                            "Disable field suggestions and return generic errors in "
                            "production; never ship a developer error experience to the "
                            "internet."
                        ),
                        evidence={"url": url, "suggestion": suggestion},
                    )
                )

            # 4) Introspection disclosure - the headline finding.
            if attrs["introspectable"]:
                findings.append(
                    self._finding(
                        f"Exposed GraphQL introspection at {host}{path}",
                        Severity.HIGH,
                        "graphql-exposure",
                        node_id, host_id, prov, attrs,
                        description=(
                            f"{host}{path} answers GraphQL introspection, disclosing "
                            f"{attrs.get('graphql_type_count', 0)} types and "
                            f"{attrs.get('graphql_field_count', 0)} fields - a complete "
                            "map of the backend. The extracted schema is attached for "
                            "review."
                        ),
                        remediation=(
                            "Disable introspection in production (graphql-disable-introspection) "
                            "or gate it behind authentication. Treat the schema as already "
                            "compromised: review every resolver for authz, rate limits, and "
                            "sensitive data exposure."
                        ),
                        evidence={
                            "url": url,
                            "query_type": attrs.get("graphql_query_type"),
                            "mutation_type": attrs.get("graphql_mutation_type"),
                            "type_count": attrs.get("graphql_type_count"),
                            "field_count": attrs.get("graphql_field_count"),
                            "deprecated": attrs.get("graphql_deprecated", [])[:20],
                            "mutations": mutations[:50],
                        },
                    )
                )
            elif auth_locked:
                # Reachable but auth-locked and not introspectable: an info note,
                # not a real exposure. The endpoint exists but an attacker cannot
                # freely query it.
                findings.append(
                    self._finding(
                        f"GraphQL endpoint at {host}{path} requires authentication",
                        Severity.INFO,
                        "graphql-exposure",
                        node_id, host_id, prov, attrs,
                        description=(
                            f"{host}{path} is a reachable GraphQL endpoint but "
                            "requires authentication. Introspection is disabled and "
                            "no anonymous queries succeed. The endpoint is noted for "
                            "completeness but is not a direct exposure."
                        ),
                        remediation=(
                            "Ensure authentication is enforced on all operations and "
                            "introspection remains disabled in production."
                        ),
                        evidence={"url": url, "auth_locked": True},
                    )
                )

            # Always record the verified endpoint as a node; when introspectable,
            # fold the schema into a searchable node for downstream review.
            node = Node.create(
                NodeType.API, url,
                label=f"GraphQL at {host}{path}",
                attrs=attrs,
                provenance=prov,
                tags={"exposed", "api", "graphql", "verified"},
            )
            result.nodes.append(node)
            result.edges.append(
                Edge(source=host_id, target=node.id, type=EdgeType.EXPOSES, provenance=[prov])
            )
            result.findings.extend(findings)
            if attrs["introspectable"]:
                self.progress("graphql-introspectable", {"host": host, "url": url})

    # ----------------------------------------------------------------- helpers

    def _finding(self, title, severity, category, node_id, host_id, prov, attrs, description, remediation, evidence) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            category=category,
            node_ids=[node_id, host_id],
            description=description,
            evidence=evidence,
            remediation=remediation,
            collector=self.name,
        )

    def _host_of(self, url: str) -> str | None:
        from urllib.parse import urlparse

        try:
            return urlparse(url).hostname or None
        except ValueError:
            return None

    def _path_of(self, url: str) -> str | None:
        from urllib.parse import urlparse

        try:
            p = urlparse(url).path
            return p or None
        except ValueError:
            return None
