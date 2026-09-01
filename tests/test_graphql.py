"""Tests for the GraphQL verification + schema extraction engine.

Covers the pure, tool-free helpers (classify / extract / suggestion) and the
collector end-to-end with a mocked HTTP client - no network, no live target.
"""

from __future__ import annotations

import asyncio
from typing import Any

from openrecon.collectors import all_collectors
from openrecon.collectors.base import CollectorContext
from openrecon.collectors.graphql import (
    GraphQLVerifier,
    classify_body,
    extract_schema,
    grep_mutations,
    suggest_marker,
    to_sdl,
)
from openrecon.config import Config
from openrecon.core.graph import AttackSurfaceGraph
from openrecon.core.models import Node, NodeType, Provenance, Severity
from openrecon.scope import Scope


# --------------------------------------------------------------- pure helpers

def test_classify_introspection_payload():
    body = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
    is_gql, hint, payload = classify_body(body, 200)
    assert is_gql is True
    assert payload  # introspection data captured


def test_classify_graphql_error_response():
    # A real GraphQL server returns structured errors with "locations".
    body = '{"errors":[{"message":"bad","locations":[{"line":1,"column":3}]}]}'
    is_gql, _, _ = classify_body(body, 400)
    assert is_gql is True


def test_classify_rejects_html_and_generic_json():
    assert classify_body("<html><body>not found</body></html>", 404)[0] is False
    # A plain JSON API (no GraphQL markers) must NOT be misclassified.
    assert classify_body('{"status":"ok","count":3}', 200)[0] is False
    assert classify_body("", 0)[0] is False


def test_extract_schema_counts_types_fields_mutations_deprecated():
    payload = {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation", "fields": [
                {"name": "createUser", "type": {"name": "User", "kind": "OBJECT"}},
                {"name": "deleteUser", "type": {"name": "Boolean"}},
            ]},
            "subscriptionType": None,
            "directives": [{"name": "include"}, {"name": "skip"}],
            "types": [
                {"name": "Query", "kind": "OBJECT", "fields": [
                    {"name": "user", "type": {"name": "User"}, "args": [{"name": "id"}]},
                    {"name": "me", "type": {"name": "User"}},
                    {"name": "legacyToken", "type": {"name": "String"},
                     "isDeprecated": True, "deprecationReason": "use tokens"},
                ]},
                {"name": "Mutation", "kind": "OBJECT", "fields": [
                    {"name": "createUser", "type": {"name": "User"}},
                ]},
                {"name": "User", "kind": "OBJECT", "fields": []},
                {"name": "__Type", "kind": "OBJECT", "fields": []},  # meta, dropped
            ],
        }
    }
    schema = extract_schema(payload)
    assert schema.introspectable is True
    assert schema.query_type == "Query"
    assert schema.mutation_type == "Mutation"
    assert len(schema.types) == 3  # meta __Type excluded
    # fields: Query(3) + Mutation(1) + User(0) = 4
    assert schema.field_count == 4
    assert len(schema.mutations) == 2
    assert schema.mutations[0]["name"] == "createUser"
    assert len(schema.deprecated) == 1
    assert schema.deprecated[0]["field"] == "legacyToken"
    assert "include" in schema.directives


def test_extract_schema_handles_type_only_response():
    payload = {"__type": {"name": "Query", "fields": [{"name": "user"}]}}
    schema = extract_schema(payload)
    assert schema.query_type == "Query"
    assert "Query" in schema.types
    assert schema.field_count == 1


def test_suggest_marker_pulls_leaked_field():
    body = '{"errors":[{"message":"Cannot query field \'foo\' on type \'Query\'. Did you mean \'user\'?"}]}'
    assert suggest_marker(body) == "user"
    assert suggest_marker('{"errors":[{"message":"Cannot query field"}]}') == "suggestion-leaked"
    assert suggest_marker("{}") is None


def test_grep_mutations_from_probe():
    payload = {"__schema": {"mutationType": {"name": "Mutation", "fields": [
        {"name": "x", "type": {"name": "Y"}},
    ]}}}
    assert grep_mutations(payload) == [{"name": "x", "type": "Y"}]
    assert grep_mutations({"__schema": {"mutationType": None}}) == []


def test_to_sdl_renders_standard_schema():
    payload = {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation", "fields": [
                {"name": "createUser", "type": {"name": "User", "kind": "OBJECT"}},
                {"name": "deleteUser", "type": {"name": "Boolean"}},
            ]},
            "subscriptionType": None,
            "directives": [{"name": "include"}, {"name": "skip"}],
            "types": [
                {"name": "Query", "kind": "OBJECT", "fields": [
                    {"name": "user", "type": {"name": "User"}, "args": [{"name": "id"}]},
                    {"name": "me", "type": {"name": "User"}},
                    {"name": "legacyToken", "type": {"name": "String"},
                     "isDeprecated": True, "deprecationReason": "use tokens"},
                ]},
                {"name": "Mutation", "kind": "OBJECT", "fields": [
                    {"name": "createUser", "type": {"name": "User"}},
                    {"name": "deleteUser", "type": {"name": "Boolean"}},
                ]},
                {"name": "User", "kind": "OBJECT", "fields": [
                    {"name": "id", "type": {"name": "ID"}},
                ]},
                {"name": "Date", "kind": "SCALAR"},
                {"name": "__Type", "kind": "OBJECT", "fields": []},
            ],
        }
    }
    schema = extract_schema(payload)
    sdl = to_sdl(schema)
    # schema declaration maps the operation roots
    assert 'schema {' in sdl
    assert 'query: Query' in sdl
    assert 'mutation: Mutation' in sdl
    # every OBJECT type is emitted with its fields, args, and deprecated marker
    assert 'type Query {' in sdl
    assert 'user(id: String): User' in sdl
    assert 'me: User' in sdl
    assert 'createUser' in sdl and 'deleteUser' in sdl
    assert 'type User {' in sdl and 'id: ID' in sdl
    # deprecated field carries the directive
    assert '@deprecated(reason: "use tokens")' in sdl
    # scalar stub is present (values not introspected)
    assert 'SCALAR Date' in sdl
    # meta types are excluded
    assert '__Type' not in sdl
    # directives noted at the end
    assert '@include' in sdl and '@skip' in sdl


def test_to_node_attrs_includes_sdl_and_kind():
    payload = {"__schema": {"queryType": {"name": "Query"}, "mutationType": None,
                            "subscriptionType": None, "directives": [],
                            "types": [{"name": "Query", "kind": "OBJECT", "fields": [
                                {"name": "a", "type": {"name": "String"}}]}]}}
    schema = extract_schema(payload)
    attrs = schema.to_node_attrs()
    assert attrs["kind"] == "graphql-introspectable"
    assert "graphql_schema_sdl" in attrs
    assert 'type Query {' in attrs["graphql_schema_sdl"]


def test_export_graphql_schemas_writes_files(tmp_path):
    from openrecon.core.graph import AttackSurfaceGraph

    graph = AttackSurfaceGraph.seed("example.com", mode="active", version="t")
    node = Node.create(
        NodeType.API, "https://api.example.com/graphql",
        label="GraphQL at api.example.com/graphql",
        attrs={"kind": "graphql-introspectable", "graphql_schema_sdl": "type Query { a: String }\n"},
        provenance=Provenance(collector="graphql_verify"),
        tags={"api", "graphql"},
    )
    graph.add_node(node)
    written = graph.export_graphql_schemas(tmp_path)
    assert len(written) == 1
    content = written[0].read_text()
    assert "type Query" in content
    # A non-GraphQL api node without SDL is skipped.
    graph.add_node(Node.create(
        NodeType.API, "https://api.example.com/openapi.json",
        attrs={"kind": "openapi"}, provenance=Provenance(collector="api_exposure"),
    ))
    assert len(graph.export_graphql_schemas(tmp_path)) == 1


# ----------------------------------------------------------------- collector

class _Resp:
    def __init__(self, text: str, status: int = 200) -> None:
        self.text = text
        self.status_code = status


class _FakeHttp:
    """Returns canned GraphQL responses keyed by the query fragment."""

    def __init__(self, mode: str = "open") -> None:
        self.mode = mode
        self.calls: list[dict[str, Any]] = []

    async def request(self, method, url, *, params=None, headers=None, retries=0, json=None, **kw):
        query = (json or {}).get("query", "")
        self.calls.append({"url": url, "query": query})
        if self.mode == "open":
            if "__openrecon_introspection" in query:
                return _Resp(_SCHEMA_BODY)
            if "__openrecon_mutations" in query:
                return _Resp(_MUTATION_BODY)
            if "__openrecon_suggest" in query:
                return _Resp(
                    '{"errors":[{"message":"Cannot query field '
                    "'thisFieldDefinitelyDoesNotExist12345' on type 'Query'. "
                    "Did you mean 'user'?}]}"
                )
        if self.mode == "locked":
            # Reachable but hardened: empty data, no hints.
            if "__openrecon_suggest" in query:
                return _Resp('{"errors":[{"message":"syntax error"}]}', status=400)
            return _Resp('{"data":{}}')
        if self.mode == "notgraphql":
            return _Resp("<html><body>404 Not Found</body></html>", status=404)
        return None


_SCHEMA_BODY = '{"data":{"__schema":{"queryType":{"name":"Query"},' \
    '"mutationType":{"name":"Mutation","fields":[' \
    '{"name":"createUser","type":{"name":"User"}},' \
    '{"name":"deleteUser","type":{"name":"Boolean"}}]},' \
    '"subscriptionType":null,"directives":[{"name":"include"}],' \
    '"types":[' \
    '{"name":"Query","kind":"OBJECT","fields":[' \
    '{"name":"user","type":{"name":"User"},"args":[{"name":"id"}]}]},' \
    '{"name":"Mutation","kind":"OBJECT","fields":[' \
    '{"name":"createUser","type":{"name":"User"}}]},' \
    '{"name":"User","kind":"OBJECT","fields":[]}]}}}'

_MUTATION_BODY = '{"data":{"__schema":{"mutationType":{"name":"Mutation","fields":[' \
    '{"name":"createUser","type":{"name":"User"}}]}}}'


def _build_collector(http, target: str = "claude.ai"):
    cfg = Config(active=True)
    scope = Scope.implicit(target)
    ctx = CollectorContext(
        config=cfg, http=http, dns=None, scope=scope, progress=lambda *a, **k: None  # type: ignore[arg-type]
    )
    return GraphQLVerifier(ctx)


def _graph_with_graphql_node(target: str = "claude.ai", host: str = "staging.claude.ai"):
    graph = AttackSurfaceGraph.seed(target, mode="active", version="t")
    graph.add_node(
        Node.create(
            NodeType.SUBDOMAIN, host,
            provenance=Provenance(collector="dns"), tags={"web"},
        )
    )
    graph.add_node(
        Node.create(
            NodeType.API, f"https://{host}/graphql",
            attrs={"host": host, "url": f"https://{host}/graphql", "kind": "GraphQL"},
            provenance=Provenance(collector="api_exposure"),
            tags={"exposed", "api"},
        )
    )
    return graph


def test_collector_registered_in_attack_stage():
    assert "graphql_verify" in all_collectors()
    assert all_collectors()["graphql_verify"] is GraphQLVerifier
    assert GraphQLVerifier.stage == "attack"
    assert GraphQLVerifier.mode.value == "active"


def test_collector_verifies_open_endpoint():
    http = _FakeHttp("open")
    collector = _build_collector(http)
    graph = _graph_with_graphql_node()
    out = asyncio.run(collector.collect(graph))

    # Introspection (HIGH) + mutations (HIGH) + suggestion (MEDIUM) = 3 findings.
    assert len(out.findings) == 3
    cats = {f.category for f in out.findings}
    assert cats == {"graphql-exposure"}
    sev = sorted((f.severity for f in out.findings), key=lambda s: s.weight)
    assert sev[0] == Severity.MEDIUM
    assert sev.count(Severity.HIGH) == 2

    # Node created with the extracted schema folded in.
    assert len(out.nodes) == 1
    node = out.nodes[0]
    assert node.attrs["introspectable"] is True
    assert node.attrs["mutations_exposed"] is True
    assert node.attrs["suggestion_leak"] is True
    assert node.attrs["graphql_type_count"] >= 1
    assert node.attrs["graphql_mutation_count"] >= 1
    # Findings anchor to both the api node and the host.
    api_id = "api:https://staging.claude.ai/graphql"
    host_id = "subdomain:staging.claude.ai"
    for f in out.findings:
        assert api_id in f.node_ids and host_id in f.node_ids


def test_collector_locked_endpoint_no_leak_findings():
    http = _FakeHttp("locked")
    collector = _build_collector(http)
    graph = _graph_with_graphql_node()
    out = asyncio.run(collector.collect(graph))

    # Reachable but hardened: a node is recorded, no exposure findings.
    assert out.findings == []
    assert len(out.nodes) == 1
    assert out.nodes[0].attrs["introspectable"] is False
    assert out.nodes[0].attrs["mutations_exposed"] is False
    assert out.nodes[0].attrs["suggestion_leak"] is False


def test_collector_skips_non_graphql_host():
    http = _FakeHttp("notgraphql")
    collector = _build_collector(http)
    graph = _graph_with_graphql_node()
    out = asyncio.run(collector.collect(graph))
    assert out.nodes == []
    assert out.findings == []


def test_collector_reports_when_no_targets():
    http = _FakeHttp("open")
    collector = _build_collector(http)
    # Only the apex domain, no web hosts, no api nodes -> nothing to probe.
    graph = AttackSurfaceGraph.seed("claude.ai", mode="active", version="t")
    out = asyncio.run(collector.collect(graph))
    assert any("no discovered GraphQL endpoints" in e for e in out.errors)
    assert out.nodes == []
