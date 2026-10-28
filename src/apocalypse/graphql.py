from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit


class GraphQLError(ValueError):
    pass


INTROSPECTION_QUERY = """
query ApocalypseIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind
      name
      fields {
        name
        args { name type { kind name ofType { kind name ofType { kind name } } } }
      }
    }
  }
}
""".strip()


COMMON_GRAPHQL_PATHS = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/",
    "/api/v1/graphql",
)


def candidate_graphql_urls(target_url: str, discovered: list[str] | None = None) -> list[str]:
    parsed = urlsplit(target_url)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    urls = [urljoin(origin + "/", path.lstrip("/")) for path in COMMON_GRAPHQL_PATHS]
    for item in discovered or []:
        path = urlsplit(item).path.lower()
        if "graphql" in path and "graphiql" not in path:
            urls.append(item.split("?", 1)[0])
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(urls))


def _unwrap_type(node: dict[str, Any] | None) -> str:
    current = node
    while isinstance(current, dict):
        if current.get("name"):
            return str(current["name"])
        current = current.get("ofType")
    return "String"


def _sample_arg_value(type_name: str) -> Any:
    lowered = type_name.lower()
    if lowered in {"int", "integer"}:
        return 1
    if lowered in {"float", "decimal"}:
        return 1.0
    if lowered in {"boolean", "bool"}:
        return False
    if lowered == "id":
        return "1"
    return "apocalypse"


def parse_introspection(document: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    """Return sample read-only GraphQL operation strings and schema summary."""
    if not isinstance(document, dict):
        raise GraphQLError("GraphQL response must be a JSON object")
    if document.get("errors") and not document.get("data"):
        raise GraphQLError("GraphQL introspection returned errors without data")
    data = document.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("__schema"), dict):
        raise GraphQLError("response is not a GraphQL introspection payload")
    schema = data["__schema"]
    query_type = (schema.get("queryType") or {}).get("name")
    if not query_type:
        raise GraphQLError("schema has no query type")
    types = {item["name"]: item for item in schema.get("types") or [] if isinstance(item, dict) and item.get("name")}
    query = types.get(query_type)
    if not isinstance(query, dict):
        raise GraphQLError("query type definition missing")

    operations: list[str] = []
    field_names: list[str] = []
    for field in query.get("fields") or []:
        if not isinstance(field, dict) or not field.get("name"):
            continue
        name = str(field["name"])
        if name.startswith("__"):
            continue
        field_names.append(name)
        args = []
        for arg in field.get("args") or []:
            if not isinstance(arg, dict) or not arg.get("name"):
                continue
            type_name = _unwrap_type(arg.get("type") if isinstance(arg.get("type"), dict) else None)
            sample = _sample_arg_value(type_name)
            rendered = json_literal(sample)
            args.append(f"{arg['name']}: {rendered}")
        if args:
            operations.append(f"query {{ {name}({', '.join(args)}) {{ __typename }} }}")
        else:
            operations.append(f"query {{ {name} {{ __typename }} }}")
        if len(operations) >= 40:
            break

    summary = {
        "query_type": query_type,
        "mutation_type": (schema.get("mutationType") or {}).get("name"),
        "field_count": len(field_names),
        "fields": field_names[:40],
        "introspection_enabled": True,
    }
    return operations, summary


def json_literal(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def graphql_arg_probe_points(document: dict[str, Any], endpoint: str, *, limit: int = 30) -> list[dict[str, Any]]:
    """Build per-argument GraphQL query templates for active probing (read-only query type)."""
    operations, _ = parse_introspection(document)
    points: list[dict[str, Any]] = []
    data = document.get("data") if isinstance(document, dict) else None
    schema = (data or {}).get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        return points
    query_type = (schema.get("queryType") or {}).get("name")
    types = {item["name"]: item for item in schema.get("types") or [] if isinstance(item, dict) and item.get("name")}
    query = types.get(query_type) if query_type else None
    if not isinstance(query, dict):
        return points
    for field in query.get("fields") or []:
        if not isinstance(field, dict) or not field.get("name") or str(field["name"]).startswith("__"):
            continue
        name = str(field["name"])
        args = [arg for arg in (field.get("args") or []) if isinstance(arg, dict) and arg.get("name")]
        if not args:
            continue
        for arg in args:
            arg_name = str(arg["name"])
            rendered_args = []
            for item in args:
                type_name = _unwrap_type(item.get("type") if isinstance(item.get("type"), dict) else None)
                sample = _sample_arg_value(type_name)
                if item["name"] == arg_name:
                    rendered_args.append(f'{item["name"]}: "{{{{PARAM}}}}"')
                else:
                    rendered_args.append(f"{item['name']}: {json_literal(sample)}")
            query_text = f"query {{ {name}({', '.join(rendered_args)}) {{ __typename }} }}"
            points.append({
                "method": "POST",
                "url": endpoint,
                "parameter": arg_name,
                "source": "graphql",
                "location": "graphql",
                "graphql_query": query_text,
                "field": name,
            })
            if len(points) >= limit:
                return points
    # Fallback: derive from sample operations list length for coverage signal.
    _ = operations
    return points
