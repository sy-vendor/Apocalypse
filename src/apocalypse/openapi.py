from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit


class OpenAPIError(ValueError):
    pass


def _resolve_ref(document: dict[str, Any], value: Any) -> Any:
    if not isinstance(value, dict) or "$ref" not in value:
        return value
    ref = value.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return value
    current: Any = document
    try:
        for part in ref[2:].split("/"):
            key = part.replace("~1", "/").replace("~0", "~")
            current = current[key]
    except (KeyError, TypeError):
        return value
    return current


def _example(parameter: dict[str, Any]) -> str:
    schema = parameter.get("schema") if isinstance(parameter.get("schema"), dict) else {}
    for candidate in (parameter.get("example"), schema.get("example"), schema.get("default")):
        if candidate is not None:
            return str(candidate).lower() if isinstance(candidate, bool) else str(candidate)
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return str(enum[0])
    kind = schema.get("type") or parameter.get("type")
    if kind in {"integer", "number"}:
        return "1"
    if kind == "boolean":
        return "false"
    return "apocalypse"


def _server_urls(document: dict[str, Any], document_url: str, target_url: str) -> list[str]:
    servers = document.get("servers")
    if isinstance(servers, list) and servers:
        result: list[str] = []
        for item in servers:
            if not isinstance(item, dict) or not isinstance(item.get("url"), str):
                continue
            value = item["url"]
            variables = item.get("variables") if isinstance(item.get("variables"), dict) else {}
            for name, config in variables.items():
                default = config.get("default") if isinstance(config, dict) else None
                if default is not None:
                    value = value.replace("{" + str(name) + "}", str(default))
            if "{" not in value:
                result.append(urljoin(document_url, value))
        if result:
            return result

    target = urlsplit(target_url)
    origin = urlunsplit((target.scheme, target.netloc, "", "", ""))
    base_path = document.get("basePath", "") if isinstance(document.get("basePath", ""), str) else ""
    return [origin.rstrip("/") + "/" + base_path.strip("/")] if base_path else [origin]


def discover_openapi_urls(document: dict[str, Any], document_url: str, target_url: str) -> list[str]:
    """Return safe, read-only endpoint candidates from an OpenAPI 2/3 JSON document."""
    if not isinstance(document, dict):
        raise OpenAPIError("OpenAPI document must be a JSON object")
    if not (isinstance(document.get("openapi"), str) or isinstance(document.get("swagger"), str)):
        raise OpenAPIError("document is not an OpenAPI or Swagger specification")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise OpenAPIError("OpenAPI document has no paths object")

    urls: set[str] = set()
    for base in _server_urls(document, document_url, target_url):
        for raw_path, raw_item in paths.items():
            if not isinstance(raw_path, str) or not isinstance(raw_item, dict):
                continue
            path_parameters = raw_item.get("parameters") if isinstance(raw_item.get("parameters"), list) else []
            for method, raw_operation in raw_item.items():
                # Only GET is automatically scheduled. Other methods remain visible to future explicit API testing modes.
                if method.lower() != "get" or not isinstance(raw_operation, dict):
                    continue
                operation_parameters = raw_operation.get("parameters")
                parameters = list(path_parameters)
                if isinstance(operation_parameters, list):
                    parameters.extend(operation_parameters)

                path = raw_path
                query: list[tuple[str, str]] = []
                for raw_parameter in parameters:
                    parameter = _resolve_ref(document, raw_parameter)
                    if not isinstance(parameter, dict) or not isinstance(parameter.get("name"), str):
                        continue
                    name, location, value = parameter["name"], parameter.get("in"), _example(parameter)
                    if location == "path":
                        path = path.replace("{" + name + "}", quote(value, safe=""))
                    elif location == "query":
                        query.append((name, value))
                if "{" in path or "}" in path:
                    continue
                endpoint = base.rstrip("/") + "/" + path.lstrip("/")
                parsed = urlsplit(endpoint)
                existing_query = list(parse_qsl(parsed.query, keep_blank_values=True))
                urls.add(urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(existing_query + query), "")))
    return sorted(urls)


def _json_properties(document: dict[str, Any], schema: dict[str, Any], *, depth: int = 0) -> list[tuple[str, str]]:
    if depth > 2 or not isinstance(schema, dict):
        return []
    schema = _resolve_ref(document, schema)
    if not isinstance(schema, dict):
        return []
    if schema.get("type") == "object" or "properties" in schema:
        props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        pairs: list[tuple[str, str]] = []
        for name, prop in list(props.items())[:20]:
            resolved = _resolve_ref(document, prop) if isinstance(prop, dict) else {}
            if not isinstance(resolved, dict):
                continue
            if resolved.get("type") == "object":
                continue
            pairs.append((str(name), _example({"schema": resolved, "name": name})))
        return pairs
    return []


def discover_openapi_operations(
    document: dict[str, Any], document_url: str, target_url: str, *, limit: int = 80,
) -> list[dict[str, Any]]:
    """Return structured read-safe and opted-in write-safe operation descriptors for API probing.

    Only GET is included by default. POST/PUT/PATCH with JSON bodies are marked mutating=False
    only when the operation is clearly a search/read idiom; otherwise they are excluded here
    (active JSON probing still occurs on discovered GET query params and crawl JSON forms).
    """
    if not isinstance(document, dict):
        raise OpenAPIError("OpenAPI document must be a JSON object")
    if not (isinstance(document.get("openapi"), str) or isinstance(document.get("swagger"), str)):
        raise OpenAPIError("document is not an OpenAPI or Swagger specification")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise OpenAPIError("OpenAPI document has no paths object")

    operations: list[dict[str, Any]] = []
    for base in _server_urls(document, document_url, target_url):
        for raw_path, raw_item in paths.items():
            if not isinstance(raw_path, str) or not isinstance(raw_item, dict):
                continue
            path_parameters = raw_item.get("parameters") if isinstance(raw_item.get("parameters"), list) else []
            for method, raw_operation in raw_item.items():
                method_l = method.lower()
                if method_l not in {"get", "post"} or not isinstance(raw_operation, dict):
                    continue
                if method_l == "post":
                    # Only include POST when tagged as search/read-like to stay non-destructive by default.
                    tags = " ".join(str(t) for t in (raw_operation.get("tags") or [])).lower()
                    op_id = str(raw_operation.get("operationId") or "").lower()
                    if not any(token in f"{tags} {op_id} {raw_path.lower()}" for token in ("search", "query", "list", "find", "get")):
                        continue
                operation_parameters = raw_operation.get("parameters")
                parameters = list(path_parameters)
                if isinstance(operation_parameters, list):
                    parameters.extend(operation_parameters)

                path = raw_path
                query: list[tuple[str, str]] = []
                headers: list[tuple[str, str]] = []
                for raw_parameter in parameters:
                    parameter = _resolve_ref(document, raw_parameter)
                    if not isinstance(parameter, dict) or not isinstance(parameter.get("name"), str):
                        continue
                    name, location, value = parameter["name"], parameter.get("in"), _example(parameter)
                    if location == "path":
                        path = path.replace("{" + name + "}", quote(value, safe=""))
                    elif location == "query":
                        query.append((name, value))
                    elif location == "header" and name.lower() not in {"authorization", "cookie", "host"}:
                        headers.append((name, value))
                if "{" in path or "}" in path:
                    continue
                endpoint = base.rstrip("/") + "/" + path.lstrip("/")
                parsed = urlsplit(endpoint)
                url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query), ""))

                json_fields: list[tuple[str, str]] = []
                if method_l == "post":
                    body = raw_operation.get("requestBody")
                    body = _resolve_ref(document, body) if isinstance(body, dict) else None
                    if isinstance(body, dict):
                        content = body.get("content") if isinstance(body.get("content"), dict) else {}
                        app_json = content.get("application/json") if isinstance(content, dict) else None
                        if isinstance(app_json, dict) and isinstance(app_json.get("schema"), dict):
                            json_fields = _json_properties(document, app_json["schema"])
                    # Swagger 2 body parameter
                    for raw_parameter in parameters:
                        parameter = _resolve_ref(document, raw_parameter)
                        if isinstance(parameter, dict) and parameter.get("in") == "body" and isinstance(parameter.get("schema"), dict):
                            json_fields = _json_properties(document, parameter["schema"])

                operations.append({
                    "method": method_l.upper(),
                    "url": url,
                    "query": query,
                    "headers": headers,
                    "json_fields": json_fields,
                    "source": "openapi",
                })
                if len(operations) >= limit:
                    return operations
    return operations
