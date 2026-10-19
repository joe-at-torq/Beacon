"""Convert the v1 OpenAPI spec into a Postman Collection (v2.1)."""

import json
import uuid
from typing import Any

SCHEMA_URL = "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
METHODS = ("get", "post", "put", "patch", "delete")


def _resolve(schema: dict, components: dict) -> dict:
    while isinstance(schema, dict) and "$ref" in schema:
        schema = components.get(schema["$ref"].rsplit("/", 1)[-1], {})
    return schema or {}


def example_for(schema: dict, components: dict, depth: int = 0) -> Any:
    """Best-effort example value for a JSON schema (prefers declared examples/defaults)."""
    schema = _resolve(schema, components)
    if depth > 6:
        return None
    if schema.get("examples"):
        return schema["examples"][0]
    if "example" in schema:
        return schema["example"]
    if "default" in schema and schema["default"] is not None:
        return schema["default"]
    for key in ("anyOf", "oneOf", "allOf"):
        if key in schema:
            options = [s for s in schema[key] if _resolve(s, components).get("type") != "null"]
            return example_for(options[0], components, depth + 1) if options else None
    if schema.get("enum"):
        return schema["enum"][0]
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        return {name: example_for(prop, components, depth + 1) for name, prop in schema.get("properties", {}).items()}
    if kind == "array":
        item = example_for(schema.get("items", {}), components, depth + 1)
        return [] if item is None else [item]
    return {"string": "", "integer": 0, "number": 0, "boolean": False}.get(kind)


def to_collection(spec: dict, base_url: str) -> dict:
    components = spec.get("components", {}).get("schemas", {})
    folders: dict[str, list] = {t["name"]: [] for t in spec.get("tags", [])}
    for path, ops in spec.get("paths", {}).items():
        for method in METHODS:
            op = ops.get(method)
            if not op:
                continue
            params = op.get("parameters", [])
            path_vars = [p for p in params if p.get("in") == "path"]
            query = [p for p in params if p.get("in") == "query"]
            segments = [f":{s[1:-1]}" if s.startswith("{") else s for s in path.strip("/").split("/")]
            raw_path = "/".join(segments)
            query_items = [
                {
                    "key": q["name"],
                    "value": str(example_for(q.get("schema", {}), components) or ""),
                    "description": q.get("description", ""),
                    "disabled": not q.get("required", False),
                }
                for q in query
            ]
            url = {
                "raw": "{{baseUrl}}/" + raw_path,
                "host": ["{{baseUrl}}"],
                "path": segments,
                "variable": [{"key": v["name"], "value": "", "description": v.get("description", "")} for v in path_vars],
            }
            if query_items:
                url["query"] = query_items
            request: dict[str, Any] = {
                "method": method.upper(),
                "header": [{"key": "Accept", "value": "application/json"}],
                "url": url,
                "description": op.get("description", ""),
            }
            body_schema = op.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema")
            if body_schema:
                request["header"].append({"key": "Content-Type", "value": "application/json"})
                request["body"] = {
                    "mode": "raw",
                    "raw": json.dumps(example_for(body_schema, components) or {}, indent=2),
                    "options": {"raw": {"language": "json"}},
                }
            item = {"name": op.get("summary") or op.get("operationId") or f"{method.upper()} {path}", "request": request}
            tag = (op.get("tags") or ["Other"])[0]
            folders.setdefault(tag, []).append(item)

    return {
        "info": {
            "_postman_id": str(uuid.uuid5(uuid.NAMESPACE_URL, base_url)),
            "name": spec.get("info", {}).get("title", "Beacon API"),
            "description": spec.get("info", {}).get("description", ""),
            "schema": SCHEMA_URL,
        },
        "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{apiKey}}", "type": "string"}]},
        "variable": [
            {"key": "baseUrl", "value": base_url, "type": "string"},
            {"key": "apiKey", "value": "", "type": "string", "description": "Create a key in Beacon → Settings → API"},
        ],
        "item": [{"name": name, "item": items} for name, items in folders.items() if items],
    }
