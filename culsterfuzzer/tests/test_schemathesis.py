# tests/test_simple_fuzz.py
"""
Simple OpenAPI-based fuzzer (no schemathesis). Works with your openapi.yaml placed
in the project root (tests/ parent). Uses requests to call endpoints and injects
Authorization header from secrets/API_TOKEN or env API_TOKEN.

Safety: By default this script SKIPS state-changing endpoints (create/upload/delete).
Enable them only in an isolated dev environment by exporting ALLOW_MUTATE=1.
"""
import os
import json
from pathlib import Path
import pytest
import requests
import yaml

ROOT = Path(__file__).parent.parent
SCHEMA_PATH = ROOT / "openapi.yaml"
SECRETS_PATH = ROOT / "secrets/API_TOKEN"

# Load token (env first, then secrets file)
API_TOKEN = os.getenv("API_TOKEN")
if not API_TOKEN and SECRETS_PATH.exists():
    API_TOKEN = SECRETS_PATH.read_text(encoding="utf-8").strip()

ALLOW_MUTATE = os.getenv("ALLOW_MUTATE", "0") == "1"
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")  # change if needed

STATEFUL_PATHS = {
    "/api/create-user",
    "/api/upload-document",
    "/api/create-watermark",
    "/api/delete-document",
    "/api/delete-document/{document_id}",
}

# Helper to produce a minimal payload from a JSON schema object
def make_example_from_schema(schema_obj):
    if not schema_obj:
        return {}
    t = schema_obj.get("type")
    if not t:
        # object by default
        t = "object"
    if t == "object":
        props = schema_obj.get("properties", {})
        required = schema_obj.get("required", list(props.keys()))
        out = {}
        for name in required:
            prop = props.get(name, {})
            out[name] = make_example_from_schema(prop)
        # if no required, try some properties
        if not out and props:
            # pick first prop
            k, v = next(iter(props.items()))
            out[k] = make_example_from_schema(v)
        return out
    if t == "array":
        items = schema_obj.get("items", {"type": "string"})
        return [make_example_from_schema(items)]
    if t == "integer" or t == "number":
        return 1
    if t == "boolean":
        return True
    # string and formats
    fmt = schema_obj.get("format", "")
    if fmt == "email":
        return "test@example.com"
    if fmt == "date-time" or fmt == "date":
        return "2025-01-01T00:00:00Z"
    if schema_obj.get("enum"):
        return schema_obj["enum"][0]
    # fallback
    return "fuzz"

def build_request_for_operation(base_url, path, method, op_obj):
    # path may contain {param} placeholders - schematically keep them as 1
    # Replace path template params with 1 (or simple example)
    real_path = path
    # Fill path params if any
    # naively replace {x} with 1
    import re
    real_path = re.sub(r"\{[^/}]+\}", "1", real_path)
    url = base_url.rstrip("/") + real_path

    headers = {}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    # default content-type if body
    body = None
    if "requestBody" in op_obj:
        # look for application/json schema
        rb = op_obj["requestBody"]
        content = rb.get("content", {})
        if "application/json" in content:
            schema_obj = content["application/json"].get("schema", {})
            body = make_example_from_schema(schema_obj)
            headers["Content-Type"] = "application/json"
        elif "multipart/form-data" in content or "application/octet-stream" in content:
            # skip multipart/file by default unless ALLOW_MUTATE
            if ALLOW_MUTATE:
                body = {"name": "poc", "file": ("poc.pdf", b"%PDF-1.4\n%...", "application/pdf")}
            else:
                body = None
        else:
            # fallback to form or raw
            body = {}
    return url, method.upper(), headers, body

def is_stateful(path, method, op_obj):
    # Basic heuristic: path in STATEFUL_PATHS OR operation has "security" AND method is POST/PUT/DELETE
    normalized = path
    if any(p.rstrip("/") == normalized.rstrip("/") or p in normalized for p in STATEFUL_PATHS):
        return True
    if method.lower() in ("post", "put", "delete", "patch"):
        # check description or tags maybe indicate stateful; conservative: treat as stateful only for known endpoints
        if path.startswith("/api/create") or path.startswith("/api/upload") or path.startswith("/api/delete"):
            return True
    return False

# Load OpenAPI
with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
    spec = yaml.safe_load(f)

paths = spec.get("paths", {})

# Dynamically generate tests for each operation
test_cases = []
for path, path_item in paths.items():
    for method, op_obj in (path_item.items() if isinstance(path_item, dict) else []):
        # skip non-HTTP keys
        if method.lower() not in ("get", "post", "put", "delete", "patch", "head", "options"):
            continue
        stateful = is_stateful(path, method, op_obj)
        if stateful and not ALLOW_MUTATE:
            # skip but record a dummy test that asserts skipped
            test_cases.append((path, method, op_obj, True, None))
            continue
        url, mtd, headers, body = build_request_for_operation(BASE_URL, path, method, op_obj)
        test_cases.append((path, method, op_obj, False, (url, mtd, headers, body)))

@pytest.mark.parametrize("path,method,op,stateful,req", test_cases)
def test_openapi_endpoint(path, method, op, stateful, req):
    """
    For each endpoint in openapi.yaml, send a conservative request and assert we get a valid HTTP response.
    """
    if stateful:
        pytest.skip(f"stateful endpoint {method.upper()} {path} skipped (ALLOW_MUTATE not set)")
    url, mtd, headers, body = req
    # perform request
    try:
        if body is None:
            resp = requests.request(mtd, url, headers=headers, timeout=10)
        else:
            if headers.get("Content-Type") == "application/json":
                resp = requests.request(mtd, url, headers=headers, json=body, timeout=10)
            elif isinstance(body, dict) and any(isinstance(v, tuple) for v in body.values()):
                # treat as multipart with files; body has tuples (filename, bytes, content-type)
                files = {}
                data = {}
                for k, v in body.items():
                    if isinstance(v, tuple):
                        files[k] = v  # (filename, content, mime)
                    else:
                        data[k] = v
                resp = requests.request(mtd, url, headers=headers, files=files, data=data, timeout=20)
            else:
                resp = requests.request(mtd, url, headers=headers, data=body, timeout=10)
    except requests.RequestException as e:
        pytest.fail(f"Request failed for {mtd} {url}: {e}")

    # Basic acceptance: server should return a HTTP status code (no exception), and not crash with 5xx ideally
    # You can change acceptance criteria as needed
    assert 100 <= resp.status_code <= 599, f"Invalid status code: {resp.status_code}"
    # fail if server returns 500-599 (server error) - indicates potential bug
    assert not (500 <= resp.status_code <= 599), f"Server error {resp.status_code} for {mtd} {url}: {resp.text[:200]}"

    # print summary for operator
    payload_preview = ""
    if body is not None:
        try:
            payload_preview = json.dumps(body, ensure_ascii=False)[:200]
        except Exception:
            payload_preview = str(body)[:200]
    print(f"{resp.status_code}\t{mtd}\t{url}\t{payload_preview}")
