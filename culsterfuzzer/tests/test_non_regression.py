# tests/test_non_regression.py
"""
Non-regression test for OpenAPI schema.

- Skips state-changing endpoints (POST/PUT/DELETE to create/upload/delete) by default.
- Enable them with ALLOW_MUTATE=1 in your environment for full coverage.
"""

import os
import json
from pathlib import Path
import pytest
import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "openapi.yaml"
SECRETS_PATH = ROOT / "secrets/API_TOKEN"

# Load API token from environment first, fallback to file
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

def make_example_from_schema(schema_obj):
    """Generate minimal payload from OpenAPI schema object."""
    if not schema_obj:
        return {}
    t = schema_obj.get("type", "object")
    if t == "object":
        props = schema_obj.get("properties", {})
        required = schema_obj.get("required", list(props.keys()))
        return {name: make_example_from_schema(props.get(name, {})) for name in required}
    if t == "array":
        return [make_example_from_schema(schema_obj.get("items", {}))]
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return True
    if "enum" in schema_obj:
        return schema_obj["enum"][0]
    fmt = schema_obj.get("format", "")
    if fmt == "email":
        return "test@example.com"
    if fmt in ("date-time", "date"):
        return "2025-01-01T00:00:00Z"
    return "fuzz"

def build_request(base_url, path, method, op_obj):
    """Construct URL, headers, and body for a request."""
    import re
    real_path = re.sub(r"\{[^/}]+\}", "1", path)
    url = base_url.rstrip("/") + real_path

    headers = {"Authorization": f"Bearer {API_TOKEN}"} if API_TOKEN else {}
    body = None

    if "requestBody" in op_obj:
        content = op_obj["requestBody"].get("content", {})
        if "application/json" in content:
            schema_obj = content["application/json"].get("schema", {})
            body = make_example_from_schema(schema_obj)
            headers["Content-Type"] = "application/json"
        elif ALLOW_MUTATE and ("multipart/form-data" in content or "application/octet-stream" in content):
            body = {"name": "poc", "file": ("poc.pdf", b"%PDF-1.4\n%...", "application/pdf")}

    return url, method.upper(), headers, body

def is_stateful(path, method):
    """Determine if endpoint is state-changing."""
    normalized = path.rstrip("/")
    if any(p.rstrip("/") == normalized or p in normalized for p in STATEFUL_PATHS):
        return True
    return method.lower() in ("post", "put", "delete", "patch") and path.startswith("/api/")

# Load OpenAPI schema
with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
    spec = yaml.safe_load(f)

paths = spec.get("paths", {})

# Generate test cases
test_cases = []
for path, path_item in paths.items():
    for method, op_obj in (path_item.items() if isinstance(path_item, dict) else []):
        if method.lower() not in ("get", "post", "put", "delete", "patch"):
            continue
        stateful = is_stateful(path, method)
        if stateful and not ALLOW_MUTATE:
            test_cases.append((path, method, op_obj, True, None))
            continue
        req = build_request(BASE_URL, path, method, op_obj)
        test_cases.append((path, method, op_obj, False, req))

@pytest.mark.parametrize("path,method,op,stateful,req", test_cases)
def test_openapi_endpoint(path, method, op, stateful, req):
    """Send request and validate basic response for each endpoint."""
    if stateful:
        pytest.skip(f"Stateful endpoint {method} {path} skipped (ALLOW_MUTATE not set)")
    url, mtd, headers, body = req
    try:
        if body is None:
            resp = requests.request(mtd, url, headers=headers, timeout=10)
        elif headers.get("Content-Type") == "application/json":
            resp = requests.request(mtd, url, headers=headers, json=body, timeout=10)
        elif isinstance(body, dict) and any(isinstance(v, tuple) for v in body.values()):
            files, data = {}, {}
            for k, v in body.items():
                if isinstance(v, tuple):
                    files[k] = v
                else:
                    data[k] = v
            resp = requests.request(mtd, url, headers=headers, files=files, data=data, timeout=20)
        else:
            resp = requests.request(mtd, url, headers=headers, data=body, timeout=10)
    except requests.RequestException as e:
        pytest.fail(f"Request failed for {mtd} {url}: {e}")

    assert 100 <= resp.status_code <= 599
    assert not (500 <= resp.status_code <= 599), f"Server error {resp.status_code} for {mtd} {url}: {resp.text[:200]}"

    # print summary
    payload_preview = json.dumps(body, ensure_ascii=False)[:200] if body else ""
    print(f"{resp.status_code}\t{mtd}\t{url}\t{payload_preview}")
