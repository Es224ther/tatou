# tests/test_fuzz_payloads.py
"""
Fuzz test using an embedded seed corpus.
- Reads openapi.yaml from project root (tests/ parent).
- Uses embedded seeds if json_payloads.txt not present.
- Mutates string fields in JSON request bodies and sends requests.
- Records "interesting" responses (5xx or unexpected success) to reports/logs/fuzz_log.txt.
- Skips stateful endpoints unless ALLOW_MUTATE=1.
- Injects Authorization: Bearer <API_TOKEN> from env or secrets/API_TOKEN file.
"""
import os
import random
import json
import time
from pathlib import Path
import requests
import pytest
import yaml

ROOT = Path(__file__).parent.parent
SCHEMA_PATH = ROOT / "openapi.yaml"
SECRETS_PATH = ROOT / "secrets/API_TOKEN"
SEED_FILE = ROOT / "json_payloads.txt"
OUT_LOG = ROOT / "reports" / "logs" / "fuzz_log.txt"
OUT_LOG.parent.mkdir(parents=True, exist_ok=True)

# Config
API_TOKEN = os.getenv("API_TOKEN")
if not API_TOKEN and SECRETS_PATH.exists():
    API_TOKEN = SECRETS_PATH.read_text(encoding="utf-8").strip()

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
ALLOW_MUTATE = os.getenv("ALLOW_MUTATE", "0") == "1"
FUZZ_ITER = int(os.getenv("FUZZ_ITER", "50"))  # number of fuzz attempts per endpoint
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "10.0"))
DELAY = float(os.getenv("FUZZ_DELAY", "0.05"))  # delay between requests

# stateful endpoints to skip by default
STATEFUL_PREFIXES = ("/api/create", "/api/upload", "/api/delete")
STATEFUL_EXACT = {"/api/create-user", "/api/upload-document", "/api/create-watermark", "/api/delete-document"}

# Embedded fallback seeds (used when json_payloads.txt absent)
EMBEDDED_SEEDS = [
    # basic valid-ish emails
    "test@example.com",
    "user+1@example.com",
    "admin@example.com",
    # malformed / edge cases
    "test@@example.com",
    "\"test@example.comtest@example.com\"",
    "test@ex\"ample.com",
    "test@exam\nple.com",
    # injections / payloads
    "user@' OR '1'='1",
    "user@admin'--",
    "user@<script>alert(1)</script>.com",
    "user@../../../../etc/passwd",
    # international / unicode / emoji
    "test@例子.公司",
    "test@☃.net",
    "空",
    "null",
    "None",
    "🧨🧨🧨",
    # IP / localhost / special
    "test@localhost",
    "test@127.0.0.1",
    "12345",
    "<xml>",
    "user@%s.com",
    "user@{{7*7}}.com",
]

# load seeds (file overrides embedded)
def load_seeds(p: Path):
    if not p.exists():
        return EMBEDDED_SEEDS[:]
    lines = p.read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]

SEEDS = load_seeds(SEED_FILE)

# helper: mutation primitives
def mutate_string(s: str):
    """Apply random simple mutations to a seed string."""
    ops = [
        lambda x: x,
        lambda x: x + x,
        lambda x: x * 5,
        lambda x: " " + x + " ",
        lambda x: x + "' OR '1'='1",
        lambda x: "<script>" + x + "</script>",
        lambda x: x.replace("@", "%40"),
        lambda x: x + "\n",
        lambda x: "🔥" + x,
        lambda x: x[::-1],
        lambda x: x[:10],
    ]
    op = random.choice(ops)
    return op(s)

def mutate_value(value):
    """Mutate a JSON value: if string, mutate; if array/object, recurse."""
    if isinstance(value, str):
        seed = random.choice(SEEDS) if SEEDS else "fuzz"
        return mutate_string(seed)
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + random.randint(-1000, 1000)
    if isinstance(value, float):
        return value * random.uniform(0.1, 10)
    if isinstance(value, list):
        if not value:
            return [mutate_value("fuzz")]
        return [mutate_value(random.choice(value))]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out[k] = mutate_value(v)
        return out
    return "fuzz"

def make_example_from_schema(schema_obj):
    """Conservative example generator for simple JSON schema objects."""
    if not schema_obj:
        return {}
    t = schema_obj.get("type", "object")
    if t == "object":
        props = schema_obj.get("properties", {})
        required = schema_obj.get("required", list(props.keys()))
        out = {}
        for name in required:
            prop = props.get(name, {"type": "string"})
            out[name] = make_example_from_schema(prop)
        if not out and props:
            k, v = next(iter(props.items()))
            out[k] = make_example_from_schema(v)
        return out
    if t == "array":
        items = schema_obj.get("items", {"type": "string"})
        return [make_example_from_schema(items)]
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return True
    # string fallback
    fmt = schema_obj.get("format", "")
    if fmt == "email":
        return "test@example.com"
    if schema_obj.get("enum"):
        return schema_obj["enum"][0]
    return "example"

def build_request_for_operation(base_url, path, method, op_obj):
    # naive replacement for path parameters: {id} -> 1
    import re
    real_path = re.sub(r"\{[^/}]+\}", "1", path)
    url = base_url.rstrip("/") + real_path

    headers = {}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"

    body = None
    if "requestBody" in op_obj:
        content = op_obj["requestBody"].get("content", {})
        if "application/json" in content:
            schema_obj = content["application/json"].get("schema", {})
            body = make_example_from_schema(schema_obj)
            headers["Content-Type"] = "application/json"
        elif "multipart/form-data" in content or "application/octet-stream" in content:
            # skip file uploads unless ALLOW_MUTATE
            if ALLOW_MUTATE:
                body = {"name": "poc.pdf", "file": ("poc.pdf", b"%PDF-1.4\n%...", "application/pdf")}
            else:
                body = None
        else:
            body = {}

    return url, method.upper(), headers, body

def is_stateful(path):
    if path in STATEFUL_EXACT:
        return True
    if any(path.startswith(p) for p in STATEFUL_PREFIXES):
        return True
    return False

# Load OpenAPI spec
with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
    spec = yaml.safe_load(f)

paths = spec.get("paths", {})

# prepare output log header if not exists
if not OUT_LOG.exists():
    with OUT_LOG.open("w", encoding="utf-8") as f:
        f.write("ts\titer\tpath\tmethod\tstatus\tlen_resp\tinteresting\treason\tdetails\n")

def log_interesting(ts, it, path, method, status, resp_text, reason):
    details = resp_text.replace("\n", "\\n")[:800].replace("\t", " ")
    line = f"{ts}\t{it}\t{path}\t{method}\t{status}\t{len(resp_text)}\t1\t{reason}\t{details}\n"
    with OUT_LOG.open("a", encoding="utf-8") as f:
        f.write(line)

# Build test cases: for each path+method, run FUZZ_ITER attempts (unless stateful and not allowed)
test_cases = []
for path, path_item in paths.items():
    if not isinstance(path_item, dict):
        continue
    for method, op_obj in path_item.items():
        if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
            continue
        stateful = is_stateful(path)
        if stateful and not ALLOW_MUTATE:
            continue
        url, mtd, headers, example_body = build_request_for_operation(BASE_URL, path, method, op_obj)
        test_cases.append((path, method, op_obj, url, mtd, headers, example_body, stateful))

@pytest.mark.parametrize("path,method,op,url,mtd,headers,body,stateful", test_cases)
def test_fuzz_endpoint(path, method, op, url, mtd, headers, body, stateful):
    # For each endpoint run FUZZ_ITER mutated requests
    for i in range(FUZZ_ITER):
        ts = int(time.time())
        # construct mutated body
        req_headers = dict(headers) if headers else {}
        req_body = None
        if body is not None:
            try:
                jb = json.loads(json.dumps(body))
            except Exception:
                jb = body
            def recurse_mut(v):
                if isinstance(v, dict):
                    return {k: recurse_mut(vv) for k, vv in v.items()}
                if isinstance(v, list):
                    return [recurse_mut(x) for x in v]
                return mutate_value(v)
            mutated = recurse_mut(jb)
            # occasional raw seed injection into top-level string fields
            if isinstance(mutated, dict) and mutated:
                for _ in range(random.randint(0, 2)):
                    k = random.choice(list(mutated.keys()))
                    mutated[k] = mutate_value(mutated[k])
            req_body = mutated
        else:
            req_body = None

        # send request
        try:
            if req_body is None:
                resp = requests.request(mtd, url, headers=req_headers, timeout=REQUEST_TIMEOUT)
            else:
                if req_headers.get("Content-Type") == "application/json":
                    resp = requests.request(mtd, url, headers=req_headers, json=req_body, timeout=REQUEST_TIMEOUT)
                else:
                    resp = requests.request(mtd, url, headers=req_headers, data=req_body, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as e:
            # network errors are considered interesting
            log_interesting(ts, i, path, mtd, "ERR", str(e), "request_exception")
            pytest.fail(f"Request exception for {mtd} {url}: {e}")
            return

        # check response
        status = resp.status_code
        text = resp.text or ""
        # interesting criteria:
        is_interesting = False
        reason = None
        if 500 <= status <= 599:
            is_interesting = True
            reason = "server_error"
        if path == "/api/login" and status == 200:
            is_interesting = True
            reason = "login_succeeded_on_fuzz"
        if len(text) > 2000:
            is_interesting = True
            reason = "large_response_body"

        if is_interesting:
            log_interesting(ts, i, path, mtd, status, text, reason)

        # basic assertion: fail on 5xx
        assert not (500 <= status <= 599), f"Server error {status} for {mtd} {url}: {text[:200]}"

        time.sleep(DELAY)

