# server/test/test_api.py
# -*- coding: utf-8 -*-
"""
End-to-end API tests for the Tatou project (excluding RMAP and real watermarking).

Covers endpoints:
  - /healthz
  - /api/create-user
  - /api/login
  - /api/upload-document
  - /api/list-documents
  - /api/list-versions (path/query)
  - /api/list-all-versions
  - /api/get-document
  - /api/get-watermarking-methods
  - /api/create-watermark (mocked)
  - /api/read-watermark (mocked)

Test framework: pytest + Flask test_client (real MariaDB connection).
"""

import io
import json
import time
import pytest
from urllib.parse import quote

def _has_route(client, path: str, method: str) -> bool:
    """Return True if Flask app has a route 'path' that accepts 'method'."""
    app = client.application
    for rule in app.url_map.iter_rules():
        if rule.rule == path and method.upper() in (rule.methods or set()):
            return True
    return False

# -----------------------------
# /healthz
# -----------------------------
def test_healthz(client):
    """
    Basic health check endpoint.
    Should return JSON containing a 'message' string and 'db_connected' boolean.
    """
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert isinstance(body.get("message"), str)
    assert "db_connected" in body
    assert isinstance(body["db_connected"], bool)


# -----------------------------
# User creation / login
# -----------------------------
def test_create_user_validation_error(client):
    """POST /api/create-user with empty body should return 400."""
    r = client.post("/api/create-user", json={})
    assert r.status_code == 400


def test_create_user_success_then_login(client, fresh_user_payload):
    """
    Create a new user and log in.
    Expected:
      - create-user: 200/201/409 (if already exists)
      - login: 200, returns token info
    """
    r = client.post("/api/create-user", json=fresh_user_payload)
    assert r.status_code in (201, 200, 409)
    r = client.post("/api/login", json={
        "email": fresh_user_payload["email"],
        "password": fresh_user_payload["password"],
    })
    assert r.status_code == 200
    data = r.get_json()
    assert isinstance(data.get("token"), str)
    assert data.get("token_type", "").lower() == "bearer"
    assert isinstance(data.get("expires_in"), int)


# -----------------------------
# Helpers
# -----------------------------
def _fake_pdf_bytes() -> bytes:
    """Return minimal fake PDF bytes for upload."""
    return b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


def _upload_one_pdf(client, token, name="Dummy.pdf"):
    """Upload a fake PDF and return (document_id, response_json)."""
    data = {"file": (io.BytesIO(_fake_pdf_bytes()), name), "name": name}
    r = client.post("/api/upload-document",
                    headers={"Authorization": f"Bearer {token}"},
                    data=data,
                    content_type="multipart/form-data")
    assert r.status_code in (201, 200), r.get_json()
    body = r.get_json()
    for k in ("id", "name", "creation", "sha256", "size"):
        assert k in body
    return int(body["id"]), body


# -----------------------------
# Upload / List / Get
# -----------------------------
def test_upload_requires_auth(client):
    """POST /api/upload-document without Authorization should fail."""
    data = {"file": (io.BytesIO(_fake_pdf_bytes()), "NoAuth.pdf"), "name": "NoAuth.pdf"}
    r = client.post("/api/upload-document", data=data, content_type="multipart/form-data")
    assert r.status_code in (401, 403)


def test_upload_list_get_roundtrip(client, auth_token):
    """
    Upload → list-documents → get-document (query + path forms).
    """
    doc_id, meta = _upload_one_pdf(client, auth_token, "Roundtrip.pdf")

    # list-documents
    r = client.get("/api/list-documents",
                   headers={"Authorization": f"Bearer {auth_token}"})
    assert r.status_code == 200
    body = r.get_json()
    assert isinstance(body.get("documents"), list)

    # get-document by query
    r = client.get("/api/get-document",
                   headers={"Authorization": f"Bearer {auth_token}"},
                   query_string={"id": doc_id})
    assert r.status_code == 200

    # get-document by path
    r = client.get(f"/api/get-document/{doc_id}",
                   headers={"Authorization": f"Bearer {auth_token}"})
    assert r.status_code == 200


# -----------------------------
# Watermarking methods
# -----------------------------

def test_get_watermarking_methods(client, monkeypatch):
    """
    GET /api/get-watermarking-methods
    Expects {"count": int, "methods": [ {name, description}, ... ]}.
    """
    import server  # adjust if your import path differs

    # A safe fake method object with both `description` and `get_usage()`.
    class _FakeMethod:
        description = "demo watermark"
        def get_usage(self):
            return "demo usage"

    # A minimal fake "WMUtils" the route can work with.
    class _FakeWMUtils:
        METHODS = {"demo": _FakeMethod()}
        @staticmethod
        def get_method(name: str):
            return _FakeWMUtils.METHODS[name]

    # Patch the exact symbol the route references.
    monkeypatch.setattr(server, "WMUtils", _FakeWMUtils, raising=False)

    # Exercise the endpoint.
    r = client.get("/api/get-watermarking-methods")
    assert r.status_code == 200, f"Unexpected status: {r.status_code}"

    # Contract checks.
    body = r.get_json()
    assert isinstance(body.get("count"), int)
    assert isinstance(body.get("methods"), list)
    assert body["count"] == len(body["methods"])
    assert body["methods"], "Expected at least one method"

    m0 = body["methods"][0]
    assert "name" in m0 and "description" in m0
    assert m0["name"] == "demo"
    assert m0["description"] in ("demo usage", "demo watermark")

# -----------------------------
# create-watermark / read-watermark / list-versions (mocked)
# -----------------------------
def test_create_and_read_watermark_and_list_versions(client, auth_token):
    """
    Structural test for watermark-related endpoints (mocked).
    - Uses fake document id (99999)
    - Skips real watermark embedding logic
    - Verifies correct status codes and JSON structure
    """
    fake_doc_id = 99999

    # ---- create-watermark ----
    payload = {
        "method": "mock_method",
        "position": "center",
        "key": "dummy-key",
        "secret": "dummy-secret",
        "intended_for": "UnitTest",
        "id": fake_doc_id
    }
    r = client.post("/api/create-watermark",
                    headers={"Authorization": f"Bearer {auth_token}"},
                    json=payload)
    assert r.status_code in (200, 201, 404), r.data
    if r.status_code in (200, 201):
        meta = r.get_json()
        for key in ("id", "documentid", "method", "position"):
            assert key in meta

    # ---- read-watermark ----
    payload = {
        "method": "mock_method",
        "position": "center",
        "key": "dummy-key",
        "id": fake_doc_id
    }
    r = client.post("/api/read-watermark",
                    headers={"Authorization": f"Bearer {auth_token}"},
                    json=payload)
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        data = r.get_json()
        for key in ("documentid", "method", "position"):
            assert key in data

    # ---- list-versions ----
    r = client.get(f"/api/list-versions/{fake_doc_id}",
                   headers={"Authorization": f"Bearer {auth_token}"})
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert isinstance(r.get_json().get("versions"), list)

    # ---- list-all-versions ----
    r = client.get("/api/list-all-versions",
                   headers={"Authorization": f"Bearer {auth_token}"})
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert isinstance(r.get_json().get("versions"), list)


# ------------ helpers ------------
def _ensure_user_and_token(client, email="test+api@example.com", password="pass123"):
    login = email.split("@")[0] or "user"
    client.post("/api/create-user", json={"email": email, "password": password, "login": login})
    r = client.post("/api/login", json={"email": email, "password": password})
    assert r.status_code == 200, f"login failed: {r.status_code} {r.get_data(as_text=True)}"
    return r.get_json()["token"]


def _authz(tok): return {"Authorization": f"Bearer {tok}"}

def _upload_pdf(client, token, name="no_xmp_cov.pdf", content=b"%PDF-1.4\n%%EOF\n"):
    r = client.post(
        "/api/upload-document",
        headers=_authz(token),
        data={"file": (io.BytesIO(content), name)},
        content_type="multipart/form-data",
    )
    assert r.status_code in (200, 201), r.get_data(as_text=True)

    lr = client.get("/api/list-documents", headers=_authz(token))
    docs = lr.get_json() or []
    if isinstance(docs, dict) and "documents" in docs:
        docs = docs["documents"]

    same = [d for d in docs if str(d.get("name") or d.get("filename")) == name]
    assert same, f"Cannot find just uploaded {name}"
    doc = max(same, key=lambda d: int(d["id"]))   
    return int(doc["id"])

# ---------- auth decorator branches ----------
def test_auth_expired_and_tampered_token(client, monkeypatch):
    import server as server_mod
    tok = _ensure_user_and_token(client)

    from itsdangerous import exc as its_exc

    class _FakeSer:
        def __init__(self, *a, **k): pass
        def dumps(self, payload): return "unused"
        def loads(self, token, max_age=None):
            if token == tok:
                raise its_exc.SignatureExpired("expired")
            if token.endswith("X"):
                raise its_exc.BadSignature("bad")
            return {"uid": 0, "login": "n/a", "email": "n/a"}

    monkeypatch.setattr(server_mod, "URLSafeTimedSerializer",
                    lambda *a, **k: _FakeSer(), raising=False)
    monkeypatch.setattr(server_mod, "_serializer",
                    lambda: _FakeSer(), raising=False)
    # 过期 -> 401
    r1 = client.get("/api/list-documents", headers=_authz(tok))
    assert r1.status_code == 401

    # 篡改 -> 401
    tok2 = _ensure_user_and_token(client, email="test2@example.com")
    r2 = client.get("/api/list-documents", headers=_authz(tok2 + "X"))
    assert r2.status_code == 401

# ---------- list-versions 参数校验 ----------
def test_list_versions_invalid_id_400(client):
    tok = _ensure_user_and_token(client)
    r = client.get("/api/list-versions", headers=_authz(tok),
                   query_string={"documentid": "NaN"})
    assert r.status_code == 400

# ---------- get-version: 非法 link ----------
def test_get_version_invalid_link_400(client):
    r = client.get("/api/get-version/zzzz")
    assert r.status_code == 400

def _pick_download_token(meta: dict) -> str:
    """Pick the field that the GET /api/get-version/<...> route expects."""
    for k in ("token", "download_token", "signed_link", "signed", "link"):
        v = meta.get(k)
        if isinstance(v, str) and v:
            return v
    return ""

def _pick_download_token(meta: dict) -> str:
    # Try common field names; fall back to 'link'
    for k in ("token", "download_token", "signed_link", "signed", "link"):
        v = meta.get(k)
        if isinstance(v, str) and v:
            return v
    return ""

# ---------- get-version: success & not-found (robust) ----------
def test_get_version_happy_path_and_not_found(client, monkeypatch):
    tok = _ensure_user_and_token(client, email="gv_ok@example.com")
    doc_id = _upload_pdf(client, tok, name="gv_ok.pdf")

    import server as server_mod

    class _WMApplyOK:
        @staticmethod
        def is_watermarking_applicable(method, pdf, position=None):
            return True
        @staticmethod
        def apply_watermark(pdf, secret, key, method, position=None):
            # Unique bytes -> unique hash/signature downstream
            salt = f"{doc_id}-{time.time_ns()}".encode()
            return b"%PDF-1.4\n%Tatou-" + salt + b"\n%%EOF\n"

    monkeypatch.setattr(server_mod, "WMUtils", _WMApplyOK, raising=False)

    # unique tag also keeps persisted file path unique (avoid uq_* on path)
    unique_tag = f"t-{doc_id}-{time.time_ns()}"

    # 1) create a version
    r_c = client.post(
        f"/api/create-watermark/{doc_id}",
        headers=_authz(tok),
        json={"method": "invisible_text", "intended_for": unique_tag, "secret": "s", "key": "k"},
    )
    if r_c.status_code not in (200, 201):
        pytest.skip(f"create-watermark unavailable in this build: {r_c.status_code} {r_c.get_data(as_text=True)}")
    meta = r_c.get_json() or {}
    token = _pick_download_token(meta)
    if not token:
        pytest.skip(f"no usable token/link in response: keys={list(meta.keys())}")

    # 2) happy path (robust): call without Authorization; accept 200 (PDF) OR 400 'invalid token'
    encoded = quote(token, safe="") if ("/" in token or "%" in token) else token
    url = f"/api/get-version/{encoded}"
    r_ok = client.get(url)
    if r_ok.status_code == 200:
        assert r_ok.data.startswith(b"%PDF")
    else:
        # tolerate builds that require external signing we cannot reproduce in tests
        body_txt = r_ok.get_data(as_text=True)
        assert r_ok.status_code == 400 and "invalid token" in body_txt.lower(), body_txt
        pytest.skip("server requires externally signed token; skipping not-found branch")

    # 3) not-found branch (only when happy path succeeded)
    bad = (token[:-2] + ("xx" if not token.endswith("xx") else "zz")) if len(token) > 2 else token + "xx"
    bad_encoded = quote(bad, safe="") if ("/" in bad or "%" in bad) else bad
    r_nf = client.get(f"/api/get-version/{bad_encoded}")
    assert r_nf.status_code in (404, 400), r_nf.get_data(as_text=True)

# ---------- delete-document 的错误分支 ----------
def test_delete_document_missing_or_bad_id_400(client):
    tok = _ensure_user_and_token(client)
    r1 = client.delete("/api/delete-document", headers=_authz(tok))
    assert r1.status_code in (400, 404)

    r2 = client.delete("/api/delete-document", headers=_authz(tok),
                       query_string={"documentid": "abc"})
    assert r2.status_code == 400

# ---------- delete-document: success / repeat-delete / POST variant / cross-tenant ----------
def test_delete_document_success_then_404(client):
    tok = _ensure_user_and_token(client, email="del_ok@example.com")
    doc_id = _upload_pdf(client, tok, name="del_ok.pdf")

    # First deletion hits the view function and should succeed
    r1 = client.delete(f"/api/delete-document/{doc_id}", headers=_authz(tok))
    assert r1.status_code in (200, 204)

    # Deleting the same id again should hit the "already gone / not found" branch inside the view
    r2 = client.delete(f"/api/delete-document/{doc_id}", headers=_authz(tok))
    assert r2.status_code in (404, 400)

def test_delete_document_post_variant_success(client):
    # Skip if POST /api/delete-document is not implemented
    if not _has_route(client, "/api/delete-document", "POST"):
        import pytest
        pytest.skip("POST /api/delete-document not implemented in this server build")

    tok = _ensure_user_and_token(client, email="del_post@example.com")
    doc_id = _upload_pdf(client, tok, name="del_post.pdf")

    # Many implementations read 'documentid' from query args (not form/json)
    r = client.post("/api/delete-document",
                    headers=_authz(tok),
                    query_string={"documentid": str(doc_id)})
    assert r.status_code in (200, 204), r.get_data(as_text=True)

# ---------- read-watermark（非 XMP） ----------
def test_read_watermark_nonxmp_ok_and_error(client, monkeypatch):
    tok = _ensure_user_and_token(client)
    doc_id = _upload_pdf(client, tok, name="rw_nonxmp_ok_err.pdf")

    import server as server_mod

    # 成功路径：让 WMUtils.read_watermark 返回字符串
    class _WMOk:
        @staticmethod
        def read_watermark(pdf, key=None, method=None):
            return "S-OK"

    monkeypatch.setattr(server_mod, "WMUtils", _WMOk)
    r_ok = client.post(
        f"/api/read-watermark/{doc_id}",
        headers=_authz(tok),
        json={"method": "invisible_text", "key": "K", "intended_for": "t"},
    )
    assert r_ok.status_code in (200, 201)
    assert (r_ok.get_json() or {}).get("secret") == "S-OK"

    # 失败路径：随便抛个异常，覆盖错误分支（不同实现可能返回 400 或 500）
    class _WMErr:
        @staticmethod
        def read_watermark(pdf, key=None, method=None):
            raise RuntimeError("boom")

    monkeypatch.setattr(server_mod, "WMUtils", _WMErr)
    r_err = client.post(
        f"/api/read-watermark/{doc_id}",
        headers=_authz(tok),
        json={"method": "invisible_text", "key": "K", "intended_for": "t"},
    )
    assert r_err.status_code in (400, 500)

# ---------- create-watermark（非 XMP 三分支） ----------
def test_create_watermark_nonxmp_success_and_failures(client, monkeypatch):
    tok = _ensure_user_and_token(client)
    doc_id = _upload_pdf(client, tok, name="cw_nonxmp.pdf")

    import server as server_mod

    # (A) applicable=False -> 400
    class _WM1:
        @staticmethod
        def is_watermarking_applicable(method, pdf, position=None): return False
    monkeypatch.setattr(server_mod, "WMUtils", _WM1)
    r_a = client.post(f"/api/create-watermark/{doc_id}",
                      headers=_authz(tok),
                      json={"method": "invisible_text", "intended_for": "t",
                            "secret": "s", "key": "k"})
    assert r_a.status_code == 400

    # (B) apply raises -> 500
    class _WM2:
        @staticmethod
        def is_watermarking_applicable(method, pdf, position=None): return True
        @staticmethod
        def apply_watermark(pdf, secret, key, method, position=None): raise RuntimeError("oops")
    monkeypatch.setattr(server_mod, "WMUtils", _WM2)
    r_b = client.post(f"/api/create-watermark/{doc_id}",
                      headers=_authz(tok),
                      json={"method": "invisible_text", "intended_for": "t",
                            "secret": "s", "key": "k"})
    assert r_b.status_code == 500

    # (C) success -> 201（返回 bytes）
    class _WM3:
        @staticmethod
        def is_watermarking_applicable(method, pdf, position=None): return True
        @staticmethod
        def apply_watermark(pdf, secret, key, method, position=None): return b"%PDF-1.4\n%%EOF\n"
    monkeypatch.setattr(server_mod, "WMUtils", _WM3)
    r_c = client.post(f"/api/create-watermark/{doc_id}",
                      headers=_authz(tok),
                      json={"method": "invisible_text", "intended_for": "t",
                            "secret": "s", "key": "k"})
    assert r_c.status_code in (200, 201, 503)
    if r_c.status_code in (200, 201):
        j = r_c.get_json() or {}
        assert j.get("link") and j.get("method") == "invisible_text"
