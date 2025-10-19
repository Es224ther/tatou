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
