from server import app
import io
import time
import pikepdf

def test_healthz_route():
    client = app.test_client()
    resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.is_json
    
def test_create_user_validation_error():
    client = app.test_client()
    resp = client.post("/api/create-user", json={})
    assert resp.status_code == 400
    assert resp.is_json

def test_create_user_route():
    client = app.test_client()
    email = f"test_{int(time.time()*1000)}@example.com"
    login = email.split("@")[0]
    resp = client.post("/api/create-user", json={
        "email": email,
        "login": login,
        "password": "test123"
    })
    assert resp.status_code == 201
    assert resp.is_json
    body = resp.get_json()
    assert {"id", "email", "login"} <= set(body.keys())


def test_login_route():
    client = app.test_client()
    resp = client.post("/api/login", json={
        "email": "Mr_Important@gmail.com",
        "password": "123456"
    })
    assert resp.status_code == 200
    assert resp.is_json
    body = resp.get_json()
    assert "token" in body and body.get("token_type") == "bearer"
    assert isinstance(body.get("expires_in"), int)


def test_get_watermarking_methods_route(client):
    resp = client.get("/api/get-watermarking-methods")
    assert resp.status_code == 200
    assert resp.is_json
    body = resp.get_json()
    assert "methods" in body


def test_upload_document_requires_auth(client):
    resp = client.post("/api/upload-document")
    assert resp.status_code == 401
    assert resp.is_json


def test_list_documents_requires_auth(client):
    resp = client.get("/api/list-documents")
    assert resp.status_code == 401
    assert resp.is_json


def test_list_versions_requires_auth(client):
    resp = client.get("/api/list-versions")
    assert resp.status_code == 401
    assert resp.is_json


def test_get_document_requires_auth(client):
    resp = client.get("/api/get-document")
    assert resp.status_code == 401
    assert resp.is_json


def test_create_watermark_requires_auth(client):
    resp = client.post("/api/create-watermark", json={})
    assert resp.status_code == 401
    assert resp.is_json


def test_read_watermark_requires_auth(client):
    resp = client.post("/api/read-watermark", json={})
    assert resp.status_code == 401
    assert resp.is_json


def test_list_documents_ok(client, auth_headers):
    resp = client.get("/api/list-documents", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.is_json
    body = resp.get_json()
    assert "documents" in body

def _make_min_pdf_bytes() -> bytes:
    pdf = pikepdf.Pdf.new()
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()

def test_upload_document_ok_and_list_versions(client, auth_headers):
    pdf_bytes = _make_min_pdf_bytes()
    data = {
        "file": (io.BytesIO(pdf_bytes), "demo.pdf", "appliation/pdf"),
        "name": "demo"
    }
    resp = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    )
    assert resp.status_code in (200, 201), (resp.status_code, resp.data)
    assert resp.is_json, resp.data
    up = resp.get_json()
    assert isinstance(up, dict), up

    # List versions for this document (should be empty array initially)
    resp2 = client.get(f"/api/list-versions?id={up['id']}", headers=auth_headers)
    assert resp2.status_code == 200
    assert resp2.is_json
    body2 = resp2.get_json()
    assert "versions" in body2


def test_get_document_ok(client, auth_headers):
    # Upload a PDF to obtain an id
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    data = {
        "file": (io.BytesIO(pdf_bytes), "demo2.pdf"),
        "name": "demo2"
    }
    up = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    ).get_json()

    # Fetch the PDF back
    resp = client.get(f"/api/get-document?id={up['id']}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"


def test_create_watermark_ok(client, auth_headers):
    # Upload a PDF to obtain an id
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    data = {
        "file": (io.BytesIO(pdf_bytes), "demo3.pdf"),
        "name": "demo3"
    }
    up = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    ).get_json()

    # Create watermark 
    resp = client.post(
        f"/api/create-watermark?id={up['id']}",
        headers=auth_headers,
        json={"method": "toy-eof", "intended_for": "Tester"},
    )
    assert resp.status_code == 201
    body = resp.get_json()
    assert {"id", "documentid", "link", "method", "filename", "size"} <= set(body.keys())
    assert body["method"] == "toy-eof"


def test_read_watermark_ok(client, auth_headers):
    # Upload a PDF to obtain an id
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    data = {
        "file": (io.BytesIO(pdf_bytes), "demo4.pdf"),
        "name": "demo4"
    }
    up = client.post(
        "/api/upload-document",
        headers=auth_headers,
        data=data,
        content_type="multipart/form-data",
    ).get_json()

    # First, create an  watermark so there is something to read
    cw = client.post(
        f"/api/create-watermark?id={up['id']}",
        headers=auth_headers,
        json={"method": "toy-eof", "intended_for": "Reader"},
    )
    assert cw.status_code == 201

    # Read watermark 
    resp = client.post(
        f"/api/read-watermark?id={up['id']}",
        headers=auth_headers,
        json={"method": "toy-eof"},
    )
    assert resp.status_code == 201
    body = resp.get_json()
    assert {"documentid", "secret", "method", "position"} <= set(body.keys())
    assert body["method"] == "toy-eof"
