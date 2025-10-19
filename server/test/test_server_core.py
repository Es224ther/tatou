# server/test/test_server_core.py
# -*- coding: utf-8 -*-
"""
Core API integration tests for Tatou system (real MariaDB, no mocks).
Covers basic endpoints and authentication flows to improve mutation coverage.
"""

import pytest
from sqlalchemy import text

# ---------------------------------------------------------------------
# Basic health and configuration tests
# ---------------------------------------------------------------------
def test_healthz_returns_ok_and_db_status(client, db_engine):
    """
    Verify that /healthz responds with HTTP 200 and JSON keys.
    """
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "message" in data
    assert "db_connected" in data
    # Ensure DB is reachable
    with db_engine.begin() as conn:
        assert conn.execute(text("SELECT 1")).scalar() == 1


# ---------------------------------------------------------------------
# Authentication: user creation + login + protected route
# ---------------------------------------------------------------------
def test_user_create_and_login_success(client, fresh_user_payload):
    """
    Create a new user and then login to receive a token.
    """
    # Create
    r1 = client.post("/api/create-user", json=fresh_user_payload)
    assert r1.status_code in (200, 201, 409)

    # Login
    r2 = client.post("/api/login", json={
        "email": fresh_user_payload["email"],
        "password": fresh_user_payload["password"],
    })
    assert r2.status_code == 200
    data = r2.get_json()
    assert "token" in data
    assert isinstance(data["token"], str)


def test_login_invalid_password_returns_401(client, fresh_user_payload):
    """
    Try login with invalid password → should return 401 Unauthorized.
    """
    client.post("/api/create-user", json=fresh_user_payload)
    bad = dict(fresh_user_payload)
    bad["password"] = "wrong"
    r = client.post("/api/login", json=bad)
    assert r.status_code == 401
    assert "error" in r.get_json()


# ---------------------------------------------------------------------
# Auth-protected endpoint behavior
# ---------------------------------------------------------------------
def test_auth_required_endpoints_reject_without_token(client):
    """
    Call a protected endpoint without Authorization header → 401.
    """
    r = client.post("/api/upload-document")
    assert r.status_code == 401
    data = r.get_json()
    assert "error" in data


def test_auth_token_header_and_x_request_id(client, auth_token, dummy_pdf):
    """
    Upload a dummy PDF with valid token and ensure headers are correct.
    """
    headers = {"Authorization": f"Bearer {auth_token}"}
    data = {"file": (open(dummy_pdf, "rb"), "demo.pdf")}
    r = client.post("/api/upload-document", headers=headers, data=data)
    assert r.status_code in (200, 201)
    assert "X-Request-ID" in r.headers
    j = r.get_json()
    for key in ("id", "name", "sha256", "size"):
        assert key in j


# ---------------------------------------------------------------------
# Direct database connection check
# ---------------------------------------------------------------------
@pytest.fixture(scope="session")
def db_engine(app):
    """
    Get the real SQLAlchemy engine from Flask app config.
    Ensures database connectivity for tests.
    """
    eng = app.config.get("_ENGINE")
    assert eng is not None, "Engine not initialized in app.config"
    return eng


def test_database_connection_alive(db_engine):
    """
    Simple query to confirm database connection is alive.
    """
    with db_engine.begin() as conn:
        assert conn.execute(text("SELECT 1")).scalar() == 1
