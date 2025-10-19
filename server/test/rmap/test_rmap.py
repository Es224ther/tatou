# -*- coding: utf-8 -*-
"""
Unit tests for RMAP routes using fakes (no real keys/DB).
English comments included.
"""

import base64
import re


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("ascii")).decode("ascii")


# ---------- /api/rmap-initiate ----------

def test_initiate_accepts_armored_b64(client, patch_fakes):
    m1 = {"armored_b64": _b64("-----BEGIN PGP MESSAGE-----\nM1\n-----END PGP MESSAGE-----")}
    resp = client.post("/api/rmap-initiate", json=m1)
    assert resp.status_code == 200, resp.get_json()
    data = resp.get_json()
    assert "payload" in data and isinstance(data["payload"], str)
    # fake returns "QUJDREVGR0g="
    assert data["payload"] == "QUJDREVGR0g="


def test_initiate_accepts_armor_body(client, patch_fakes):
    armor = "-----BEGIN PGP MESSAGE-----\nHELLO\n-----END PGP MESSAGE-----"
    resp = client.post("/api/rmap-initiate", json={"armor_body": armor})
    assert resp.status_code == 200, resp.get_json()
    assert "payload" in resp.get_json()


def test_initiate_invalid_base64_returns_400(client, patch_fakes):
    resp = client.post("/api/rmap-initiate", json={"armored_b64": "!!!!not_base64!!!!"})
    assert resp.status_code == 400
    assert "invalid base64" in resp.get_json().get("error", "").lower()


# ---------- /api/rmap-get-link & /api/get-version/<token> ----------

def test_get_link_happy_path_returns_download_url(client, patch_fakes):
    m2 = {"armored_b64": _b64("-----BEGIN PGP MESSAGE-----\nM2\n-----END PGP MESSAGE-----")}
    resp = client.post("/api/rmap-get-link", json=m2)
    assert resp.status_code == 200, resp.get_json()
    data = resp.get_json()
    assert {"result", "download_url"} <= set(data.keys())
    token = data["result"]
    assert re.fullmatch(r"[0-9a-f]{32}", token)
    assert f"/api/get-version/{token}" in data["download_url"]


def test_get_version_serves_pdf(client, patch_fakes):
    # Create a version first
    m2 = {"armored_b64": _b64("-----BEGIN PGP MESSAGE-----\nM2\n-----END PGP MESSAGE-----")}
    post_resp = client.post("/api/rmap-get-link", json=m2)
    assert post_resp.status_code == 200, post_resp.get_json()
    token = post_resp.get_json()["result"]

    # Now download it
    get_resp = client.get(f"/api/get-version/{token}")
    assert get_resp.status_code == 200
    assert get_resp.mimetype == "application/pdf"
    assert get_resp.data.startswith(b"%PDF")


def test_get_version_invalid_token(client):
    bad = client.get("/api/get-version/NOT_A_TOKEN")
    assert bad.status_code == 400
