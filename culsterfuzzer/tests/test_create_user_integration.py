# tests/test_create_user_integration.py
import os
import time
import json
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent
SECRETS_PATH = ROOT / "secrets" / "API_TOKEN"

API_TOKEN = os.getenv("API_TOKEN")
if not API_TOKEN and SECRETS_PATH.exists():
    API_TOKEN = SECRETS_PATH.read_text(encoding="utf-8").strip()

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
CREATE_USER_PATH = "/api/create-user"

# Allow running this test only when explicitly enabled:
ALLOW = os.getenv("ALLOW_MUTATE", "0") == "1" or os.getenv("CREATE_USER_TEST", "0") == "1"

pytestmark = pytest.mark.skipif(not ALLOW, reason="Stateful create-user test skipped (ALLOW_MUTATE or CREATE_USER_TEST not set)")

def unique_email():
    # produce a reasonably unique email to reduce collisions
    ts = int(time.time() * 1000)
    return f"test+{ts}@example.invalid"

def build_headers():
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    return headers

def try_delete_user(base_url, user_id, headers):
    """
    Try several common deletion endpoints; ignore errors.
    This is best-effort cleanup — not all APIs expose deletion via same path.
    """
    if not user_id:
        return False
    candidates = [
        f"{base_url}/api/delete-user/{user_id}",
        f"{base_url}/api/users/{user_id}",
        f"{base_url}/api/user/{user_id}",
        f"{base_url}/api/delete-user",  # sometimes expects JSON body
    ]
    for url in candidates:
        try:
            if url.endswith("/api/delete-user"):
                r = requests.delete(url, headers=headers, json={"id": user_id}, timeout=10)
            else:
                r = requests.request("DELETE", url, headers=headers, timeout=10)
        except requests.RequestException:
            continue
        # successful deletion if 200/204/202
        if r.status_code in (200, 202, 204):
            return True
    return False

def test_create_user_basic():
    """
    Integration test for POST /api/create-user.
    - Uses a unique email to reduce collisions.
    - Accepts 201 (created) or 409 (already exists) as valid outcomes, but fails on 5xx.
    - Attempts best-effort cleanup if an id is returned.
    """
    url = BASE_URL.rstrip("/") + CREATE_USER_PATH
    headers = build_headers()
    email = unique_email()
    payload = {"email": email, "login": email.split("@", 1)[0], "password": "P@ssw0rd!23"}
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=15)
    except requests.RequestException as e:
        pytest.skip(f"Request failed (skipping integration): {e}")

    # Basic sanity asserts
    assert 100 <= r.status_code <= 599
    # Server error -> fail the test (these indicate regression)
    assert not (500 <= r.status_code <= 599), f"Server error {r.status_code}: {r.text[:400]}"

    # Acceptable outcomes:
    # - 201 Created -> success, try cleanup if id returned
    # - 409 Conflict (already exists) -> acceptable (non-regression)
    # - 400/422 -> possibly validation errors; treat as failure for this test since we send valid payload
    if r.status_code == 201:
        # try to parse id from response
        user_id = None
        try:
            data = r.json() if r.content else {}
        except Exception:
            data = {}
        # common fields where id may appear
        for k in ("id", "user_id", "uid"):
            if k in data:
                user_id = data[k]
                break

        # best-effort cleanup
        deleted = False
        if user_id:
            deleted = try_delete_user(BASE_URL.rstrip("/"), user_id, headers)
        # if deletion failed, don't mark the test as failed — just warn
        if not deleted:
            # log a warning to stdout (pytest will show on -s)
            print(f"[WARN] created user id {user_id} not deleted (cleanup best-effort failed).")
        return

    if r.status_code == 409:
        # Already exists is acceptable; check response message or body if needed
        return

    # For other 2xx we accept, for 4xx non-409 treat as failure
    if 200 <= r.status_code < 300:
        return

    # otherwise fail
    pytest.fail(f"Unexpected response {r.status_code}: {r.text[:400]}")
