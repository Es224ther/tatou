# server/test/conftest.py
# -*- coding: utf-8 -*-
"""
Pytest fixtures for Tatou API tests (real MariaDB, no RMAP, no real watermarking).
- Ensures DB env and waits for MySQL.
- Creates Flask test client from your `server.py`.
- Provides `fresh_user_payload` and `auth_token` for API tests.
- Registers ONE dummy watermark method so that `/api/get-watermarking-methods`
  returns a non-empty list without loading real implementations.
- Isolates filesystem and sets a temp STORAGE_DIR.
"""

import os
import sys
import io
import shutil
import uuid
import time
import socket
import tempfile
import pytest
from pathlib import Path

def pytest_collection_modifyitems(config, items):
    """Skip tests that rely on external deps: embed-attachment / xmp-metadata."""
    skip_keys = ("embed-attachment", "xmp-metadata")
    for item in items:
        if any(k in item.nodeid for k in skip_keys):
            item.add_marker(pytest.mark.skip(
                reason="External dependency; skipped for CI/mutation"))

# --- Make source importable in tests ---

ROOT_DIR   = Path(__file__).resolve().parents[2]   # tatou/ （项目根）
SERVER_DIR = ROOT_DIR / "server"
SRC_DIR    = SERVER_DIR / "src"

for p in (str(ROOT_DIR), str(SERVER_DIR), str(SRC_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)
# ---------------------------------------



# ------------------------------------------------------------
# Ensure minimal secrets & disable RMAP during these tests
# ------------------------------------------------------------
os.environ.setdefault("TATOU_XMP_SECRET", "test-secret-key")
os.environ.setdefault("ENABLE_RMAP", "0")   # RMAP tested separately
os.environ.setdefault("SECRET_KEY", "test-secret-key")


# ------------------------------------------------------------
# Database environment for tests (use local MySQL / Docker)
# ------------------------------------------------------------
@pytest.fixture(autouse=True, scope="session")
def _set_db_env():
    os.environ.setdefault("DB_HOST", "127.0.0.1")  # if running on host; use "db" inside container
    os.environ.setdefault("DB_PORT", "3306")
    os.environ.setdefault("DB_NAME", "tatou")
    os.environ.setdefault("DB_USER", "group8")
    os.environ.setdefault("DB_PASSWORD", "0915")


# ------------------------------------------------------------
# Optional: wait until MySQL is ready (avoid race in CI/Docker)
# ------------------------------------------------------------
def _wait_port(host: str, port: int, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, int(port)), timeout=2):
                return True
        except OSError:
            time.sleep(0.5)
    return False

@pytest.fixture(scope="session", autouse=True)
def _wait_mysql_ready():
    host = os.getenv("DB_HOST", "127.0.0.1")
    port = int(os.getenv("DB_PORT", "3306"))
    assert _wait_port(host, port, timeout=40), f"MySQL not ready at {host}:{port}"


# ------------------------------------------------------------
# Register a DUMMY watermarking method (no real logic)
#   so /api/get-watermarking-methods has at least one entry.
#   Avoids importing real modules like xmp_metadata_method, etc.
# ------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def _register_dummy_wm_method():
    try:
        import watermarking_utils as wm
    except Exception:
        return  # if module not importable, skip silently

    class _DummyMethod:
        name = "mock_method"
        description = "A dummy watermark method for API structure tests."
        position = "center"

    def get_usage(self):
        return self.description

    def embed(self, *args, **kwargs):
        return b""     # no-op
    def read(self, *args, **kwargs):
        return {"method": self.name, "position": self.position}


    try:
        wm.register_method(_DummyMethod())
    except Exception:
        pass

# ------------------------------------------------------------
# Ensure every registered watermark method has get_usage()
# ------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def _force_get_usage_on_methods():
    try:
        import types
        import watermarking_utils as wm
    except Exception:
        return

    # Your utils expose a module-level METHODS dict, not a WMUtils class
    registry = getattr(wm, "METHODS", None)
    if not isinstance(registry, dict):
        return

    # Iterate through already-registered methods and patch missing get_usage()
    for name, obj in list(registry.items()):
        if not hasattr(obj, "get_usage"):
            # Prefer method.description; fall back to the method name
            desc = getattr(obj, "description", str(name))

            def _make_get_usage(desc_value):
                def _get_usage(self):
                    return desc_value
                return _get_usage

            obj.get_usage = types.MethodType(_make_get_usage(desc), obj)


            # Bind as an instance method
            obj.get_usage = types.MethodType(_make_get_usage(desc), obj)


# ------------------------------------------------------------
# Flask app / client fixtures
# ------------------------------------------------------------
@pytest.fixture(scope="session")
def app():
    # Your file is server/src/server.py, so this imports the module `server`
    from server import app as _app
    _app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

    # Use an isolated storage directory for tests
    tmp = tempfile.mkdtemp(prefix="tatou_storage_")
    _app.config["STORAGE_DIR"] = Path(tmp)


    try:
        yield _app
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture(scope="session")
def client(app):
    return app.test_client()


# ------------------------------------------------------------
# Auth helpers (aligns with test_api.py usage)
# ------------------------------------------------------------
@pytest.fixture
def fresh_user_payload():
    ts = uuid.uuid4().hex[:12]
    return {
        "email": f"u{ts}@example.com",
        "login": f"u{ts}",
        "password": "p123456",
    }


@pytest.fixture
def auth_token(client, fresh_user_payload):
    """
    Create a fresh user and log in, returning the Bearer token string.
    """
    # create-user (201/200 if new, 409 if already exists)
    r = client.post("/api/create-user", json=fresh_user_payload)
    assert r.status_code in (201, 200, 409)

    # login
    r = client.post("/api/login", json={
        "email": fresh_user_payload["email"],
        "password": fresh_user_payload["password"],
    })
    assert r.status_code == 200, r.get_json()
    data = r.get_json()
    assert isinstance(data.get("token"), str)
    return data["token"]


# ------------------------------------------------------------
# Filesystem isolation (cwd + a few benign envs)
#   We keep it lightweight; RMAP is disabled anyway.
# ------------------------------------------------------------
@pytest.fixture(autouse=True)
def _isolated_fs(tmp_path, monkeypatch):
    # Work in a clean directory each test (does not affect STORAGE_DIR above)
    monkeypatch.chdir(tmp_path)

    # Keep benign envs (no real RMAP used)
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("ENABLE_RMAP", "0")

    yield


# ------------------------------------------------------------
# Dummy PDF helpers (still useful for unit tests)
# ------------------------------------------------------------
@pytest.fixture()
def dummy_pdf(tmp_path):
    p = tmp_path / "demo.pdf"
    p.write_bytes(b"%PDF-1.4\n%EOF\n")
    return p


@pytest.fixture()
def bytes_pdf():
    return io.BytesIO(b"%PDF-1.4\n%EOF\n")



