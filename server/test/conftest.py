# server/test/conftest.py
from pathlib import Path
import os
import sys
import tempfile
import shutil
import pytest
import os
import sys
import pathlib
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

os.environ.setdefault("TATOU_XMP_SECRET", "test-secret")
os.environ.setdefault("DB_HOST", "127.0.0.1")
os.environ.setdefault("DB_PORT", "3306")
os.environ.setdefault("DB_NAME", "tatou")
os.environ.setdefault("DB_USER", "group8")
os.environ.setdefault("DB_PASSWORD", "0915")
os.environ.setdefault("STORAGE_DIR", str(pathlib.Path("storage").resolve()))
pathlib.Path(os.environ["STORAGE_DIR"]).mkdir(parents=True, exist_ok=True)

@pytest.fixture(autouse=True, scope="session")
def _register_wm_methods():
    import importlib
    wm = importlib.import_module("watermarking_utils")

    try:
        from xmp_metadata_method import XmpMetadataMethod
        wm.register_method(XmpMetadataMethod())
    except Exception:
        pass

    try:
        from invisible_text_watermark import InvisibleTextWatermark
        wm.register_method(InvisibleTextWatermark())
    except Exception:
        pass
    
    try:
        from embed_attachment import EmbedAttachment
        wm.register_method(EmbedAttachment())
    except Exception:
        pass


@pytest.fixture(scope="session")
def client():
    from server import app
    tmp_str = tempfile.mkdtemp(prefix="tatou_storage_")
    tmp = Path(tmp_str)
    app.config.update({
        "STORAGE_DIR": tmp,
        "TESTING": True,
        "PROPAGATE": True,
    })
    try:
        yield app.test_client()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

@pytest.fixture
def auth_headers(client):
    import time
    # create user (ignore 409 if already exists)
    email = f"u{int(time.time()*1000)}@example.com"
    client.post("/api/create-user", json={
        "email": email,
        "login": email.split("@")[0],
        "password": "test123"
    })
    # login to get token
    resp = client.post("/api/login", json={"email": email, "password": "test123"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data and "token" in data, f"Login response missing token: {data}"
    token = data["token"]
    return {"Authorization": f"Bearer {token}"}
