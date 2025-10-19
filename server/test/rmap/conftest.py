# -*- coding: utf-8 -*-
"""
RMAP route tests: isolated Flask app + fakes for RMAP and DB.
- Forces a temp STORAGE_DIR and OUTPUT_DIR
- Creates a tiny valid-ish PDF as RMAP_INPUT_PDF
- Monkeypatches get_rmap / InvisibleTextWatermark / get_engine
"""

import os
import tempfile
from pathlib import Path

import pytest
from flask import Flask

# Import your blueprint module
import rmap_route as rr


@pytest.fixture(scope="session")
def _tmp_root():
    with tempfile.TemporaryDirectory(prefix="tatou_rmap_tests_") as d:
        yield Path(d)


@pytest.fixture()
def app(_tmp_root, monkeypatch):
    """
    Build a fresh Flask app for each test and register the RMAP blueprint.
    """
    # 1) temp storage + sample input PDF
    storage_dir = _tmp_root / "storage"
    storage_dir.mkdir(parents=True, exist_ok=True)

    sample_pdf = storage_dir / "files" / "Mr_Important" / "20250926T172119__Group_8.pdf"
    sample_pdf.parent.mkdir(parents=True, exist_ok=True)
    # Minimal, but acceptable for send_file
    sample_pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n")

    # 2) env vars used by rmap_route
    monkeypatch.setenv("RMAP_INPUT_PDF", str(sample_pdf))
    # 覆盖模块级常量，避免导入时已读取为 None
    monkeypatch.setattr(rr, "RMAP_INPUT_PDF", str(sample_pdf), raising=False)
    monkeypatch.setenv("RMAP_WATERMARK_SECRET", "Group_8")
    monkeypatch.setenv("RMAP_WATERMARK_POSITION", "last-page-bottom-left")

    # fake key paths (won't be actually read thanks to fake get_rmap)
    keys_root = _tmp_root / "secrets"
    (keys_root / "clients").mkdir(parents=True, exist_ok=True)
    (keys_root / "server").mkdir(parents=True, exist_ok=True)
    (keys_root / "server" / "server_priv.asc").write_text("FAKE")
    (keys_root / "server" / "server_pub.asc").write_text("FAKE")
    monkeypatch.setenv("RMAP_CLIENT_KEYS_DIR", str(keys_root / "clients"))
    monkeypatch.setenv("RMAP_SERVER_PRIVATE", str(keys_root / "server" / "server_priv.asc"))
    monkeypatch.setenv("RMAP_SERVER_PUBLIC", str(keys_root / "server" / "server_pub.asc"))

    # 3) Flask app config
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        STORAGE_DIR=str(storage_dir),
        DB_HOST="127.0.0.1",
        DB_PORT="3306",
        DB_NAME="tatou",
        DB_USER="group8",
        DB_PASSWORD="0915",
        SERVER_NAME="localhost",        # needed for url_for(..., _external=True)
        PREFERRED_URL_SCHEME="http",
    )
    app.register_blueprint(rr.rmap_bp)
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


# -------------------- Fakes --------------------

class _FakeRMAP:
    """Tiny fake for rmap.rmap.RMAP."""
    def __init__(self, token: str = "047d3e70257ff236d3ddcb490c57bc1d"):
        self.token = token
    def handle_message1(self, data):
        # prove call path by returning a known base64 string
        return {"payload": "QUJDREVGR0g="}  # "ABCDEFGH"
    def handle_message2(self, data):
        return {"result": self.token}


class _FakeWatermarker:
    """Fake for InvisibleTextWatermark; returns tiny PDF bytes."""
    def add_watermark(self, input_pdf, secret, key="", position="center"):
        return b"%PDF-1.4\n% watermarked\n%%EOF\n"


class _FakeConnCtx:
    """
    Mimic SQLAlchemy Connection; returns a Result-like object with .first().
    We capture the final watermarked path into a dict so GET can read it later.
    """
    class _Result:
        def __init__(self, row): self._row = row
        def first(self): return self._row

    def __init__(self, input_pdf_path: Path, final_path_holder: dict):
        self._input_pdf_path = str(input_pdf_path.resolve())
        self._final_path_holder = final_path_holder

    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False

    def execute(self, stmt, params=None):
        sql = str(stmt)
        params = params or {}

        # SELECT id FROM Documents WHERE path = :p LIMIT 1
        if "SELECT id FROM Documents" in sql:
            if params.get("p") == self._input_pdf_path:
                class Row: id = 42
                return self._Result(Row())
            return self._Result(None)

        # SELECT path FROM Versions WHERE link = :t LIMIT 1
        if "SELECT path FROM Versions" in sql:
            token = params.get("t")
            path = self._final_path_holder.get(token)
            if path:
                class Row:
                    def __init__(self, p): self.path = p
                return self._Result(Row(path))
            return self._Result(None)

        # INSERT INTO Versions (...)
        if "INSERT INTO Versions" in sql:
            link = params.get("link")
            path = params.get("path")
            if link and path:
                self._final_path_holder[link] = path
            return self._Result(None)

        raise AssertionError(f"Unexpected SQL in fake: {sql}")


class _FakeBeginCtx:
    def __init__(self, conn_ctx): self._conn_ctx = conn_ctx
    def __enter__(self): return self._conn_ctx
    def __exit__(self, exc_type, exc, tb): return False


class _FakeEngine:
    def __init__(self, input_pdf_path: Path, final_path_holder: dict):
        self._conn_ctx = _FakeConnCtx(input_pdf_path, final_path_holder)
    def connect(self): return self._conn_ctx
    def begin(self): return _FakeBeginCtx(self._conn_ctx)


@pytest.fixture()
def patch_fakes(monkeypatch, _tmp_root):
    """
    Apply all monkeypatches and force OUTPUT_DIR to a writable temp dir.
    """
    final_path_holder = {}
    input_pdf = Path(os.environ["RMAP_INPUT_PDF"]).resolve()

    # Force output dir to avoid relative 'static/watermarked' surprises
    out_dir = _tmp_root / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(rr, "OUTPUT_DIR", str(out_dir), raising=False)

    # Flask 3: send_file no longer accepts 'cache_timeout' -> drop it
    from flask import send_file as _flask_send_file
    def _safe_send_file(path, *args, **kwargs):
        kwargs.pop("cache_timeout", None)
        return _flask_send_file(path, *args, **kwargs)
    monkeypatch.setattr(rr, "send_file", _safe_send_file, raising=False)

    # Ensure module-level constant is also set (belt-and-suspenders)
    monkeypatch.setattr(rr, "RMAP_INPUT_PDF", str(input_pdf), raising=False)

    # Apply fakes
    monkeypatch.setattr(rr, "get_rmap", lambda: _FakeRMAP(), raising=True)
    monkeypatch.setattr(rr, "InvisibleTextWatermark", _FakeWatermarker, raising=True)
    monkeypatch.setattr(rr, "get_engine", lambda: _FakeEngine(input_pdf, final_path_holder), raising=True)

    return {"final_path_holder": final_path_holder}
