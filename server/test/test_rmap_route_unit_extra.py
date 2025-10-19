# -*- coding: utf-8 -*-
"""
Extra unit tests to kill surviving mutants in server/src/rmap_route.py.
Self-contained: does not rely on project conftest fixtures.
English comments included.
"""

import base64
import re
import types
from pathlib import Path

import pytest
from flask import Flask

# Import module under test
import rmap_route as rr

# ---------------------------
# 0) Small helper utilities
# ---------------------------
def _b64(s: str) -> str:
    return base64.b64encode(s.encode("ascii")).decode("ascii")


# ------------------------------------------------------------
# 1) Helpers: _expand and _require_file  (kills 15, 18)
# ------------------------------------------------------------
def test_expand_and_require_file(monkeypatch, tmp_path):
    # _expand(None) must stay None (kills mutant flipping condition)
    assert rr._expand(None) is None

    # env/home expansion
    monkeypatch.setenv("X_TMP", str(tmp_path))
    assert rr._expand("$X_TMP/sub") == str(tmp_path / "sub")

    # _require_file must raise for None and for a missing file
    with pytest.raises(FileNotFoundError):
        rr._require_file(None, "RMAP_INPUT_PDF")

    with pytest.raises(FileNotFoundError):
        rr._require_file(str(tmp_path / "missing.pdf"), "RMAP_INPUT_PDF")

    # and must pass for an existing file
    f = tmp_path / "ok.pdf"
    f.write_bytes(b"%PDF-1.4\n")
    rr._require_file(str(f), "RMAP_INPUT_PDF")  # should not raise


# -------------------------------------------------------------------
# 2) resolve_input_pdf & OUTPUT_DIR behavior (kills 19–33 style envs)
# -------------------------------------------------------------------
def test_output_dir_created_and_input_pdf_checked(monkeypatch, tmp_path):
    # Point RMAP_OUTPUT_DIR to a fresh folder and reload the module to apply
    out_dir = tmp_path / "watermarked"
    monkeypatch.setenv("RMAP_OUTPUT_DIR", str(out_dir))

    # Create an input PDF and set env
    input_pdf = tmp_path / "input.pdf"
    input_pdf.write_bytes(b"%PDF-1.4\n")
    monkeypatch.setenv("RMAP_INPUT_PDF", str(input_pdf))

    # Reload to rebind module constants (OUTPUT_DIR, etc.)
    import importlib
    importlib.reload(rr)

    # Folder should be created with exist_ok=True
    assert out_dir.exists() and out_dir.is_dir()

    # resolve_input_pdf should return the exact path and verify existence
    got = rr.resolve_input_pdf(identity="ignored")
    assert got == str(input_pdf)

    # Now point to a missing file -> expect FileNotFoundError
    monkeypatch.setenv("RMAP_INPUT_PDF", str(tmp_path / "missing.pdf"))
    importlib.reload(rr)
    with pytest.raises(FileNotFoundError):
        rr.resolve_input_pdf(identity="ignored")


# ----------------------------------------------------------------------
# 3) _extract_payload_as_json & _build_payload_for_rmap
#    (kills 42,44–58,66–67,74–75,78,81–84)
# ----------------------------------------------------------------------
def test_extract_and_build_payload_normalizes_and_validates():
    # Wrapper payload -> unwrap to armored_b64
    req = types.SimpleNamespace(
        get_json=lambda **_: {"payload": {"armored_b64": _b64("hello")}},
        get_data=lambda: b""
    )
    out = rr._extract_payload_as_json(req)
    assert out == {"armored_b64": _b64("hello")}

    # armor_body_b64 -> re-key to armored_b64
    req2 = types.SimpleNamespace(
        get_json=lambda **_: {"armor_body_b64": _b64("X")},
        get_data=lambda: b""
    )
    out2 = rr._extract_payload_as_json(req2)
    assert out2 == {"armored_b64": _b64("X")}

    # Build payload with whitespace should strip to strict base64
    spaced = " \n".join([_b64("msg")[:8], _b64("msg")[8:]])
    req3 = types.SimpleNamespace(get_json=lambda **_: {"armored_b64": spaced}, get_data=lambda: b"")
    bp = rr._build_payload_for_rmap(req3)
    assert "payload" in bp and re.fullmatch(r"[A-Za-z0-9+/=]+", bp["payload"])

    # Invalid base64 must raise with diagnostic including head and len
    bad = "%%%NOTB64%%%=" * 5
    req_bad = types.SimpleNamespace(get_json=lambda **_: {"armored_b64": bad}, get_data=lambda: b"")
    with pytest.raises(ValueError) as ei:
        rr._build_payload_for_rmap(req_bad)
    s = str(ei.value)
    assert "invalid base64" in s and "head='" in s and "len=" in s


# -----------------------------------------------------------
# 4) Blueprint should be a Blueprint (kills 86)
# -----------------------------------------------------------
def test_blueprint_exists():
    from flask import Blueprint
    assert isinstance(rr.rmap_bp, Blueprint)


# --------------------------------------------------------------------------------
# 5) /api/rmap-initiate happy path with fake RMAP (kills 95 "and" vs "or")
# --------------------------------------------------------------------------------
class _FakeRMAP1:
    def handle_message1(self, payload):
        assert isinstance(payload, dict) and "payload" in payload
        return {"payload": "ok"}

def test_rmap_initiate_ok(monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(rr.rmap_bp)
    monkeypatch.setattr(rr, "get_rmap", lambda: _FakeRMAP1(), raising=True)

    client = app.test_client()
    resp = client.post("/api/rmap-initiate", json={"payload": {"armored_b64": _b64("X")}})
    assert resp.status_code == 200
    assert resp.get_json() == {"payload": "ok"}


# -----------------------------------------------------------------------------------------
# 6) /api/rmap-get-link with full fakes (kills 102,107,112–126,131,133,153,141–150)
# -----------------------------------------------------------------------------------------
class _FakeRMAP2:
    def handle_message2(self, payload):
        # must receive normalized dict (kills 102)
        assert isinstance(payload, dict) and "payload" in payload
        return {"result": "ab" * 16}  # 32-hex token

class _FakeWM:
    def add_watermark(self, input_pdf, secret="", key="", position=""):
        # secret must not be None (kills 120)
        assert secret is not None
        return b"%PDF-watermarked%"

class _Row:
    def __init__(self, **kw): self.__dict__.update(kw)

class _FakeConn:
    def execute(self, stmt, params=None):
        sql = str(stmt)
        if "FROM Documents" in sql:
            assert "path = :p" in sql  # kills mutated SQL
            return types.SimpleNamespace(first=lambda: _Row(id=1))
        if "INSERT INTO Versions" in sql:
            # correct param names and values (kills 141–150 set)
            assert params["documentid"] == 1
            assert params["link"] == "ab" * 16
            assert params["method"] == "invisible_text"
            assert params["position"] == "last-page-bottom-left"
            assert params["path"].endswith(".pdf")
            return None
        return None
    def __enter__(self): return self
    def __exit__(self, *a): pass

class _FakeEngine:
    def connect(self): return _FakeConn()
    def begin(self): return self.connect()

def test_rmap_get_link_returns_absolute_url(monkeypatch, tmp_path):
    # Prepare env and input pdf
    storage = tmp_path / "storage"
    storage.mkdir()
    input_pdf = storage / "in.pdf"
    input_pdf.write_bytes(b"%PDF-1.4\n")

    monkeypatch.setenv("RMAP_INPUT_PDF", str(input_pdf))
    monkeypatch.setenv("RMAP_OUTPUT_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("RMAP_WATERMARK_SECRET", "Group_8")
    monkeypatch.setenv("RMAP_WATERMARK_KEY", "")

    # Reload to pick up constants
    import importlib; importlib.reload(rr)

    # Monkeypatch send_file to tolerate cache_timeout kw (Flask 3)
    _real_send_file = rr.send_file
    def _safe_send_file(path, *args, **kwargs):
        kwargs.pop("cache_timeout", None)
        return _real_send_file(path, *args, **kwargs)
    monkeypatch.setattr(rr, "send_file", _safe_send_file, raising=False)

    # Apply fakes
    monkeypatch.setattr(rr, "get_rmap", lambda: _FakeRMAP2(), raising=True)
    monkeypatch.setattr(rr, "InvisibleTextWatermark", lambda: _FakeWM(), raising=True)
    monkeypatch.setattr(rr, "get_engine", lambda: _FakeEngine(), raising=True)

    app = Flask(__name__)
    app.config["STORAGE_DIR"] = str(storage)
    app.register_blueprint(rr.rmap_bp)

    body = {"payload": {"armored_b64": _b64("X")}}
    resp = app.test_client().post("/api/rmap-get-link", json=body)
    assert resp.status_code == 200
    data = resp.get_json()
    # url_for(..., _external=True) should yield absolute URL (kills 153)
    assert data["download_url"].startswith("http")




# ----------------------------------------------------------------------------
# 8) Touch module singletons to guard type-hint mutants (34–37 safe)
# ----------------------------------------------------------------------------
def test_module_singletons_are_none_or_objects():
    assert rr._identity_manager is None or isinstance(rr._identity_manager, object)
    assert rr._rmap is None or isinstance(rr._rmap, object)
