# tests/watermarking/test_xmp_metadata_method.py
# Goal: cover BOTH code paths of xmp_metadata_method.py in ONE file:
# - "no_fitz" fallback (simulate ImportError for fitz)
# - "with_fitz" primary path (only if PyMuPDF is installed; otherwise auto-skip)

from __future__ import annotations

import base64
import hmac
import hashlib
import io
import sys
from pathlib import Path
import importlib

import pytest

# --- Make server/src importable ---
THIS_FILE = Path(__file__).resolve()
REPO_ROOT = THIS_FILE.parents[2]  # repo/
SRC_DIR = REPO_ROOT / "server" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def _expected_token(secret: str, key: str) -> str:
    # Expected token = HMAC-SHA256(secret, key) -> base64url (no padding)
    mac = hmac.new(key.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


@pytest.fixture(params=["no_fitz", "with_fitz"])
def xmp_module(monkeypatch, request):
    """
    Parametrized fixture that provides the xmp_metadata_method module under
    two environments:
      - "no_fitz": force ImportError for fitz -> fallback path
      - "with_fitz": import PyMuPDF (fitz) if available; skip otherwise
    We reload the module each time so it picks up the current environment.
    """
    mode = request.param
    if mode == "no_fitz":
        # Simulate that PyMuPDF is not installed
        monkeypatch.setitem(sys.modules, "fitz", None)
    else:
        # Require PyMuPDF; auto-skip if missing
        pytest.importorskip("fitz")
        # Ensure a real 'fitz' module is present in sys.modules now

    # Reload SUT so its internal imports reflect the current env
    if "xmp_metadata_method" in sys.modules:
        mod = importlib.reload(sys.modules["xmp_metadata_method"])
    else:
        mod = importlib.import_module("xmp_metadata_method")  # type: ignore
    return mode, mod


@pytest.fixture
def minimal_pdf_bytes(xmp_module) -> bytes:
    """
    Produce a small valid PDF:
    - If fitz is available (mode == "with_fitz"), build via PyMuPDF for realism.
    - Otherwise return a tiny valid-ish PDF byte string.
    """
    mode, _ = xmp_module
    if mode == "with_fitz":
        import fitz  # type: ignore
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "hello XMP")
        data = doc.tobytes()
        doc.close()
        return data
    # Fallback minimal PDF bytes
    return b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


def test_xmp_roundtrip_success(xmp_module, minimal_pdf_bytes):
    mode, xmp = xmp_module
    wm = xmp.XmpMetadataMethod()
    secret = "S3cr3t-中文✓"
    key = "K3y-!@#"

    # Create watermark
    out_bytes = wm.add_watermark(minimal_pdf_bytes, secret=secret, key=key, position=None)
    assert isinstance(out_bytes, (bytes, bytearray))

    # Basic tags should exist even in fallback mode
    assert b"tatou:wmMethod" in out_bytes
    assert b"xmp-metadata" in out_bytes
    assert b"tatou:wmSig" in out_bytes

    # Read back -> HMAC token must match
    token = wm.read_secret(io.BytesIO(out_bytes), key=key)
    assert token == _expected_token(secret, key)

    # Applicability + usage string
    assert wm.is_watermark_applicable(minimal_pdf_bytes) is True
    help_text = wm.get_usage()
    assert xmp.XmpMetadataMethod.name in help_text
    assert "XMP" in help_text


def test_xmp_read_raises_when_absent(xmp_module, minimal_pdf_bytes):
    _, xmp = xmp_module
    wm = xmp.XmpMetadataMethod()
    with pytest.raises(ValueError):
        _ = wm.read_secret(minimal_pdf_bytes, key="whatever")


@pytest.mark.parametrize("weird_secret", ["", " ", "\u200b", "🚀" * 16])
def test_xmp_handles_edge_secrets(xmp_module, minimal_pdf_bytes, weird_secret):
    _, xmp = xmp_module
    wm = xmp.XmpMetadataMethod()
    key = "edge-key"
    out_bytes = wm.add_watermark(minimal_pdf_bytes, secret=weird_secret, key=key)
    token = wm.read_secret(out_bytes, key=key)
    assert token == _expected_token(weird_secret, key)

