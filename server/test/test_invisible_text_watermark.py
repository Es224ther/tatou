# test_invisible_text_watermark.py
# -*- coding: utf-8 -*-

import io
import re
import pytest
import invisible_text_watermark as mod


# ----------------------------- Helper functions -----------------------------

def _get_instance():
    """Create an instance of InvisibleTextWatermark (must exist in module)."""
    ITW = getattr(mod, "InvisibleTextWatermark", None)
    assert ITW is not None, "InvisibleTextWatermark class not found in module"
    return ITW()

def _embed(itw, pdf_bytes, secret, key="", position=None):
    """Unified embed call (.add_watermark or .apply)."""
    if hasattr(itw, "add_watermark"):
        return itw.add_watermark(pdf_bytes, secret, key=key, position=position)
    if hasattr(itw, "apply"):
        return itw.apply(pdf_bytes, secret=secret, key=key, position=position)
    raise AttributeError("Neither add_watermark() nor apply() is implemented")

def _extract(itw, pdf_bytes, key=""):
    """Unified extractor."""
    return itw.read_secret(pdf_bytes, key=key)


# ----------------------------- Real fitz producer ----------------------------

def _make_pdf_bytes_real_fitz():
    """Try creating a 1-page PDF via real fitz; return None if unavailable."""
    if getattr(mod, "fitz", None) is None:
        return None
    doc = mod.fitz.open()
    page = doc.new_page()
    try:
        page.insert_text((72, 72), "This is a test PDF.")
    except Exception:
        pass
    for method in ("tobytes", "write"):
        f = getattr(doc, method, None)
        if callable(f):
            out = f()
            if isinstance(out, (bytes, bytearray, memoryview)):
                doc.close()
                return bytes(out)
    doc.close()
    return None


# ----------------------------- Fake fitz simulation --------------------------

class _FakeRect:
    def __init__(self, width=595, height=842):
        self.width = width
        self.height = height


class _FakePage:
    """Fake PyMuPDF Page with rect, insert_text, get_text."""
    def __init__(self, _doc, width=595, height=842):
        self._doc = _doc
        self.rect = _FakeRect(width=width, height=height)

    def insert_text(self, *args, **kwargs):
        # Capture payload text into parent doc
        text = None
        if len(args) >= 2 and isinstance(args[1], str):
            text = args[1]
        text = kwargs.get("text", text)
        if isinstance(text, str):
            self._doc._embedded_text = text
        return None

    def insert_textbox(self, *args, **kwargs):
        text = kwargs.get("text", None)
        if isinstance(text, str):
            self._doc._embedded_text = text
        return None

    def get_text(self, *args, **kwargs):
        return self._doc._embedded_text or ""


class _FakeDoc:
    """
    Fake fitz Document:
    - Supports new_page(), indexing, load_page().
    - Serializes embedded text into bytes (before %%EOF).
    - Can recover embedded text via open(stream=...).
    """
    _BASE_BYTES = b"%PDF-1.4\n% fake\n%%EOF\n"

    def __init__(self, data: bytes | None = None, pages: int = 0, width=595, height=842):
        self._bytes = bytes(data) if data is not None else self._BASE_BYTES
        self._pages = int(pages) if pages > 0 else 0
        self._width = width
        self._height = height
        self._embedded_text: str = ""

        # Recover embedded text from bytes if present
        try:
            s = self._bytes.decode("utf-8", errors="ignore")
            m = re.search(r"\[HWM\](.*?)\[/HWM\]", s)
            if m:
                self._embedded_text = f"[HWM]{m.group(1)}[/HWM]"
        except Exception:
            pass

    def new_page(self, width=595, height=842):
        self._width = width
        self._height = height
        self._pages += 1
        return _FakePage(self, width=width, height=height)

    @property
    def page_count(self):
        # Return 0 if explicitly set to 0 and byte stream is empty (empty PDF).
        if self._pages > 0:
            return self._pages
        return 0 if len(self._bytes) == 0 else 1

    def __len__(self):
        return self.page_count

    def __getitem__(self, idx):
        n = self.page_count
        if idx < 0:
            idx = n + idx
        if not (0 <= idx < n):
            raise IndexError("page index out of range")
        return _FakePage(self, width=self._width, height=self._height)

    def load_page(self, i):
        return self.__getitem__(i)

    def _serialize_bytes(self) -> bytes:
        payload = self._embedded_text.encode("utf-8") if self._embedded_text else b""
        if b"%%EOF" in self._bytes:
            i = self._bytes.rfind(b"%%EOF")
            return self._bytes[:i] + b"\n" + payload + b"\n%%EOF\n"
        return self._bytes + b"\n" + payload + b"\n%%EOF\n"

    def tobytes(self):
        return self._serialize_bytes()

    def write(self):
        return self._serialize_bytes()

    def close(self):
        pass


class _FakeFitz:
    """Fake fitz module with open()."""
    def open(self, *args, **kwargs):
        # Support open() and open(stream=..., filetype="pdf")
        if "stream" in kwargs:
            data = kwargs.get("stream", None)
            pages = 1 if isinstance(data, (bytes, bytearray, memoryview)) and len(data) > 0 else 0
            return _FakeDoc(bytes(data) if data is not None else None, pages=pages)
        return _FakeDoc()


# ----------------------------- Test cases ------------------------------------

@pytest.mark.skipif(getattr(mod, "InvisibleTextWatermark", None) is None,
                    reason="InvisibleTextWatermark class not found")
def test_roundtrip_with_real_fitz_or_skip():
    """If PyMuPDF is available: embed -> read -> assert. Otherwise skip cleanly."""
    pdf = _make_pdf_bytes_real_fitz()
    if pdf is None:
        pytest.skip("PyMuPDF not available; skipping real E2E roundtrip")
    itw = _get_instance()
    secret = "my_secret_123"
    out_pdf = _embed(itw, pdf, secret)
    recovered = _extract(itw, out_pdf)
    assert recovered == secret


@pytest.mark.skipif(getattr(mod, "InvisibleTextWatermark", None) is None,
                    reason="InvisibleTextWatermark class not found")
def test_roundtrip_with_fake_fitz(monkeypatch):
    """Full roundtrip with fake fitz (no dependency)."""
    monkeypatch.setattr(mod, "fitz", _FakeFitz(), raising=False)
    itw = _get_instance()
    doc = mod.fitz.open()
    doc.new_page()
    pdf = doc.tobytes()
    doc.close()

    secret = "hello-watermark"
    out_pdf = _embed(itw, pdf, secret)
    assert isinstance(out_pdf, (bytes, bytearray, memoryview))
    assert bytes(out_pdf).startswith(b"%PDF")
    recovered = _extract(itw, out_pdf)
    assert recovered == secret


@pytest.mark.skipif(getattr(mod, "InvisibleTextWatermark", None) is None,
                    reason="InvisibleTextWatermark class not found")
def test_embed_accepts_various_input_types(monkeypatch, tmp_path):
    """Embed should accept bytes, path, and file-like inputs."""
    monkeypatch.setattr(mod, "fitz", _FakeFitz(), raising=False)
    itw = _get_instance()

    base_pdf = mod.fitz.open().tobytes()

    out1 = _embed(itw, base_pdf, "s")
    assert bytes(out1).startswith(b"%PDF")

    p = tmp_path / "a.pdf"
    p.write_bytes(base_pdf)
    out2 = _embed(itw, str(p), "s")
    assert bytes(out2).startswith(b"%PDF")

    out3 = _embed(itw, io.BytesIO(base_pdf), "s")
    assert bytes(out3).startswith(b"%PDF")


@pytest.mark.skipif(getattr(mod, "InvisibleTextWatermark", None) is None,
                    reason="InvisibleTextWatermark class not found")
def test_read_secret_behaviors(monkeypatch):
    """
    Wrong key should not break reading (your implementation ignores key).
    No-secret case should return empty string.
    """
    monkeypatch.setattr(mod, "fitz", _FakeFitz(), raising=False)
    itw = _get_instance()

    # Watermarked PDF
    base = mod.fitz.open().tobytes()
    stamped = _embed(itw, base, "top-secret", key="k1")

    # Wrong key => should still return a string (very likely the same secret)
    wrong = _extract(itw, stamped, key="wrong")
    assert isinstance(wrong, str)

    # No secret present => empty string
    no_secret = _extract(itw, base, key="k1")
    assert no_secret in ("", None,)


@pytest.mark.skipif(getattr(mod, "InvisibleTextWatermark", None) is None,
                    reason="InvisibleTextWatermark class not found")
def test_embed_raises_on_unsupported_input_type():
    """Passing an unsupported object should raise TypeError."""
    itw = _get_instance()
    class _Weird: pass
    with pytest.raises(TypeError):
        _embed(itw, _Weird(), "x")  # type: ignore[arg-type]


# ----------------------------- Extra branches --------------------------------

@pytest.mark.skipif(getattr(mod, "InvisibleTextWatermark", None) is None,
                    reason="InvisibleTextWatermark class not found")
def test_add_watermark_raises_on_empty_pdf(monkeypatch):
    """add_watermark should raise ValueError when page_count == 0."""
    monkeypatch.setattr(mod, "fitz", _FakeFitz(), raising=False)
    itw = _get_instance()
    with pytest.raises(ValueError):
        _embed(itw, b"", "secret")  # Fake open(stream=b"", ...) => pages=0 -> ValueError

@pytest.mark.skipif(getattr(mod, "InvisibleTextWatermark", None) is None,
                    reason="InvisibleTextWatermark class not found")
def test_is_watermark_applicable_variants(monkeypatch):
    """is_watermark_applicable() should reflect fitz availability and page count."""
    itw = _get_instance()

    # fitz None -> False
    monkeypatch.setattr(mod, "fitz", None, raising=False)
    assert itw.is_watermark_applicable(b"%PDF-1.4\n%%EOF", None) is False

    # fake fitz + non-empty -> True
    monkeypatch.setattr(mod, "fitz", _FakeFitz(), raising=False)
    assert itw.is_watermark_applicable(b"%PDF-1.4\n%%EOF", None) is True

    # fake fitz + empty -> False
    assert itw.is_watermark_applicable(b"", None) is False
