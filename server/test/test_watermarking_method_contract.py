# tests/unit/test_watermarking_method_contract.py
import io
import pytest
from watermarking_method import WatermarkingMethod

class GoodImpl(WatermarkingMethod):
    """
    Minimal concrete implementation used to validate the interface contract.
    """
    name = "good-dummy"

    # For observability in tests
    def __init__(self):
        self.calls = []

    def add_watermark(self, pdf, secret: str, key: str, position=None) -> bytes:
        self.calls.append(("add_watermark", pdf, secret, key, position))
        # Return PDF-like bytes per the contract
        return b"%PDF-1.4\n% GOOD-DUMMY\n%EOF\n"

    def read_secret(self, pdf, key: str) -> str:
        self.calls.append(("read_secret", pdf, key))
        # Return a string secret per the contract
        return "SECRET_OK"

    def is_watermark_applicable(self, pdf, position=None) -> bool:
        self.calls.append(("is_watermark_applicable", pdf, position))
        # Minimal policy: everything is applicable in this dummy
        return True

    def get_usage(self) -> str:
        self.calls.append(("get_usage",))
        # A non-empty help string per the contract
        return "Usage: good-dummy for tests"

# --- Fixtures for input sources ------------------------------------------------
@pytest.fixture()
def path_pdf(tmp_path):
    p = tmp_path / "demo.pdf"
    p.write_bytes(b"%PDF-1.4\n%EOF\n")
    return p

@pytest.fixture()
def bytes_pdf():
    return io.BytesIO(b"%PDF-1.4\n%EOF\n")

# --- Tests --------------------------------------------------------------------

def test_good_impl_can_instantiate():
    impl = GoodImpl()
    assert isinstance(impl, WatermarkingMethod)

def test_add_watermark_returns_bytes_with_path(path_pdf):
    impl = GoodImpl()
    out = impl.add_watermark(str(path_pdf), secret="FLAG", key="K", position=None)
    assert isinstance(out, (bytes, bytearray))
    assert out.startswith(b"%PDF-")

def test_add_watermark_accepts_filelike(bytes_pdf):
    impl = GoodImpl()
    out = impl.add_watermark(bytes_pdf, secret="S", key="K")
    assert isinstance(out, (bytes, bytearray))

def test_read_secret_returns_str(bytes_pdf):
    impl = GoodImpl()
    secret = impl.read_secret(bytes_pdf, key="K")
    assert isinstance(secret, str)
    assert secret != ""  # non-empty

def test_is_watermark_applicable_returns_bool(bytes_pdf):
    impl = GoodImpl()
    ok = impl.is_watermark_applicable(bytes_pdf, position=None)
    assert isinstance(ok, bool)

def test_get_usage_non_empty():
    impl = GoodImpl()
    usage = impl.get_usage()
    assert isinstance(usage, str) and usage.strip()

def test_methods_receive_arguments(bytes_pdf, path_pdf):
    """
    Sanity: ensure our implementation actually receives the inputs we pass.
    This catches accidental signature mismatch.
    """
    impl = GoodImpl()
    impl.add_watermark(str(path_pdf), "FLAG", "K", position=(10, 20))
    impl.read_secret(bytes_pdf, "K")
    impl.is_watermark_applicable(bytes_pdf, position="top-left")
    impl.get_usage()

    names = [c[0] for c in impl.calls]
    assert names == [
        "add_watermark",
        "read_secret",
        "is_watermark_applicable",
        "get_usage",
    ]
