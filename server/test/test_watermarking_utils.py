# tests/unit/test_watermarking_utils.py
import pytest
from watermarking_method import WatermarkingMethod  # your real abstract base class

# -----------------------------------------------------------------------------
# Dummy watermarking implementation that satisfies the real interface.
# Implement ALL abstract methods so the class can be instantiated.
# -----------------------------------------------------------------------------
class DummyMethod(WatermarkingMethod):
    name = "dummy"

    def add_watermark(self, pdf, secret: str, key: str, position=None) -> bytes:
        # Return minimal "PDF-like" bytes. Enough for dispatcher assertions.
        return b"%PDF-1.4\n% DUMMY WM ADDED\n%EOF\n"

    def read_secret(self, pdf, key: str) -> str:
        # watermarking_utils.read_watermark() calls read_secret()
        return "SECRET_FROM_DUMMY"

    def is_watermark_applicable(self, pdf, position=None) -> bool:
        # Required by the ABC. Keep logic simple for unit tests.
        return True

    def get_usage(self) -> str:
        # Required by the ABC. A simple help/usage string is fine.
        return "Dummy watermark method for tests."


# -----------------------------------------------------------------------------
# Registration & lookup
# -----------------------------------------------------------------------------
def test_register_and_get_method(monkeypatch):
    import watermarking_utils as wm
    # isolate global registry to avoid cross-test pollution
    monkeypatch.setattr(wm, "METHODS", {}, raising=False)

    wm.register_method(DummyMethod())
    m = wm.get_method("dummy")
    assert isinstance(m, DummyMethod)


def test_get_method_with_instance_passthrough():
    """
    If an instance is passed directly, get_method should return it unchanged,
    provided it is an instance of WatermarkingMethod.
    """
    import watermarking_utils as wm
    inst = DummyMethod()
    assert wm.get_method(inst) is inst


def test_get_method_unknown_raises():
    """Unknown method name should raise KeyError with a helpful message."""
    import watermarking_utils as wm
    with pytest.raises(KeyError):
        wm.get_method("no_such_method")


# -----------------------------------------------------------------------------
# Dispatcher: apply / applicable / read
# -----------------------------------------------------------------------------
def test_apply_watermark_delegates_to_method(monkeypatch, dummy_pdf):
    import watermarking_utils as wm
    monkeypatch.setattr(wm, "METHODS", {}, raising=False)
    wm.register_method(DummyMethod())

    out_bytes = wm.apply_watermark(
        "dummy", pdf=str(dummy_pdf), secret="FLAG-123", key="K"
    )
    assert isinstance(out_bytes, (bytes, bytearray))
    assert out_bytes.startswith(b"%PDF-")


def test_is_watermarking_applicable_delegates(monkeypatch, bytes_pdf):
    import watermarking_utils as wm
    monkeypatch.setattr(wm, "METHODS", {}, raising=False)
    wm.register_method(DummyMethod())

    ok = wm.is_watermarking_applicable("dummy", pdf=bytes_pdf, position=None)
    assert ok is True


def test_read_watermark_delegates(monkeypatch, bytes_pdf):
    import watermarking_utils as wm
    monkeypatch.setattr(wm, "METHODS", {}, raising=False)
    wm.register_method(DummyMethod())

    secret = wm.read_watermark("dummy", pdf=bytes_pdf, key="K")
    assert secret == "SECRET_FROM_DUMMY"


# -----------------------------------------------------------------------------
# explore_pdf minimal behavior (structure sanity)
# -----------------------------------------------------------------------------
def test_explore_pdf_returns_tree(bytes_pdf):
    """
    explore_pdf() should return a serializable tree/dict.
    We only assert shallow invariants so this stays a pure unit test.
    """
    import watermarking_utils as wm
    tree = wm.explore_pdf(bytes_pdf)
    assert isinstance(tree, dict)
    # The concrete shape may vary; assert basic keys commonly present.
    assert "id" in tree
    assert "type" in tree
