# tests/unit/test_watermarking_method_abc_enforcement.py
import pytest
from watermarking_method import WatermarkingMethod

def test_cannot_instantiate_abstract_class():
    """
    The abstract base class itself must not be instantiable.
    """
    with pytest.raises(TypeError):
        WatermarkingMethod()  # missing abstract methods


def test_missing_one_method_still_abstract():
    """
    A subclass that does not implement ALL required abstract methods
    must remain abstract and fail on instantiation.
    """
    class BadImpl(WatermarkingMethod):
        name = "bad"
        # Implement only some methods to confirm ABC behavior.
        def add_watermark(self, pdf, secret: str, key: str, position=None) -> bytes:
            return b"%PDF-1.4\n% BAD\n%EOF\n"
        # def read_secret(self, pdf, key: str) -> str:   # missing on purpose
        def is_watermark_applicable(self, pdf, position=None) -> bool:
            return True
        def get_usage(self) -> str:
            return "bad impl (incomplete)"

    with pytest.raises(TypeError):
        BadImpl()   # still abstract because read_secret is missing
