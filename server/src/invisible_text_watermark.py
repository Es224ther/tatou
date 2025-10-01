# invisible_text_watermark.py
from __future__ import annotations

from typing import Optional, Union
import io

from watermarking_method import WatermarkingMethod

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

PdfLike = Union[bytes, bytearray, memoryview, str]  # bytes/path
PREFIX = "[HWM]"   # Prefix to mark the beginning of the hidden watermark
SUFFIX = "[/HWM]"  # Suffix to mark the end of the hidden watermark


def _read_all(pdf: PdfLike) -> bytes:
    """
    Normalize various PDF sources to raw bytes.

    Supports:
      - bytes / bytearray / memoryview
      - str path to a local file
      - file-like objects with .read()
    """
    if isinstance(pdf, (bytes, bytearray, memoryview)):
        return bytes(pdf)
    if isinstance(pdf, str):
        with open(pdf, "rb") as f:
            return f.read()
    read = getattr(pdf, "read", None)
    if callable(read):
        data = read()
        return bytes(data)
    raise TypeError(f"Unsupported PDF source type: {type(pdf)!r}")


class InvisibleTextWatermark(WatermarkingMethod):
    """
    Insert an invisible text watermark on the last page of a PDF.

    The secret is embedded as white text (on white background, visually invisible),
    wrapped by a fixed prefix/suffix so it can be reliably located and extracted.
    """
    name = "invisible_text"
    description = "Invisible text on last page (white text, prefixed/suffixed for extraction)."

    # ---- Required by watermarking_utils.apply_watermark() ----
    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str = "",
        position: Optional[str] = None,
        **kwargs,
    ) -> bytes:
        """
        Apply the invisible watermark and return new PDF bytes.
        """
        if fitz is None:
            raise RuntimeError("PyMuPDF (fitz) is required for InvisibleTextWatermark.")

        pdf_bytes = _read_all(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        if doc.page_count == 0:
            doc.close()
            raise ValueError("Empty PDF: no pages to watermark.")

        page = doc[-1]  # last page
        payload = f"{PREFIX}{secret}{SUFFIX}"

        # Place near bottom-left; white color makes it essentially invisible on white background.
        x = 36
        y = page.rect.height - 36
        page.insert_text(
            (x, y),
            payload,
            fontsize=6,
            color=(1, 1, 1),  # white text; no opacity arg (not supported in your PyMuPDF version)
        )

        out = io.BytesIO()
        out.write(doc.write())
        doc.close()
        return out.getvalue()

    # ---- Required by watermarking_utils.read_watermark() ----
    def read_secret(self, pdf, key: str = "", **kwargs) -> str:
        """
        Extract the embedded secret. Returns empty string if not found.
        """
        if fitz is None:
            raise RuntimeError("PyMuPDF (fitz) is required for InvisibleTextWatermark.")

        pdf_bytes = _read_all(pdf)
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        if doc.page_count == 0:
            doc.close()
            return ""

        text = doc[-1].get_text() or ""
        doc.close()

        start = text.find(PREFIX)
        if start < 0:
            return ""
        end = text.find(SUFFIX, start + len(PREFIX))
        if end <= start:
            return ""
        return text[start + len(PREFIX): end]

    # ---- Required by watermarking_utils.is_watermark_applicable() ----
    def is_watermark_applicable(self, pdf, position: Optional[str] = None, **kwargs) -> bool:
        """
        Returns True if the method can be applied to the given PDF (must have >= 1 page).
        """
        try:
            if fitz is None:
                return False
            pdf_bytes = _read_all(pdf)
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            ok = doc.page_count > 0
            doc.close()
            return ok
        except Exception:
            return False

    def get_usage(self):
        """
        Describe how to call this watermarking method via the API/UI.
        """
        return {
            "name": self.name,
            "description": self.description,
            "params": {
                "secret": {
                    "type": "string",
                    "required": True,
                    "description": "Secret to embed (wrapped by prefix/suffix).",
                },
                "key": {
                    "type": "string",
                    "required": False,
                    "description": "Unused for this method.",
                },
                "position": {
                    "type": "string",
                    "required": False,
                    "default": "last-page-bottom-left",
                    "description": "Ignored; watermark is placed on the last page bottom-left.",
                },
            },
        }
