from __future__ import annotations
from typing import Final
import io
import pikepdf

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    SecretNotFoundError,
    load_pdf_bytes
)


class EmbedAttachment(WatermarkingMethod):
    """Embed a secret as a PDF file attachment.

    - Secret can be a small string or token.
    - Stored as a hidden file attachment; does not affect page rendering.
    - Extraction is deterministic and simple.
    """
    name: Final[str] = "embed-attachment"

    @staticmethod
    def get_usage() -> str:
        return "Embed a secret as a hidden PDF attachment. Provide secret as text; position is ignored."

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        if not secret:
            raise ValueError("Secret must be non-empty")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be non-empty")

        data = load_pdf_bytes(pdf)
        out_bytes = io.BytesIO()
        with pikepdf.open(io.BytesIO(data)) as pdf_obj:
            filename = f"secret_{key}.txt"
            payload_bytes = secret.encode("utf-8")
            pdf_obj.attachments[filename] = payload_bytes
            pdf_obj.save(out_bytes)
        return out_bytes.getvalue()

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        # Always applicable
        return True

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        with pikepdf.open(io.BytesIO(data)) as pdf_obj:
            filename = f"secret_{key}.txt"
            if filename not in pdf_obj.attachments:
                raise SecretNotFoundError(f"No attachment for key '{key}'")
            attached = pdf_obj.attachments[filename]
            payload_bytes = attached.get_file()  # 获取附件原始内容
            return payload_bytes.decode("utf-8")


__all__ = ["EmbedAttachment"]
