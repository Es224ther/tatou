# xmp_metadata_method.py
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import re
from typing import Optional

from watermarking_method import (
    PdfSource,
    WatermarkingMethod,
    load_pdf_bytes,
)

_TATOU_NS = "http://tatou.example/ns/1.0/"
_TATOU_PREFIX = "tatou"
_TAG_SIG = "wmSig"
_TAG_METH = "wmMethod"
_METHOD_NAME = "xmp-metadata"  # human-readable key exposed to the registry

# Very small, valid XMP packet template (RDF in x:xmpmeta).
# We include our custom namespace and two tags: tatou:wmSig and tatou:wmMethod.
_XMP_TEMPLATE = """<?xpacket begin='﻿' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x='adobe:ns:meta/'>
  <rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'
           xmlns:{prefix}='{ns}'>
    <rdf:Description rdf:about=''>
      <{prefix}:{tag_meth}>{method}</{prefix}:{tag_meth}>
      <{prefix}:{tag_sig}>{sig}</{prefix}:{tag_sig}>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end='w'?>
"""


def _derive_signature(secret: str, key: str) -> str:
    """HMAC-SHA256(secret, key) -> base64url (no padding)."""
    mac = hmac.new(key.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def _build_xmp_packet(sig: str, method_name: str = _METHOD_NAME) -> bytes:
    xml = _XMP_TEMPLATE.format(
        prefix=_TATOU_PREFIX,
        ns=_TATOU_NS,
        tag_meth=_TAG_METH,
        tag_sig=_TAG_SIG,
        method=method_name,
        sig=sig,
    )
    # Encode as UTF-8; XMP packets are generally UTF-8 with optional BOM already handled by xpacket begin
    return xml.encode("utf-8")


def _extract_sig_from_xml(xml: str) -> Optional[str]:
    # Find <tatou:wmSig>...</tatou:wmSig> in a tolerant way
    m = re.search(rf"<{_TATOU_PREFIX}:{_TAG_SIG}>(.*?)</{_TATOU_PREFIX}:{_TAG_SIG}>", xml, flags=re.DOTALL)
    return m.group(1).strip() if m else None


class XmpMetadataMethod(WatermarkingMethod):
    """Embed a watermark in the PDF XMP metadata.

    Preferred path uses PyMuPDF to write a /Metadata XML stream.
    Fallback path appends an XMP packet after EOF (still parsable by many readers).
    """
    name: str = _METHOD_NAME
    description: str = "Embed an authenticated tag (HMAC) inside the PDF XMP metadata."

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        data = load_pdf_bytes(pdf)
        sig = _derive_signature(secret, key)
        xmp = _build_xmp_packet(sig)

        # Try PyMuPDF
        try:
            import fitz  # type: ignore
            doc = fitz.open(stream=data, filetype="pdf")
            set_xml = getattr(doc, "set_xml_metadata", None)
            if callable(set_xml):
                set_xml(xmp.decode("utf-8"))
            else:
                # Older versions: try a known attribute name, otherwise store in Info as weak fallback
                maybe_set = getattr(doc, "metadata_xml", None)
                if callable(maybe_set):
                    maybe_set(xmp.decode("utf-8"))
                else:
                    meta = dict(doc.metadata or {})
                    # Keep keys conservative to avoid readers rejecting the file
                    meta["producer"] = (meta.get("producer") or "") + " Tatou-XMP"
                    meta["keywords"] = f"{_TATOU_PREFIX}:{_TAG_SIG}={sig}"
                    doc.set_metadata(meta)
            out = doc.tobytes()
            doc.close()
            return out
        except Exception:
            pass

        # Fallback: append an XMP packet and allow downstream readers to parse it.
        # Keep original bytes and add a newline before our packet for safety.
        return data + b"\n" + xmp

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Return the original secret is not stored; we verify by signature round-trip.

        Contract in this project: we recover the *secret* via server DB normally.
        Here, we return the base64url HMAC so the caller can map it to the stored record.
        """
        data = load_pdf_bytes(pdf)

        # Try PyMuPDF to fetch XMP
        xml: Optional[str] = None
        try:
            import fitz  # type: ignore
            doc = fitz.open(stream=data, filetype="pdf")
            # Try the modern attribute / method names
            for attr in ("metadata_xmp", "xmp_metadata", "xml_metadata"):
                val = getattr(doc, attr, None)
                if isinstance(val, str) and val.strip():
                    xml = val
                    break
                if callable(val):
                    try:
                        xml_val = val()
                        if isinstance(xml_val, str) and xml_val.strip():
                            xml = xml_val
                            break
                    except Exception:
                        pass
            doc.close()
        except Exception:
            pass

        if xml is None:
            # Fallback: regex scan bytes for our tag
            try:
                xml = data.decode("utf-8", "ignore")
            except Exception:
                xml = ""

        sig = _extract_sig_from_xml(xml) if xml else None
        if not sig:
            raise ValueError("XMP watermark not found")

        # We cannot invert HMAC to get secret; return signature token as the recovered value.
        # Server code should map this token back to 'secret' through its DB (method, sig -> secret).
        return sig

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        # XMP does not depend on page geometry; always applicable
        _ = load_pdf_bytes(pdf)  # trigger any source validation
        return True

    # --- required by WatermarkingMethod ABC ---
    def get_usage(self) -> str:
        """
        Usage/help string for this method. 统一与项目现有 CLI/帮助输出。
       """
        return (
            f"{self.name}: Embed an authenticated token in the PDF XMP metadata.\n"
            "- params: secret(str), key(str), position(optional, ignored by this method)\n"
            "- apply_watermark(...) returns PDF bytes with XMP packet\n"
            "- read_watermark(...) returns a token (e.g., HMAC/base64url) you can map to the stored secret"
        )
