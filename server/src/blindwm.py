from __future__ import annotations
import io, re, hmac, hashlib, datetime as dt
from dataclasses import dataclass
from typing import Tuple, List, Optional
from pathlib import Path

import fitz # PyMuPDF
from PIL import Image
import numpy as np
from blind_watermark import WaterMark


# ============ Basic tools ============

def canonicalize_pdf_text(pdf_path: Path) -> str:
    """Extract text from PDF and standardize it"""
    text_parts: List[str] = []
    with fitz.open(pdf_path) as doc:
        for p in doc:
	    t = p.get_text("text") or ""
            t = re.sub(r"\s+", " ", t).strip()
            if t:
                text_parts.append(t)
    return "\n".join(text_parts)

def hmac_hex(key: bytes, message: str) -> str:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

def _rgb(gray: float) -> Tuple[float, float, float]:
    return (gray, gray, gray)

# ============ PDF ←→ PNG ============

def render_page_to_png(page: fitz.Page, dpi: int = 200) -> bytes:
    """Render the page as PNG bytes (no alpha channel)"""
    zoom = dpi / 72.0
    mat = fitz.Matrix(zoom, zoom)
    pix = page.get_pixmap(matrix=mat, alpha=False)
    return pix.tobytes("png")

def rebuild_pdf_from_images(page_pngs: List[bytes], header: Optional[str], footer: Optionzal[str]) -> bytes:
    """
    Reconstructs a PDF using full-page images and overlays visible headers/footers on top of a PyMuPDF layer.
    """
    out = fitz.open()
    for png in page_pngs:
        img = Image.open(io.BytesIO(png))
        width, height = img.size # pixels
        # Create pages in pixels
        page = out.new_page(-1, width=width, height=height)

        # Picture fills the entire page
        rect = fitz.Rect(0, 0, width, height)
        page.insert_image(rect, stream=png)

        # Draw header/footer (light gray)
        if header:
            page.insert_text((40, 40), header, fontsize=18, color=_rgb(0.3))
        if footer:
            page.insert_text((40, height - 40), footer, fontsize=14, color=_rgb(0.4))
    return out.tobytes()

# ============ BlindWatermark ============

@dataclass
class BlindWMParams:
    password_img: int = 1
    password_wm: int = 1
    dpi: int = 200 # Render DPI
    target_pages: str = "first" # "first" | "all"

@dataclass
class CreateResult:
    output_pdf: Path
    wm_len: int
    doc_hmac: str

WM_PREFIX = "WM:" # Locate secret

def _embed_blind_wm_png(png_bytes: bytes, text_secret: str, pwd_img: int, pwd_wm: int) -> Tuple[bytes, int]:
    """Write blind watermark on a PNG (string mode), returning the new PNG and bit length."""
    bwm = WaterMark(password_img=pwd_img, password_wm=pwd_wm)
    with Image.open(io.BytesIO(png_bytes)) as im:
        bio = io.BytesIO()
        im.save(bio, format="PNG")
        bio.seek(0)
        tmp_in = bio

    import tempfile, os
    with tempfile.TemporaryDirectory() as td:
        in_path = Path(td) / "in.png"
        out_path = Path(td) / "out.png"
        with open(in_path, "wb") as f:
            f.write(png_bytes)
        bwm.read_img(str(in_path))
        bwm.read_wm(text_secret, mode="str")
        bwm.embed(str(out_path))
        wm_len = len(bwm.wm_bit)
        with open(out_path, "rb") as f:
            return f.read(), wm_len
def create_pdf_with_blind_wm(
    input_pdf: Path,
    output_pdf: Path,
    secret_plain: str, # secret
    intended_for: str,
    hmac_key: bytes,
    params: BlindWMParams = BlindWMParams(),
) -> CreateResult:
    """
    1) Extract the original text → Calculate the HMAC (print the footer, optionally include the blind watermark plaintext)
    2) Render the PDF → PNG
    3) Blind watermark the target page PNG (write WM: + secret_plain or HMAC)
    4) Reconstruct the PDF using the watermarked/unmodified PNG and overlay the header/footer
    """
    input_pdf = Path(input_pdf); output_pdf = Path(output_pdf)
    text = canonicalize_pdf_text(input_pdf)
    doc_h = hmac_hex(hmac_key, text)
    header = f"Delivered to {intended_for} • {now_iso()}"
    footer = f"Doc HMAC: {doc_h[:16]}…"

    page_pngs: List[bytes] = []
    wm_len_final: Optional[int] = None

    with fitz.open(input_pdf) as doc:
        for idx, page in enumerate(doc):
            png = render_page_to_png(page, dpi=params.dpi)
            need_wm = (params.target_pages == "all") or (params.target_pages == "first" and idx == 0)
            if need_wm:
                text_secret = f"{WM_PREFIX}{secret_plain}"
                png, wm_len = _embed_blind_wm_png(png, text_secret, params.password_img, params.password_wm)
                wm_len_final = wm_len
            page_pngs.append(png)

    pdf_bytes = rebuild_pdf_from_images(page_pngs, header=header, footer=footer)
    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    with open(output_pdf, "wb") as f:
        f.write(pdf_bytes)

    assert wm_len_final is not None, "No page was watermarked; check params.target_pages"
    return CreateResult(output_pdf=output_pdf, wm_len=wm_len_final, doc_hmac=doc_h)

def extract_blind_wm_from_pdf(
    input_pdf: Path,
    wm_len: int,
    params: BlindWMParams = BlindWMParams(),
) -> Optional[str]:
    """
    Renders a PNG from the first or all pages → Tries to extract the blind watermark (string mode), returning the secret without the prefix.
    Requires the wm_len (or wm_shape) parameter
    """
    with fitz.open(input_pdf) as doc:
        targets = [0] if params.target_pages == "first" else list(range(len(doc)))
        for idx in targets:
            page = doc[idx]
            png = render_page_to_png(page, dpi=params.dpi)
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                in_path = Path(td) / "in.png"
                with open(in_path, "wb") as f:
                    f.write(png)
                bwm = WaterMark(password_img=params.password_img, password_wm=params.password_wm)
                try:
                    wm_text = bwm.extract(str(in_path), wm_shape=wm_len, mode="str")
                except Exception:
                    continue
                if isinstance(wm_text, str) and WM_PREFIX in wm_text:
                    m = re.search(rf"{re.escape(WM_PREFIX)}(.+)", wm_text)
                    if m:
                        return m.group(1)
    return None
