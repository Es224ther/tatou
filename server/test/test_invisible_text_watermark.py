import fitz  # PyMuPDF
from invisible_text_watermark import InvisibleTextWatermark

def test_invisible_text_watermark_roundtrip():
    # 1) Create a simple one-page PDF in memory
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "This is a test PDF.")
    src_pdf = doc.write()
    doc.close()

    # 2) Apply the watermark
    wm = InvisibleTextWatermark()
    secret = "my_secret_123"
    watermarked_pdf = wm.add_watermark(src_pdf, secret)

    # 3) Read it back
    recovered = wm.read_secret(watermarked_pdf)

    # 4) Verify
    assert recovered == secret, f"Expected {secret}, got {recovered}"
