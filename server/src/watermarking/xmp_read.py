
"""
Read and verify the XMP watermark stored in a PDF.

- Fields are stored under a custom XMP namespace (NS_URI).
- Integrity is checked with HMAC-SHA256 over a canonical JSON of the record.
- The secret key is taken from env var TATOU_XMP_SECRET (base64 preferred).
"""

import os, sys, json, base64, hashlib, hmac
import pikepdf

# Use the SAME namespace URI as in your writer script.
# A stable, unique URI prevents name collisions in XMP.
NS_URI = "urn:uuid:61d129f9-3270-40fd-b5e7-97d63d6d5866"

# Load secret key from environment (base64 is recommended; plaintext allowed).
SECRET_ENV = os.environ.get("TATOU_XMP_SECRET")
if not SECRET_ENV:
    print("ERROR: please set environment variable TATOU_XMP_SECRET", file=sys.stderr)
    sys.exit(2)
try:
    SECRET = base64.urlsafe_b64decode(SECRET_ENV.encode())
except Exception:
    SECRET = SECRET_ENV.encode()  # fallback: treat as raw bytes (not recommended)

def hmac_sig(payload: dict, secret: bytes) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

def read_xmp(input_pdf: str) -> dict:
    pdf = pikepdf.open(input_pdf)
    try:
        with pdf.open_metadata() as meta:
            meta.register_namespace("tatou", NS_URI)
            get = lambda k: meta.get(f"tatou:{k}")
            record = {
                "versionId": get("versionId"),
                "method":    get("method"),
                "issuer":    get("issuer"),
                "recipient": get("recipient"),
                "issuedAt":  get("issuedAt"),
                "docSha256": get("docSha256"),
            }
            message = get("message")  # may be None for legacy files
            if message is not None:
                record["message"] = message
            sig = get("sig")
    finally:
        pdf.close()

    if not all(v is not None and v != "" for k, v in record.items() if k != "message") or not sig:
        return {"ok": False, "error": "missing-xmp-fields", "record": record}

    # Verify (try with 'message' if present; otherwise without)
    sig_calc = hmac_sig(record, SECRET)
    if sig_calc != sig:
        # Optional fallback: if message exists but signature was made without it (very old writer)
        if "message" in record:
            legacy = {k: v for k, v in record.items() if k != "message"}
            if hmac_sig(legacy, SECRET) == sig:
                return {"ok": True, "record": record, "warning": "legacy-signature-without-message"}
        return {"ok": False, "error": "bad-signature", "record": record}

    return {"ok": True, "record": record}

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: xmp_read.py <pdf>")
        sys.exit(1)
    print(json.dumps(read_xmp(sys.argv[1]), indent=2))
