import os, sys, json, uuid, hashlib, hmac, base64, datetime
import pikepdf

# 1) Read the server secret from env var TATOU_XMP_SECRET
SECRET_ENV = os.environ.get("TATOU_XMP_SECRET")
if not SECRET_ENV:
    print("ERROR: please set environment variable TATOU_XMP_SECRET", file=sys.stderr)
    sys.exit(2)
try:
    # Try to treat the secret as base64 (recommended)
    SECRET = base64.urlsafe_b64decode(SECRET_ENV.encode())
except Exception:
    # Also allow plain-text secret (not recommended)
    SECRET = SECRET_ENV.encode()

# Custom XMP namespace (use your own URI)
NS_URI = "urn:uuid:61d129f9-3270-40fd-b5e7-97d63d6d5866"


def hmac_sig(payload: dict, secret: bytes) -> str:
    """Deterministic signature: canonical JSON (sorted, compact) + HMAC-SHA256 hex."""
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()

def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""):
            h.update(chunk)
    return h.hexdigest()

def write_xmp(input_pdf: str, output_pdf: str, issuer: str, recipient: str, message: str|None):
    # Build record
    record = {
        "versionId": str(uuid.uuid4()),
        "method": "xmp",
        "issuer": issuer,
        "recipient": recipient,
        "issuedAt": datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z",
        "docSha256": file_sha256(input_pdf),
    }
    # Optional user-defined text
    if message:
        record["message"] = message  # ← your custom watermark text

    # Sign all present fields
    record["sig"] = hmac_sig(record, SECRET)

    # Write XMP
    pdf = pikepdf.open(input_pdf)
    with pdf.open_metadata(set_pikepdf_as_editor=False) as meta:
        meta.register_namespace("tatou", NS_URI)
        for k, v in record.items():
            meta[f"tatou:{k}"] = v
        meta["xmp:CreatorTool"] = "Tatou-XMP"
        meta["pdf:Producer"] = "Tatou-XMP"

    # Backup in /Info (optional, helps survive some re-exports)
    di = pdf.docinfo
    di["/TatouVersionId"] = record["versionId"]
    di["/TatouSig"] = record["sig"]
    di["/TatouMethod"] = "xmp"
    di["/TatouRecipient"] = recipient
    di["/TatouIssuer"] = issuer
    if message:
        di["/TatouMessage"] = message

    pdf.save(output_pdf)
    pdf.close()

    print("OK: watermarked to", output_pdf)
    print(json.dumps(record, indent=2))

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: xmp_watermark.py <input.pdf> <output.pdf> <issuer> <recipient> [message...]")
        sys.exit(1)
    inp, outp, issuer, recipient = sys.argv[1:5]
    message = " ".join(sys.argv[5:]) if len(sys.argv) > 5 else None
    write_xmp(inp, outp, issuer, recipient, message)