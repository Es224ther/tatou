# rmap_route.py
from __future__ import annotations

from flask import Blueprint, request, jsonify, url_for, current_app, send_file
from sqlalchemy import create_engine, text
from pathlib import Path
import os, time, re, json, base64, binascii
from typing import Dict, Any

# RMAP (installed package)
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP

# Your watermarking helper
from invisible_text_watermark import InvisibleTextWatermark


# ============================================================================
# Helpers
# ============================================================================

def _expand(p: str | None) -> str | None:
    """Expand '~' and env vars safely; return None if input is None."""
    if p is None:
        return None
    return os.path.expandvars(os.path.expanduser(p))

def _require_file(path: str | None, label: str) -> None:
    """Raise a clear error if a required file is missing."""
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(f"{label} not found at: {path}")


# ============================================================================
# Configuration via environment variables
# (use container-internal, absolute paths; do NOT leak secrets)
# ============================================================================

RMAP_CLIENT_KEYS_DIR = _expand(os.getenv("RMAP_CLIENT_KEYS_DIR", "/home/lab/tatou/deploy/secrets/clients"))
RMAP_SERVER_PRIVATE  = _expand(os.getenv("RMAP_SERVER_PRIVATE",  "/home/lab/tatou/deploy/secrets/server/server_priv.asc"))
RMAP_SERVER_PUBLIC   = _expand(os.getenv("RMAP_SERVER_PUBLIC",   "/home/lab/tatou/deploy/secrets/server/server_pub.asc"))

# Source PDF to watermark (first version relies on a single env; you can DB-lookup later)
RMAP_INPUT_PDF  = _expand(os.getenv("RMAP_INPUT_PDF"))

# Temporary output directory for intermediate results
OUTPUT_DIR = _expand(os.getenv("RMAP_OUTPUT_DIR", "static/watermarked"))
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================================
# Lazy RMAP wiring (avoid import-time crashes)
# ============================================================================

_identity_manager: IdentityManager | None = None
_rmap: RMAP | None = None

def get_identity_manager() -> IdentityManager:
    """Create once, on first use. Matches rmap==2.0.0 signature."""
    global _identity_manager
    if _identity_manager is None:
        # Validate paths lazily (import-time validation makes pytest/app boot fragile)
        if RMAP_CLIENT_KEYS_DIR is None or not os.path.isdir(RMAP_CLIENT_KEYS_DIR):
            raise RuntimeError(f"RMAP_CLIENT_KEYS_DIR not found: {RMAP_CLIENT_KEYS_DIR}")
        _require_file(RMAP_SERVER_PRIVATE, "RMAP_SERVER_PRIVATE")
        _require_file(RMAP_SERVER_PUBLIC,  "RMAP_SERVER_PUBLIC")

        _identity_manager = IdentityManager(
            client_keys_dir=RMAP_CLIENT_KEYS_DIR,
            server_public_key_path=RMAP_SERVER_PUBLIC,
            server_private_key_path=RMAP_SERVER_PRIVATE,
            server_private_key_passphrase=os.getenv("RMAP_SERVER_PRIVATE_PASSPHRASE"),
        )
    return _identity_manager

def get_rmap() -> RMAP:
    global _rmap
    if _rmap is None:
        _rmap = RMAP(get_identity_manager())
    return _rmap


# ============================================================================
# DB helpers
# ============================================================================

def _db_url_from_config() -> str:
    c = current_app.config
    return (
        f"mysql+pymysql://{c['DB_USER']}:{c['DB_PASSWORD']}"
        f"@{c['DB_HOST']}:{c['DB_PORT']}/{c['DB_NAME']}?charset=utf8mb4"
    )

def get_engine():
    eng = current_app.config.get("_ENGINE")
    if eng is None:
        eng = create_engine(_db_url_from_config(), pool_pre_ping=True, future=True)
        current_app.config["_ENGINE"] = eng
    return eng


# ============================================================================
# Watermark helpers
# ============================================================================

def resolve_input_pdf(identity: str) -> str:
    """
    Decide which source PDF to watermark for a given authenticated identity.
    First version: rely on env var RMAP_INPUT_PDF.
    Later: replace with DB lookup (e.g., latest document for this user).
    """
    if not RMAP_INPUT_PDF:
        raise RuntimeError(
            "RMAP_INPUT_PDF is not set. Please set it to an absolute path like:\n"
            "  /app/storage/files/Mr_Important/20250926T172119159244Z__Group_8.pdf"
        )
    _require_file(RMAP_INPUT_PDF, "RMAP_INPUT_PDF")
    return RMAP_INPUT_PDF

def build_invisible_text_watermarker(identity: str) -> InvisibleTextWatermark:
    """
    Build the watermark object. This implementation takes no ctor args.
    We still keep env values to pass as call-time parameters.
    """
    return InvisibleTextWatermark()

# ============================================================================
# Payload normalization for RMAP endpoints
# ============================================================================

def _extract_payload_as_json(req) -> Dict[str, str]:
    """
    Normalize inbound payload for RMAP.

    Accepted formats:
      - JSON or form data containing one of:
          * armor_body          : ASCII-armored PGP text (-----BEGIN PGP MESSAGE----- ...)
          * armored_b64         : base64(ASCII-armored PGP text)
          * armor_body_b64      : alias of armored_b64
          * payload / message1  : may contain the above as a dict or string
      - text/plain              : entire body is treated as armor_body

    Returns:
        dict with exactly one of {'armor_body', 'armored_b64'}.
    """
    PRIMARY_KEYS = ("armor_body", "armored_b64", "armor_body_b64")
    WRAPPER_KEYS = ("payload", "message1", "data", "m1")

    # 1) JSON body
    data = req.get_json(silent=True)
    if isinstance(data, dict) and data:
        # Unwrap common wrapper keys
        for wk in WRAPPER_KEYS:
            if wk in data and data[wk]:
                inner = data[wk]
                if isinstance(inner, dict):
                    data = inner
                else:
                    s = inner.decode("ascii", errors="ignore") if isinstance(inner, (bytes, bytearray)) else str(inner)
                    s = s.strip()
                    if s.startswith("-----BEGIN PGP MESSAGE-----"):
                        return {"armor_body": s}
                    return {"armored_b64": s}

        # Top-level keys
        for k in PRIMARY_KEYS:
            if k in data and data[k]:
                val = data[k]
                if isinstance(val, (bytes, bytearray)):
                    val = val.decode("ascii", errors="ignore")
                if k == "armor_body_b64":
                    return {"armored_b64": val}
                return {k: val}

    # 2) Form data
    form = {}
    try:
        form = req.form.to_dict(flat=True)
    except Exception:
        pass
    if form:
        for k in PRIMARY_KEYS + WRAPPER_KEYS:
            if k in form and form[k]:
                v = form[k]
                if isinstance(v, (bytes, bytearray)):
                    v = v.decode("ascii", errors="ignore")
                v = v.strip()
                if k in PRIMARY_KEYS:
                    if k == "armor_body_b64":
                        return {"armored_b64": v}
                    return {k: v}
                else:
                    if v.startswith("-----BEGIN PGP MESSAGE-----"):
                        return {"armor_body": v}
                    return {"armored_b64": v}

    # 3) text/plain body
    raw = req.get_data(as_text=False) or b""
    if raw:
        txt = raw.decode("ascii", errors="ignore").strip()
        if txt.startswith("-----BEGIN PGP MESSAGE-----"):
            return {"armor_body": txt}
        if txt:
            return {"armored_b64": txt}

    raise KeyError(
        "Missing armor payload. Provide one of: armor_body / armored_b64 / armor_body_b64 "
        "or wrap it inside 'payload' / 'message1'."
    )

def _build_payload_for_rmap(req) -> Dict[str, str]:
    """
    Return {"payload": <non-empty base64 string>} for the RMAP handlers.
    """
    parsed = _extract_payload_as_json(req)

    if parsed.get("armored_b64"):
        s = parsed["armored_b64"]

    elif parsed.get("armor_body"):
        armor = parsed["armor_body"]
        armor = armor.decode("ascii", errors="ignore") if isinstance(armor, (bytes, bytearray)) else armor
        armor = armor.strip()
        # If it's ASCII-armored, encode it once to base64; otherwise assume it's already base64.
        s = base64.b64encode(armor.encode("ascii")).decode("ascii") if armor.startswith("-----BEGIN PGP MESSAGE-----") else armor

    elif parsed.get("payload"):
        inner = parsed["payload"]
        if isinstance(inner, dict):
            if inner.get("armored_b64"):
                s = inner["armored_b64"]
            elif inner.get("armor_body"):
                armor = inner["armor_body"]
                armor = armor.decode("ascii", errors="ignore") if isinstance(armor, (bytes, bytearray)) else armor
                armor = armor.strip()
                s = base64.b64encode(armor.encode("ascii")).decode("ascii") if armor.startswith("-----BEGIN PGP MESSAGE-----") else armor
            else:
                raise ValueError("payload dict missing 'armored_b64' or 'armor_body'")
        elif isinstance(inner, (str, bytes, bytearray)):
            s = inner.decode("ascii", errors="ignore") if not isinstance(inner, str) else inner
        else:
            raise ValueError("payload must be string or dict")

    else:
        raise ValueError("no armor_body / armored_b64 / payload in request")

    # Normalize whitespace and validate base64 strictly
    s = re.sub(r"\s+", "", s.strip())
    if not s:
        raise ValueError("payload is empty after normalization")
    try:
        decoded = base64.b64decode(s, validate=True)
        if not decoded:
            raise ValueError("payload decodes to empty bytes")
    except (binascii.Error, ValueError) as e:
        head = s[:64]
        raise ValueError(f"invalid base64: {e}; head='{head}', len={len(s)}")

    return {"payload": s}


# ============================================================================
# Flask blueprint and routes
# ============================================================================

rmap_bp = Blueprint("rmap", __name__)

@rmap_bp.route("/api/rmap-initiate", methods=["POST"])
def rmap_initiate():
    """
    Accept RMAP Message 1 and return Response 1.
    Contract (rmap v2.0.0):
      - Input : {"payload": "<base64(ASCII-armored PGP)>"}
      - Output: {"payload": "<base64(...)>"} (encrypted to identity)
    """
    try:
        payload_for_rmap = _build_payload_for_rmap(request)
        resp = get_rmap().handle_message1(payload_for_rmap)
        if not isinstance(resp, dict) or "payload" not in resp:
            return jsonify({"error": f"handle_message1 unexpected output: {resp}"}), 500
        return jsonify(resp), 200
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": f"rmap-initiate failed: {e}"}), 400


@rmap_bp.route("/api/rmap-get-link", methods=["POST"])
def rmap_get_link():
    """
    Accept RMAP Message 2 (encrypted to server). On success RMAP returns:
        {"result": "<32-hex>"}
    We then:
      1) generate a watermarked PDF using InvisibleTextWatermark.add_watermark(...) -> bytes
      2) record a row in Versions
      3) return {"result": token, "download_url": ".../api/get-version/<token>"}
    """
    try:
        # 1) Normalize input → {"payload": "<base64>"}
        payload_for_rmap = _build_payload_for_rmap(request)

        # 2) Verify with RMAP and get the session token
        resp = get_rmap().handle_message2(payload_for_rmap)  # -> {"result": "<32-hex>"} or {"error": "..."}
        if not isinstance(resp, dict) or "result" not in resp:
            return jsonify(resp), 400

        token = str(resp["result"]).lower()
        if not re.fullmatch(r"[0-9a-f]{32}", token):
            return jsonify({"error": f"Invalid RMAP token: {token}"}), 500

        # 3) Build a watermarked PDF (your class returns bytes)
        input_pdf = resolve_input_pdf(identity=os.getenv("RMAP_WATERMARK_SECRET", "Group_8"))
        out_basename = f"{token}_{int(time.time())}.pdf"
        output_pdf = os.path.join(OUTPUT_DIR, out_basename)

        # Your watermark class: ctor takes no args; add_watermark returns bytes
        wm = InvisibleTextWatermark()
        secret_text = os.getenv("RMAP_WATERMARK_SECRET", token)  # unique per session (fallback to token)
        watermarked_bytes = wm.add_watermark(
            input_pdf,
            secret=secret_text,
            key=os.getenv("RMAP_WATERMARK_KEY", "") or "",
            position=os.getenv("RMAP_WATERMARK_POSITION", "last-page-bottom-left"),
        )

        # Write bytes to the temp output directory
        Path(output_pdf).write_bytes(watermarked_bytes)

        # 4) Move the file under STORAGE_DIR/.../watermarks (consistent with your app)
        storage_root = Path(current_app.config["STORAGE_DIR"]).resolve()
        src_fp = Path(input_pdf).resolve()
        dest_dir = src_fp.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)
        final_path = dest_dir / out_basename

        try:
            Path(output_pdf).replace(final_path)
        except Exception:
            file_bytes = Path(output_pdf).read_bytes()
            final_path.write_bytes(file_bytes)
            Path(output_pdf).unlink(missing_ok=True)

        # Safety: ensure result stays inside STORAGE_DIR (no path traversal)
        try:
            final_path.resolve().relative_to(storage_root)
        except Exception:
            return jsonify({"error": "watermarked path escapes STORAGE_DIR"}), 500

        # 5) Record metadata in DB (same schema as server.py)
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id FROM Documents WHERE path = :p LIMIT 1"),
                    {"p": str(src_fp)},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {e}"}), 503

        if not row:
            return jsonify({"error": "Document not found in DB for given input_pdf"}), 404

        document_id = int(row.id)
        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions
                        (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": document_id,
                        "link": token,                  # exact <32-hex> from RMAP
                        "intended_for": "RMAP",         # replace with real identity if you track it
                        "secret": secret_text,          # store for audit
                        "method": "invisible_text",
                        "position": "last-page-bottom-left",
                        "path": str(final_path),
                    },
                )
        except Exception as e:
            try:
                final_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        # 6) Build clickable URL for the client
        download_url = url_for("rmap.get_version", token=token, _external=True)
        return jsonify({"result": token, "download_url": download_url}), 200

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": f"rmap-get-link failed: {e}"}), 400



@rmap_bp.route("/api/get-version/<token>", methods=["GET"])
def get_version(token: str):
    """
    Given a 32-hex token, fetch the watermarked PDF path from DB and stream it.
    This is what makes the 'click-to-download' link work for the client.
    """
    if not re.fullmatch(r"[0-9a-f]{32}", token or ""):
        return jsonify({"error": "invalid token"}), 400

    try:
        with get_engine().connect() as conn:
            row = conn.execute(
                text("SELECT path FROM Versions WHERE link = :t LIMIT 1"),
                {"t": token},
            ).first()
        if not row:
            return jsonify({"error": "not found"}), 404

        final_path = Path(row.path).resolve()
        storage_root = Path(current_app.config["STORAGE_DIR"]).resolve()
        final_path.relative_to(storage_root)  # raises if outside STORAGE_DIR

        return send_file(
            final_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"watermarked-{token}.pdf",
            cache_timeout=0,
        )
    except Exception as e:
        return jsonify({"error": f"get-version failed: {e}"}), 400