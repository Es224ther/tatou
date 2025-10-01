from flask import Blueprint, request, jsonify, url_for, current_app
from sqlalchemy import create_engine, text
from pathlib import Path
from rmap.identity_manager import IdentityManager
from rmap.rmap import RMAP
from watermarking_utils import InvisibleTextWatermark
import secrets, hashlib
import os
import base64
import time


# -------- Helpers --------

def _expand(p: str | None) -> str | None:
    """Expand '~' and env vars safely; return None if input is None."""
    if p is None:
        return None
    return os.path.expandvars(os.path.expanduser(p))

def _require_file(path: str, label: str) -> None:
    """Raise a clear error if a required file is missing."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"{label} not found at: {path}")

# -------- Configuration via environment variables --------
# Tip: set these in your .env (never commit private keys)
#   RMAP_CLIENT_KEYS_DIR=/absolute/or/~/path/to/clients
#   RMAP_SERVER_PRIVATE=/absolute/or/~/path/to/server_priv.asc
#   RMAP_SERVER_PUBLIC=/absolute/or/~/path/to/server_pub.asc
#   RMAP_INPUT_PDF=/app/storage/files/Mr_Important/20250926T172119159244Z__Group_8.pdf

RMAP_CLIENT_KEYS_DIR = _expand(os.getenv("RMAP_CLIENT_KEYS_DIR", "/home/lab/tatou/deploy/secrets/clients"))
RMAP_SERVER_PRIVATE  = _expand(os.getenv("RMAP_SERVER_PRIVATE",  "/home/lab/tatou/deploy/secrets/server/server_priv.asc"))
RMAP_SERVER_PUBLIC   = _expand(os.getenv("RMAP_SERVER_PUBLIC",   "/home/lab/tatou/deploy/secrets/server/server_pub.asc"))

# Input PDF to watermark (for now use an env var; later you can DB-lookup)
RMAP_INPUT_PDF  = _expand(os.getenv("RMAP_INPUT_PDF"))

# Output directory for generated watermarked PDFs
OUTPUT_DIR = _expand(os.getenv("RMAP_OUTPUT_DIR", "static/watermarked"))
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Basic sanity checks (fail fast with clear messages at app start)
if RMAP_CLIENT_KEYS_DIR is None or not os.path.isdir(RMAP_CLIENT_KEYS_DIR):
    raise RuntimeError(f"RMAP_CLIENT_KEYS_DIR not found: {RMAP_CLIENT_KEYS_DIR}")
_require_file(RMAP_SERVER_PRIVATE, "RMAP_SERVER_PRIVATE")
_require_file(RMAP_SERVER_PUBLIC,  "RMAP_SERVER_PUBLIC")

# -------- RMAP wiring --------
identity_manager = IdentityManager(
    RMAP_CLIENT_KEYS_DIR,
    RMAP_SERVER_PRIVATE,
    RMAP_SERVER_PUBLIC
)
rmap = RMAP(identity_manager)

# In-memory session store (nonce tracking). Prefer DB/cache with TTL in prod.
_sessions: dict[str, dict] = {}

# Flask blueprint
rmap_bp = Blueprint("rmap", __name__)


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

def _db_url_from_config():
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

def build_invisible_text_watermarker(identity: str) -> InvisibleTextWatermark:
    """Construct an InvisibleTextWatermark instance using env overrides where available."""
    secret   = os.getenv("RMAP_WATERMARK_SECRET", identity)
    position = os.getenv("RMAP_WATERMARK_POSITION", "center")
    key      = os.getenv("RMAP_WATERMARK_KEY")

    # Some implementations may support extra params like font_size / opacity; we set if present.
    font_sz  = int(os.getenv("RMAP_WATERMARK_FONT_SIZE", "10"))
    opacity  = float(os.getenv("RMAP_WATERMARK_OPACITY", "0.03"))

    try:
        # Preferred constructor signature
        wm = InvisibleTextWatermark(
            secret=secret,
            position=position,
            key=key,
            font_size=font_sz,
            opacity=opacity,
        )
    except TypeError:
        # Fallback: minimal constructor + attribute assignment
        wm = InvisibleTextWatermark(secret)
        for attr, val in [
            ("position", position),
            ("key", key),
            ("font_size", font_sz),
            ("opacity", opacity),
        ]:
            if val is not None and hasattr(wm, attr):
                setattr(wm, attr, val)
    return wm


@rmap_bp.route("/rmap-initiate", methods=["POST"])
def rmap_initiate():
    """
    Handle RMAP Message 1.
    """
    try:
        data = request.get_json(silent=True) or {}
        if "payload" not in data:
            return jsonify({"error": "Missing 'payload'"}), 400

        encrypted_payload = base64.b64decode(data["payload"])
        msg1 = rmap.receive_message1(encrypted_payload)

        identity = msg1["identity"]
        nonce_client = msg1["nonceClient"]

        nonce_server, response1 = rmap.generate_response1(identity, nonce_client)

        _sessions[identity] = {
            "nonceClient": nonce_client,
            "nonceServer": nonce_server,
            "ts": time.time(),
        }

        return jsonify({"payload": base64.b64encode(response1).decode()}), 200

    except Exception as e:
        return jsonify({"error": f"rmap-initiate failed: {e}"}), 400


@rmap_bp.route("/rmap-get-link", methods=["POST"])
def rmap_get_link():
    """
    Handle RMAP Message 2 and return a URL to a freshly watermarked PDF.
    """
    try:
        data = request.get_json(silent=True) or {}
        if "payload" not in data:
            return jsonify({"error": "Missing 'payload'"}), 400

        encrypted_payload = base64.b64decode(data["payload"])
        msg2 = rmap.receive_message2(encrypted_payload)

        identity = msg2["identity"]
        nonce_server = msg2["nonceServer"]

        sess = _sessions.get(identity)
        if not sess or sess.get("nonceServer") != nonce_server:
            return jsonify({"error": "Invalid session or nonce"}), 403

        input_pdf = resolve_input_pdf(identity)

        out_basename = f"{identity}_{int(time.time())}.pdf"
        output_pdf = os.path.join(OUTPUT_DIR, out_basename)

        # Use InvisibleTextWatermark instead of apply_watermark
        wm = build_invisible_text_watermarker(identity)

        # Try common method names for applying the watermark
        for method_name in ("apply", "embed", "watermark", "run"):
            if hasattr(wm, method_name):
                getattr(wm, method_name)(input_pdf, output_pdf)
                break
        else:
            return jsonify({"error": "InvisibleTextWatermark has no usable method (apply/embed/watermark/run)."}), 500

        storage_root = Path(current_app.config["STORAGE_DIR"]).resolve()

        # Use the original input_pdf directory as the base; place output in a sibling "watermarks" subdir
        # (keeps it consistent with /api/create-watermark)
        src_fp = Path(input_pdf).resolve()
        dest_dir = src_fp.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Output filename: identity_timestamp.pdf
        out_basename = f"{identity}_{int(time.time())}.pdf"
        final_path = dest_dir / out_basename

        # Move the product we first wrote to OUTPUT_DIR into the storage directory
        # (or generate directly to final_path in the first place)
        try:
            Path(output_pdf).replace(final_path)
        except Exception:
            # If replace fails, fall back to copy
            data = Path(output_pdf).read_bytes()
            final_path.write_bytes(data)
            Path(output_pdf).unlink(missing_ok=True)

        # Safety check: final_path must stay under STORAGE_DIR (server.py performs the same check)
        try:
            final_path.resolve().relative_to(storage_root)
        except Exception:
            return jsonify({"error": "watermarked path escapes STORAGE_DIR"}), 500

        # Generate a 32-hex token
        session_secret = f"{sess['nonceClient']}:{sess['nonceServer']}".encode()
        token = hashlib.sha256(session_secret).hexdigest()[:32]  # length 32

        # Look up Documents.id via the absolute input path (server.py stores absolute paths)
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

        # Insert into Versions (link = 32-hex, path = absolute file path); column names aligned with server.py
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
                        "link": token,
                        "intended_for": identity,  # the group this watermark is intended for
                        "secret": identity,         # or use RMAP_WATERMARK_SECRET
                        "method": "invisible_text",
                        "position": "last-page-bottom-left",  # fixed position for this method
                        "path": str(final_path),
                    },
                )
        except Exception as e:
            # If DB insert fails, try to remove the generated file
            try:
                final_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        # Return the 32-hex token; client will download via GET /api/get-version/
        sess["link"] = token
        sess["output"] = str(final_path)
        return jsonify({"result": token}), 200

    except Exception as e:
        return jsonify({"error": f"rmap-get-link failed: {e}"}), 400
