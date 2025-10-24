import os
import sys
import hashlib
import logging
from datetime import datetime
from tempfile import NamedTemporaryFile

# ---------- Configuration via environment (with safe defaults) ----------
CONTAINER_FLAG_PATH = os.environ.get("CONTAINER_FLAG_PATH", "/app/flag")
CONTAINER_BACKUP_DIR = os.environ.get("CONTAINER_BACKUP_DIR", "/app/flag_backups")  # mount as a volume

REPO_FLAG_PATH = os.environ.get("REPO_FLAG_PATH", os.path.abspath("./tatou/flag"))
REPO_BACKUP_DIR = os.environ.get("REPO_BACKUP_DIR", os.path.abspath("./flag_backups"))

# For PDF rotation, wire this to your actual pipeline
PDF_DOC_NAME = os.environ.get("PDF_DOC_NAME", "flag of user named \"Mr Important\"")
PDF_BACKUP_DIR = os.environ.get("PDF_BACKUP_DIR", os.path.abspath("./pdf_flag_backups"))

# Optional: run `docker compose restart` elsewhere if your app only reads /app/flag at startup.
RESTART_HINT = os.environ.get("RESTART_HINT", "restart container after rotation if needed")

LOG_PATH = os.environ.get("FLAG_ROTATION_LOG", "/var/log/tatou/flag_rotation.log")  # mount /var/log/tatou

# ---------- Logging ----------
log = logging.getLogger("security.flag_rotation") 

# ---------- Helpers ----------
def _utc_ts() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _atomic_write_text(path: str, text: str, mode: int = 0o600) -> None:
    """
    Write text atomically: create a temp file in the same dir, fsync, then os.replace.
    Ensures permissions are 0600 (owner read/write).
    """
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    with NamedTemporaryFile("w", dir=d, delete=False) as tmp:
        tmp.write(text)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    os.replace(tmp_path, path)         # atomic on POSIX
    os.chmod(path, mode)

def _backup_if_exists(src_path: str, backup_dir: str, tag: str) -> str | None:
    if not os.path.exists(src_path):
        return None
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, f"{os.path.basename(src_path)}.{tag}")
    with open(src_path, "rb") as r, open(backup_path, "wb") as w:
        data = r.read()
        w.write(data)
    # store a .sha256 alongside for auditing
    with open(backup_path + ".sha256", "w") as h:
        h.write(_sha256_hex(data) + "\n")
    return backup_path

def _normalize_flag(s: str) -> str:
    """
    Strip CR/LF and surrounding whitespace; enforce single-line.
    """
    s = s.replace("\r", "").strip()
    if "\n" in s:
        lines = [ln for ln in s.split("\n") if ln.strip()]
        if len(lines) != 1:
            raise ValueError("flag must be a single line")
        s = lines[0].strip()
    if not s:
        raise ValueError("empty flag after normalization")
    return s

# ---------- Rotators ----------
def rotate_container_flag(new_value: str) -> dict:
    """
    Rotate the runtime flag stored inside the container filesystem (/app/flag).
    This function assumes CONTAINER_FLAG_PATH is mounted to a persistent volume.
    """
    ts = _utc_ts()
    new_value = _normalize_flag(new_value)

    # Backup current value to persistent backup dir
    bkp = _backup_if_exists(CONTAINER_FLAG_PATH, CONTAINER_BACKUP_DIR, ts)
    if bkp:
        log.info(f"[container] backed up old flag to {bkp}")
    else:
        log.warning("[container] no existing flag found, first rotation?")

    # Atomic write new value (0600)
    _atomic_write_text(CONTAINER_FLAG_PATH, new_value, 0o600)

    # Log hash only
    sha = _sha256_hex(new_value.encode())
    log.info(f"[container] rotated /app/flag (sha256={sha[:12]}...) — {RESTART_HINT}")
    return {"target": "container", "path": CONTAINER_FLAG_PATH, "sha256": sha, "ts": ts}

def rotate_repo_flag(new_value: str) -> dict:
    """
    Rotate the repository working-tree flag (tatou/flag).
    This file MUST be gitignored to avoid accidental pushes.
    """
    ts = _utc_ts()
    new_value = _normalize_flag(new_value)

    # Safety guard: warn if not gitignored (best-effort check)
    try:
        import subprocess
        out = subprocess.run(["git", "check-ignore", "-q", REPO_FLAG_PATH], check=False)
        if out.returncode != 0:
            log.warning(f"[repo] {REPO_FLAG_PATH} is not gitignored — add it to .gitignore ASAP")
    except Exception:
        log.warning("[repo] git check-ignore failed (not a git repo or git not available)")

    # Backup old value to host dir
    bkp = _backup_if_exists(REPO_FLAG_PATH, REPO_BACKUP_DIR, ts)
    if bkp:
        log.info(f"[repo] backed up old flag to {bkp}")
    else:
        log.warning("[repo] no existing flag found, first rotation?")

    # Atomic write new value (0600)
    _atomic_write_text(REPO_FLAG_PATH, new_value, 0o600)

    sha = _sha256_hex(new_value.encode())
    log.info(f"[repo] rotated tatou/flag (sha256={sha[:12]}...)")
    return {"target": "repo", "path": REPO_FLAG_PATH, "sha256": sha, "ts": ts}

def rotate_pdf_flag(new_value: str) -> dict:
    """
    Rotate the PDF-embedded flag in the document:
      "flag of user named 'Mr Important'".
    Wire this to your existing watermark/pdf-generation pipeline.
    """
    ts = _utc_ts()
    new_value = _normalize_flag(new_value)

    os.makedirs(PDF_BACKUP_DIR, exist_ok=True)

    # TODO: call your real PDF/watermark pipeline here

    # For audit continuity, just write a sidecar hash; DO NOT store plaintext.
    sidecar = os.path.join(PDF_BACKUP_DIR, f"pdf_flag_{ts}.sha256")
    with open(sidecar, "w") as f:
        f.write(_sha256_hex(new_value.encode()) + "\n")

    log.info(f"[pdf] rotated embedded flag for \"{PDF_DOC_NAME}\" "
             f"(sha256={_sha256_hex(new_value.encode())[:12]}...) — "
             f"remember to persist the new PDF via your pipeline")

    return {"target": "pdf", "doc": PDF_DOC_NAME, "sha256": _sha256_hex(new_value.encode()), "ts": ts}

# ---------- CLI ----------
def _usage_and_exit():
    print("Usage:\n"
          " python -m server.flag_rotate <target> <NEW_VALUE>\n"
          "Targets:\n"
          "  container   rotate /app/flag inside the container volume\n"
          "  repo        rotate tatou/flag in the working tree (must be gitignored)\n"
          "  pdf         rotate the embedded flag in 'Mr Important' PDF (hook required)\n", file=sys.stderr)
    sys.exit(2)

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in {"container", "repo", "pdf"}:
        _usage_and_exit()

    target, new_val = sys.argv[1], sys.argv[2]
    if target == "container":
        out = rotate_container_flag(new_val)
    elif target == "repo":
        out = rotate_repo_flag(new_val)
    else:
        out = rotate_pdf_flag(new_val)

    # 1) log to existing pipeline (no plaintext)
    log.info("flag_rotated", extra={
        "target": out.get("target"),
        "path_or_doc": out.get("path") or out.get("doc"),
        "sha256_prefix": out.get("sha256", "")[:12],
        "ts": out.get("ts")
    })
    # 2) keep stdout for Journal paste
    print({"event": "flag_rotated", **out})
