# tests/test_regression_fuzz.py
import os
import requests
from pathlib import Path
import pytest

# ====== 配置 ======
HOST = os.getenv("TATOU_BASE_URL", "http://127.0.0.1:5000")
UPLOAD_PATH = os.getenv("UPLOAD_PATH", "/api/upload-document")
URL = f"{HOST.rstrip('/')}/{UPLOAD_PATH.lstrip('/')}"
TIMEOUT = int(os.getenv("FUZZ_REPLAY_TIMEOUT", "30"))

# ====== secrets ======
# 从 culsterfuzzer/secrets/API_TOKEN 文件读取 token
SECRETS_DIR = Path(__file__).resolve().parent.parent / "secrets"
TOKEN_FILE = SECRETS_DIR / "API_TOKEN"

def load_token() -> str | None:
    if TOKEN_FILE.exists():
        try:
            return TOKEN_FILE.read_text().strip()
        except Exception:
            return None
    return None

TOKEN = load_token()
HEADERS = {"User-Agent": "regression-fuzzer/1.0"}
if TOKEN:
    HEADERS["Authorization"] = f"Bearer {TOKEN}"
else:
    print("[warn] no token found (tests may fail or get 401)")

# ====== 辅助函数 ======
def read_meta_for(pdf_path: Path) -> dict:
    meta_path = pdf_path.with_suffix(pdf_path.suffix + ".txt")
    meta = {}
    if meta_path.exists():
        try:
            txt = meta_path.read_text(errors="ignore")
            for line in txt.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    meta[k.strip()] = v.strip()
            if "--- response preview ---" in txt:
                parts = txt.split("--- response preview ---", 1)
                meta["response_preview"] = parts[1].strip()
        except Exception:
            pass
    return meta

# ====== crash PDF 列表 ======
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CRASH_DIR = PROJECT_ROOT / "reports" / "crashes"
CRASH_PDFS = sorted(CRASH_DIR.glob("*.pdf"))

if not CRASH_PDFS:
    @pytest.mark.skip("No crash samples in reports/crashes/ — add fuzz samples to run these tests.")
    def test_no_samples():
        pass

# ====== 测试函数 ======
@pytest.mark.parametrize("pdf_path", CRASH_PDFS)
def test_replay_and_check_no_server_crash(pdf_path):
    """
    Replay each fuzzed PDF and assert:
      - server does not return 5xx
      - response body does not contain 'traceback' or 'segmentation'
      - if metadata contains numeric status, assert equality
      - also check for info-leak keywords
    """
    pdf_path = Path(pdf_path)
    meta = read_meta_for(pdf_path)
    data = pdf_path.read_bytes()
    files = {"file": ("regress.pdf", data, "application/pdf")}

    try:
        r = requests.post(URL, files=files, headers=HEADERS, timeout=TIMEOUT)
    except requests.exceptions.RequestException as e:
        pytest.fail(f"Request exception replaying {pdf_path.name}: {e}")

    status = r.status_code
    body = (r.text or "").lower()

    # 主要断言
    assert not (500 <= status <= 599), (
        f"Server returned 5xx for {pdf_path.name}: {status}\nbody_preview={r.text[:400]!s}"
    )
    assert "traceback" not in body, f"Server response contains 'traceback' for {pdf_path.name}: {r.text[:400]!s}"
    assert "segmentation" not in body, f"Server response contains 'segmentation' for {pdf_path.name}: {r.text[:400]!s}"

    # 如果 metadata 中有 numeric status，进行比对
    if "status" in meta:
        expected = meta.get("status")
        if expected and expected.isdigit():
            exp_int = int(expected)
            assert status == exp_int, f"Expected status {exp_int} for {pdf_path.name} per metadata but got {status}"

    # info-leak 关键词检查
    for kw in ("exception", "error", "stacktrace", "traceback"):
        assert kw not in body, f"Response for {pdf_path.name} contains keyword '{kw}' — potential info leak."
