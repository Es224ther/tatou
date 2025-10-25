# tests/test_api_nonregression.py
import os
from pathlib import Path
import schemathesis
import pytest

# === Locate schema ===
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PROJECT_ROOT / "openapi.yaml"

# === Load API token ===
API_TOKEN_FILE = PROJECT_ROOT / "secrets/API_TOKEN"
with open(API_TOKEN_FILE) as f:
    API_TOKEN = f.read().strip()

# === Load schema ===
schema = schemathesis.from_file(str(SCHEMA_PATH))  # 4.3.10 使用 from_file 而不是 from_path/from_url

# === Base URL ===
BASE_URL = os.getenv("TATOU_BASE_URL", "http://127.0.0.1:5000")

@pytest.mark.parametrize
@schema.parametrize()
def test_api(case):
    """
    For each endpoint defined in OpenAPI:
    - Call it with valid/generated data
    - Validate response against schema
    - Check no server crash (no 5xx)
    """
    response = case.call(base_url=BASE_URL, headers={"Authorization": f"Bearer {API_TOKEN}"})
    case.validate_response(response)
    assert response.status_code < 500, f"{case.method} {case.path} returned {response.status_code}"
