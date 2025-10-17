from server import app
import base64
from pathlib import Path
import types


def test_rmap_initiate_route(monkeypatch):
    import rmap_route as rr

    class FakeRMAP:
        def receive_message1(self, payload: bytes):
            return {"identity": "Group_8", "nonceClient": "nc123"}

        def generate_response1(self, identity: str, nonce_client: str):
            return "ns456", b"resp1-bytes"

    monkeypatch.setattr(rr, "rmap", FakeRMAP(), raising=True)

    client = app.test_client()
    payload = base64.b64encode(b"cipher").decode()
    resp = client.post("/rmap-initiate", json={"payload": payload})
    assert resp.status_code == 200
    body = resp.get_json()
    assert "payload" in body
    assert base64.b64decode(body["payload"]) == b"resp1-bytes"


def test_rmap_get_link_route(tmp_path, monkeypatch):
    import rmap_route as rr

    # Prepare storage root and an input PDF under it
    storage_root = tmp_path / "storage"
    storage_root.mkdir(parents=True, exist_ok=True)
    src_dir = storage_root / "files"
    src_dir.mkdir(parents=True, exist_ok=True)
    input_pdf = src_dir / "input.pdf"
    input_pdf.write_bytes(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n%%EOF\n")

    # Prime session for identity
    rr._sessions.clear()
    rr._sessions["Group_8"] = {"nonceClient": "nc123", "nonceServer": "ns456", "ts": 0}

    class FakeRMAP2:
        def receive_message2(self, payload: bytes):
            return {"identity": "Group_8", "nonceServer": "ns456"}

    monkeypatch.setattr(rr, "rmap", FakeRMAP2(), raising=True)
    monkeypatch.setattr(rr, "resolve_input_pdf", lambda identity: str(input_pdf), raising=True)

    class FakeWM:
        def apply(self, in_path: str, out_path: str):
            Path(out_path).write_bytes(b"%PDF-1.4\nWM\n%%EOF\n")

    monkeypatch.setattr(rr, "build_invisible_text_watermarker", lambda identity: FakeWM(), raising=True)

    class _FakeConn:
        def execute(self, _text, params=None):
            class _Row:
                def __init__(self, id_val):
                    self.id = id_val
            if params and "p" in params:
                return types.SimpleNamespace(first=lambda: _Row(1))
            return None
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False

    class _FakeEngine:
        def connect(self):
            return _FakeConn()
        def begin(self):
            return _FakeConn()

    monkeypatch.setattr(rr, "get_engine", lambda: _FakeEngine(), raising=True)

    app.config["STORAGE_DIR"] = storage_root

    client = app.test_client()
    payload = base64.b64encode(b"cipher2").decode()
    resp = client.post("/rmap-get-link", json={"payload": payload})
    assert resp.status_code == 200
    body = resp.get_json()
    assert "result" in body and isinstance(body["result"], str) and len(body["result"]) == 32
