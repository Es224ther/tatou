# tests/ops/test_logscan.py
# Robust test for logscan.py:
# - Prefer patching logscan.follow_logs() if present
# - Else patch the process constructor (subprocess.Popen / Popen / sp.Popen)
# - Provide stdout as text or bytes depending on how logscan launches Popen
# - Make time.sleep a no-op to avoid delays in loops

from __future__ import annotations

import json
import sys
from pathlib import Path
import importlib
import types

import pytest

# --- import logscan from server/src ---
THIS_FILE = Path(__file__).resolve()
REPO_ROOT = THIS_FILE.parents[2]
SRC_DIR = REPO_ROOT / "server" / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
logscan = importlib.import_module("logscan")  # type: ignore


# ---------- helpers ----------
def _jsonl_lines(records):
    """Yield lines terminated with newline, as docker logs would."""
    for r in records:
        line = r if isinstance(r, str) else json.dumps(r)
        yield line + "\n"


def _gen_rule1_records(ts="2025-10-23T10:00:00Z", ip="203.0.113.10"):
    # three failures from same IP -> alert when IP_FAIL_THRESHOLD=3
    return [
        {"timestamp": ts, "message": "auth_login_failed", "remote_addr": ip},
        {"timestamp": ts, "message": "auth_login_failed", "remote_addr": ip},
        {"timestamp": ts, "message": "auth_login_failed", "remote_addr": ip},
    ]


def _gen_rule2_records(uid=7, t0="2025-10-23T10:00:00Z"):
    # login success + two denials within 120s -> alert when POST_LOGIN_DENIED_THRESHOLD=2
    return [
        {"timestamp": t0, "message": "auth_login_success", "user_id": uid},
        {"timestamp": "2025-10-23T10:00:30Z", "message": "doc_owner_mismatch", "user_id": uid},
        {"timestamp": "2025-10-23T10:01:10Z", "message": "forbidden", "user_id": uid},
    ]


class _FakeStdoutIter:
    """Iterator that can yield text or bytes, depending on requested mode."""
    def __init__(self, lines, as_text: bool):
        self._iter = iter(lines if as_text else [l.encode("utf-8") for l in lines])
        self._as_text = as_text

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._iter)


class _FakePopen:
    """Minimal stub for subprocess.Popen used by logscan."""
    def __init__(self, *args, **kwargs):
        # text=True | universal_newlines=True => expect str; else bytes
        as_text = bool(kwargs.get("text") or kwargs.get("universal_newlines"))
        lines = kwargs.pop("_lines")  # injected by test
        self.stdout = _FakeStdoutIter(lines, as_text)

    def wait(self, timeout=None):
        return 0

    def poll(self):
        return 0


def _patch_source(monkeypatch, lines):
    """
    Patch the log source used by logscan.main():
    - If logscan.follow_logs exists -> replace with a finite generator
    - Else patch the process constructor in whichever form logscan uses
      (subprocess.Popen OR Popen imported into module OR sp.Popen)
    - Also neutralize time.sleep if present
    """
    # neutralize sleeps if logscan references a time module/name
    if hasattr(logscan, "time"):
        try:
            monkeypatch.setattr(logscan.time, "sleep", lambda *a, **k: None, raising=False)
        except Exception:
            pass
    else:
        # provide a lightweight time stub if code does "import time" but doesn't expose it
        monkeypatch.setattr(logscan, "time", types.SimpleNamespace(sleep=lambda *a, **k: None), raising=False)

    # case 1: follow_logs() provided
    if getattr(logscan, "follow_logs", None):
        def _iter():
            for line in lines:
                yield line
        monkeypatch.setattr(logscan, "follow_logs", _iter)
        return

    # case 2/3/4: patch a Popen constructor somewhere accessible from logscan
    fake_popen = lambda *a, **kw: _FakePopen(*a, _lines=lines, **kw)

    # Try logscan.subprocess.Popen if a subprocess module object exists
    subp = getattr(logscan, "subprocess", None)
    if subp is not None:
        monkeypatch.setattr(subp, "Popen", fake_popen, raising=True)
        return

    # Try a directly imported symbol Popen in the module namespace
    if hasattr(logscan, "Popen"):
        monkeypatch.setattr(logscan, "Popen", fake_popen, raising=True)
        return

    # Try a common alias e.g. "import subprocess as sp"
    sp = getattr(logscan, "sp", None)
    if sp is not None and hasattr(sp, "Popen"):
        monkeypatch.setattr(sp, "Popen", fake_popen, raising=True)
        return

    # If none of the above exist, fail explicitly for easier diagnosis
    raise AttributeError("Cannot find a process constructor to patch in logscan module.")


# ---------- tests ----------
def test_logscan_emits_both_alerts(monkeypatch, capsys):
    # thresholds consistent with logscan.py
    monkeypatch.setattr(logscan, "THRESH_IP", 3, raising=False)
    monkeypatch.setattr(logscan, "BURST_DENIED", 2, raising=False)
    monkeypatch.setattr(logscan, "WINDOW_S", 120, raising=False)

    lines = list(_jsonl_lines(_gen_rule1_records() + _gen_rule2_records(uid=7) + ["not a json"]))
    _patch_source(monkeypatch, lines)

    logscan.main()
    out = capsys.readouterr().out.lower()

    # robust checks: two alerts; offending IP; user id + 'denials'
    assert out.count("[alert]") >= 2, out
    assert "203.0.113.10" in out, out
    assert "user 7" in out and "denials" in out, out


def test_logscan_no_alerts_below_threshold(monkeypatch, capsys):
    monkeypatch.setattr(logscan, "THRESH_IP", 3, raising=False)
    monkeypatch.setattr(logscan, "BURST_DENIED", 2, raising=False)
    monkeypatch.setattr(logscan, "WINDOW_S", 120, raising=False)
    
    lines = list(_jsonl_lines([
        {"timestamp": "2025-10-23T10:00:00Z", "message": "auth_login_failed", "remote_addr": "198.51.100.20"},
        {"timestamp": "2025-10-23T10:00:01Z", "message": "auth_login_failed", "remote_addr": "198.51.100.20"},
        {"timestamp": "2025-10-23T10:00:02Z", "message": "auth_login_success", "user_id": 9},
        {"timestamp": "2025-10-23T10:00:20Z", "message": "doc_owner_mismatch", "user_id": 9},
    ]))
    _patch_source(monkeypatch, lines)

    logscan.main()
    out = capsys.readouterr().out.lower()
    assert "[alert]" not in out, out


