#!/usr/bin/env python3
import json, subprocess, os, sys
from collections import deque, defaultdict
from datetime import datetime, timedelta

CONTAINER   = os.getenv("SERVER_CONTAINER", "tatou-server-1")
USE_COMPOSE = os.getenv("USE_COMPOSE", "0") == "1"   
WINDOW_S    = int(os.getenv("LOG_WINDOW_S", "60"))
THRESH_IP   = int(os.getenv("IP_FAIL_THRESHOLD", "10"))
BURST_DENIED = int(os.getenv("POST_LOGIN_DENIED_THRESHOLD", "8"))
DEBUG       = os.getenv("DEBUG", "0") == "1"

SENSITIVE_PREFIXES = ("/api/get-document/", "/api/read-watermark")
FAIL_MESSAGES = {"auth_login_failed","auth_token_invalid","doc_owner_mismatch","forbidden"}

def _now(): return datetime.utcnow()

def _start_tail():
    if USE_COMPOSE:
        cmd = ["docker","compose","logs","-f","--since=0s","server"]
    else:
        cmd = ["docker","logs","-f",CONTAINER,"--since=0s"]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

def _parse_ts(ev):
    ts = ev.get("timestamp") or ev.get("time")
    if isinstance(ts,str):
        try:
            return datetime.fromisoformat(ts.replace("Z","+00:00"))
        except Exception:
            return _now()
    return _now()

def _get(ev, *keys, default=None):
    for k in keys:
        if k in ev: return ev[k]
        if "ctx" in ev and isinstance(ev["ctx"], dict) and k in ev["ctx"]:
            return ev["ctx"][k]
    return default

def main():
    ip_fails = defaultdict(deque)          # ip -> deque[timestamps]
    last_login = {}                        # user_id -> ts
    denied_after_login = defaultdict(int)  # user_id -> counter

    p = _start_tail()
    for raw in p.stdout:  # type: ignore
        line = raw.strip()
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            if DEBUG and line:
                print(f"[DBG] non-json: {line[:120]}", flush=True)
            continue

        ts   = _parse_ts(ev)
        msg  = _get(ev, "message", "msg", default="")
        ip   = _get(ev, "remote_addr", "ip", default="unknown")
        uid  = _get(ev, "user_id", default=None)
        path = _get(ev, "path", default="")
        sc   = _get(ev, "status_code", default=None)
        try:
            sc = int(sc) if sc is not None else None
        except Exception:
            sc = None

        # Rule 1
        is_fail_event = (msg in FAIL_MESSAGES)
        is_sensitive_4xx = (path.startswith(SENSITIVE_PREFIXES) and sc in (403,404))
        if is_fail_event or is_sensitive_4xx:
            dq = ip_fails[ip]; dq.append(ts)
            while dq and (ts - dq[0]).total_seconds() > WINDOW_S: dq.popleft()
            if len(dq) >= THRESH_IP:
                print(f"[ALERT] {ts.isoformat()} brute-like from {ip}: {len(dq)} fails/{WINDOW_S}s (last={msg or sc})", flush=True)

        # Rule 2
        if msg == "auth_login_success" and uid is not None:
            last_login[uid] = ts; denied_after_login[uid] = 0
        if (msg in {"doc_owner_mismatch","forbidden"} or is_sensitive_4xx) and uid in last_login:
            if ts - last_login[uid] <= timedelta(minutes=2):
                denied_after_login[uid] += 1
                if denied_after_login[uid] >= BURST_DENIED:
                    print(f"[ALERT] {ts.isoformat()} user {uid} scanning? {denied_after_login[uid]} denials post-login", flush=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
