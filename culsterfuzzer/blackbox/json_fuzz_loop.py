#!/usr/bin/env python3
"""
json_fuzz_loop_enhanced.py
增强日志记录：记录 ISO 时间、状态、响应长度、响应前 N 字符、选定 headers，
并可选保存每次完整响应为独立 JSON 文件。
"""

import argparse
import csv
import json
import time
from pathlib import Path
import sys
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from datetime import datetime, timezone

DEFAULT_TARGET = "http://127.0.0.1:5000/api/login"

def iso_now():
    # ISO 8601 with milliseconds, UTC
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")

def parse_args():
    p = argparse.ArgumentParser(description="JSON fuzzing script with enhanced logging.")
    p.add_argument("--target", "-t", default=DEFAULT_TARGET, help="Target URL to POST JSON to")
    p.add_argument("--payload-file", "-p", default="json_payloads.txt", help="One payload per line")
    p.add_argument("--out", "-o", default="reports/logs/json_fuzz_log.txt", help="Output TSV log file")
    p.add_argument("--responses-dir", "-r", default="reports/logs/responses", help="Directory to optionally save full responses")
    p.add_argument("--timeout", type=float, default=10.0, help="Requests timeout (seconds)")
    p.add_argument("--delay", type=float, default=0.1, help="Delay between requests (seconds)")
    p.add_argument("--retries", type=int, default=2, help="Number of retries on transient errors")
    p.add_argument("--backoff-factor", type=float, default=0.5, help="Backoff factor for retries")
    p.add_argument("--no-retry-statuses", nargs="*", type=int,
                   default=[429, 500, 502, 503, 504],
                   help="Status codes considered for retry (default: 429,500,502,503,504)")
    p.add_argument("--resp-preview-length", type=int, default=500,
                   help="How many characters of response body to include in TSV (0 = none)")
    p.add_argument("--headers-to-log", nargs="*", default=["Content-Type", "Set-Cookie"],
                   help="Response headers to include in TSV (space-separated)")
    p.add_argument("--save-responses", action="store_true",
                   help="If set, save full responses as JSON files under --responses-dir (one file per payload index).")
    return p.parse_args()

def load_payloads(path: Path):
    if not path.exists():
        print(f"[ERROR] Payload file missing: {path}", file=sys.stderr)
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]

def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def make_session(retries: int, backoff: float, status_forcelist):
    s = requests.Session()
    retry = Retry(total=retries,
                  backoff_factor=backoff,
                  status_forcelist=status_forcelist,
                  allowed_methods=frozenset(["POST", "GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]))
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

def write_header_if_needed(path: Path, headers_to_log):
    if not path.exists() or path.stat().st_size == 0:
        ensure_dir(path.parent)
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, delimiter="\t", lineterminator="\n")
            hdr = ["iso_ts", "unix_ts", "index", "status", "resp_len_bytes", f"resp_preview({args.resp_preview_length})", "error", "payload"]
            # append header names for each logged header
            for h in headers_to_log:
                hdr.append(f"hdr_{h}")
            writer.writerow(hdr)

def append_tsv(path: Path, row):
    with path.open("a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t", lineterminator="\n")
        writer.writerow(row)

def save_response_json(out_dir: Path, index: int, payload: str, resp_obj: dict):
    ensure_dir(out_dir)
    fname = out_dir / f"resp_{index:05d}.json"
    with fname.open("w", encoding="utf-8") as f:
        json.dump({
            "index": index,
            "payload": payload,
            "recorded_at": iso_now(),
            "response": resp_obj
        }, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    args = parse_args()
    target = args.target
    payload_file = Path(args.payload_file).resolve()
    out_file = Path(args.out).resolve()
    responses_dir = Path(args.responses_dir).resolve()

    payloads = load_payloads(payload_file)
    if not payloads:
        print("[ERROR] No payloads to test. Please check payload file path.", file=sys.stderr)
        sys.exit(1)

    session = make_session(retries=args.retries, backoff=args.backoff_factor, status_forcelist=args.no_retry_statuses)
    write_header_if_needed(out_file, args.headers_to_log)

    print(f"[INFO] Target: {target}")
    print(f"[INFO] Payloads: {len(payloads)}")
    print(f"[INFO] Log: {out_file}")
    print(f"[INFO] Timeout: {args.timeout}s, Delay: {args.delay}s, Retries: {args.retries}")
    if args.save_responses:
        print(f"[INFO] Full responses will be saved to: {responses_dir}")

    for i, p in enumerate(payloads):
        body = {"email": p, "password": "password123"}
        unix_ts = int(time.time())
        iso_ts = iso_now()
        error_text = ""
        status = ""
        resp_len = ""
        resp_preview = ""
        header_values = []

        try:
            r = session.post(target, json=body, timeout=args.timeout)
            status = r.status_code
            resp_bytes = r.content or b""
            resp_len = len(resp_bytes)
            # safe text preview (may be binary/unicode)
            try:
                txt = r.text or ""
            except Exception:
                txt = resp_bytes.decode("utf-8", errors="replace")
            if args.resp_preview_length > 0:
                resp_preview = txt[:args.resp_preview_length].replace("\n", "\\n")
            # collect requested headers
            for hn in args.headers_to_log:
                header_values.append(r.headers.get(hn, ""))
            # if saving full responses, write JSON including headers and body (body as text if possible)
            if args.save_responses:
                resp_obj = {
                    "status": r.status_code,
                    "headers": dict(r.headers),
                    "body_text_preview": txt[:2000]  # avoid insanely large saves in body_text_preview
                }
                save_response_json(responses_dir, i, p, resp_obj)
            pretty = f"{iso_ts}\t{unix_ts}\t{i}\t{status}\t{resp_len}\t{resp_preview}\t-\t{p}"
        except Exception as e:
            status = "ERR"
            resp_len = ""
            resp_preview = ""
            header_values = ["" for _ in args.headers_to_log]
            error_text = f"{type(e).__name__}: {str(e)}"
            pretty = f"{iso_ts}\t{unix_ts}\t{i}\tERR\t-\t-\t{error_text}\t{p}"
        # write to console and TSV
        print(pretty)
        row = [iso_ts, unix_ts, i, status, resp_len, resp_preview, error_text, p] + header_values
        append_tsv(out_file, row)
        time.sleep(args.delay)
