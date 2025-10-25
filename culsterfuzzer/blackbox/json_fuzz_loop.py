#!/usr/bin/env python3
"""
json_fuzz_loop_enhanced.py

增强 JSON fuzz 测试 /api/create-user，包含：
- 自动读取 secrets/API_TOKEN（相对于项目根）
- seed 支持 + 自动补全 login/password
- field-aware mutations（email/login/password）
- 保证每个变体至少修改一个字段
- 跳过重复 payload（避免大量 409）
- 可选 --uniquify 在 seed email 上添加随机短后缀以避免已存在的账号冲突
- 增强日志 / 可选保存完整响应
"""

import argparse
import csv
import json
import os
import random
import string
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# ------------------ defaults ------------------
DEFAULT_TARGET = "http://127.0.0.1:5000/api/create-user"
DEFAULT_OUT_FILE = "reports/logs/json_fuzz_log.txt"
DEFAULT_RESP_DIR = "reports/logs/responses"
SECRETS_PATH = Path(__file__).resolve().parent.parent / "secrets/API_TOKEN"

# ------------------ helpers ------------------
def iso_now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")

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

def write_header_if_needed(path: Path, headers_to_log, resp_preview_len):
    if not path.exists() or path.stat().st_size == 0:
        ensure_dir(path.parent)
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f, delimiter="\t", lineterminator="\n")
            hdr = ["iso_ts", "unix_ts", "index", "status", "resp_len_bytes", f"resp_preview({resp_preview_len})", "error", "payload", "note"]
            hdr += [f"hdr_{h}" for h in headers_to_log]
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

# ------------------ mutation utils ------------------
COMMON_WEAK_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "abc123", "P@ssw0rd!", "password1",
    "letmein", "welcome", "admin", "passw0rd", "111111", "123456789"
]

HOMOGLYPHS = {
    "a": ["а", "á", "à", "â", "ä", "α"],
    "o": ["о", "0", "ö", "ó"],
    "e": ["е", "è", "é"],
    "i": ["і", "1", "í"],
    "s": ["ѕ", "$", "5"],
    "l": ["1", "ɫ"]
}

def random_unicode_suffix():
    return "".join(random.choice(["\u200b", "\u2603", "\u00A0", "\u200d"]) for _ in range(random.randint(1,3)))

def percent_encode(s: str):
    out = ""
    for c in s:
        if random.random() < 0.15:
            out += "%%%02X" % ord(c)
        else:
            out += c
    return out

def homoglyph_substitute(s: str):
    if not s:
        return s
    i = random.randrange(len(s))
    ch = s[i].lower()
    if ch in HOMOGLYPHS:
        sub = random.choice(HOMOGLYPHS[ch])
        return s[:i] + sub + s[i+1:]
    return s

def flip_case(s: str):
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in s)

def mutate_email(email: str) -> list:
    try:
        local, domain = email.split("@", 1)
    except Exception:
        local = email
        domain = "example.com"
    muts = []
    muts.append(f"{local}+test@{domain}")
    muts.append(f"{local}.alt@{domain}")
    muts.append(f"{local}123@{domain}")
    muts.append(f"{local.upper()}@{domain}")
    muts.append(f"{flip_case(local)}@{domain}")
    muts.append(percent_encode(local) + "@" + domain)
    muts.append(f"\"{local}\"@{domain}")
    muts.append(local)  # missing domain -> invalid
    muts.append("@" + domain)  # missing local -> invalid
    muts.append(local + "@" + domain + ".")  # trailing dot
    muts.append(local + ("A"*200) + "@" + domain)  # huge local
    muts.append(local + "<script>alert(1)</script>@" + domain)
    muts.append(local + "' OR '1'='1@" + domain)
    muts.append(local + "\u200b" + "@" + domain)
    muts.append(homoglyph_substitute(local) + "@" + domain)
    return muts

def mutate_password(pw: str) -> list:
    muts = []
    muts.extend(COMMON_WEAK_PASSWORDS)
    muts.append(pw + "1")
    muts.append(pw + "!")
    muts.append(pw[:-1] if len(pw)>1 else pw + "x")
    muts.append(pw * 2)
    muts.append("A" * 1024)
    muts.append("P" * 5000)
    muts.append(pw + "' OR '1'='1")
    muts.append(pw + "<script>alert(1)</script>")
    muts.append(pw + "\x00")
    muts.append(pw + random_unicode_suffix())
    muts.append(percent_encode(pw))
    return muts

def mutate_login(login: str) -> list:
    muts = []
    muts.append(login + "1")
    muts.append(login + "_" + login)
    muts.append(f"{login}.{login}")
    muts.append(login[::-1])
    muts.append(f"{login}' OR '1'='1")
    muts.append(homoglyph_substitute(login))
    muts.append(f"{login}{random.randint(1000,9999)}")
    muts.append(f"{login}{random_unicode_suffix()}")
    muts.append(f"{flip_case(login)}")
    return muts

def mutate_field(field_name: str, value) -> list:
    s = str(value) if value is not None else ""
    fname = field_name.lower()
    if fname in ("email","e-mail","mail"):
        return mutate_email(s)
    if "pass" in fname:
        return mutate_password(s)
    if fname in ("login","username","user","user_name","name"):
        return mutate_login(s)
    muts = []
    muts.append(s + random.choice(["A","1","!"]*10))
    muts.append(homoglyph_substitute(s))
    muts.append(percent_encode(s))
    muts.append(s + random_unicode_suffix())
    muts.append(s[::-1])
    return muts

def generate_mutations_from_payload(payload_json_str: str, n: int):
    """
    Field-aware mutation generator that:
    - Ensures each returned payload differs from the original (if possible)
    - Attempts varied field changes (1-2 fields per variant)
    - Returns at most n unique variants (as JSON strings)
    """
    try:
        obj = json.loads(payload_json_str)
    except Exception:
        # fallback: percent-encode the raw string
        return [percent_encode(payload_json_str) for _ in range(n)]

    if not isinstance(obj, dict) or not obj:
        return [payload_json_str for _ in range(n)]

    keys = list(obj.keys())
    priority = [k for k in keys if k.lower() in ("email","login","password","username")]
    others = [k for k in keys if k not in priority]
    field_pool = priority + others

    seen = set()
    muts = []
    attempts = 0
    max_attempts = max(200, n * 20)

    while len(muts) < n and attempts < max_attempts:
        attempts += 1
        new = dict(obj)
        kcount = 1 if random.random() < 0.7 else 2
        chosen = random.sample(field_pool, min(len(field_pool), kcount))
        changed = False
        for k in chosen:
            orig = new.get(k, "")
            candidates = mutate_field(k, orig)
            if not candidates:
                continue
            val = random.choice(candidates)
            if str(val) != str(orig):
                changed = True
            new[k] = val
        # Ensure at least one field changed; otherwise skip
        if not changed:
            continue
        s = json.dumps(new, ensure_ascii=False, sort_keys=True)
        if s in seen:
            continue
        seen.add(s)
        muts.append(s)

    # If not enough unique muts, try deterministic fallbacks (append numbers)
    i = 0
    while len(muts) < n:
        base = dict(obj)
        k = random.choice(field_pool)
        base_val = str(base.get(k, ""))
        base[k] = base_val + f"_AUTOMUT{i}"
        s = json.dumps(base, ensure_ascii=False, sort_keys=True)
        if s not in seen:
            seen.add(s)
            muts.append(s)
        i += 1
        if i > n * 100:
            break

    return muts

# ------------------ argument parsing ------------------
def parse_args():
    p = argparse.ArgumentParser(description="JSON fuzzing for /api/create-user with better mutations")
    p.add_argument("--target", "-t", default=DEFAULT_TARGET, help="Target URL")
    p.add_argument("--out", "-o", default=DEFAULT_OUT_FILE, help="TSV log file")
    p.add_argument("--responses-dir", "-r", default=DEFAULT_RESP_DIR, help="Responses dir")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--delay", type=float, default=0.05)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--backoff-factor", type=float, default=0.5)
    p.add_argument("--no-retry-statuses", nargs="*", type=int, default=[429,500,502,503,504])
    p.add_argument("--resp-preview-length", type=int, default=300)
    p.add_argument("--headers-to-log", nargs="*", default=["Content-Type","Set-Cookie"])
    p.add_argument("--save-responses", action="store_true")
    p.add_argument("--seed", default=None, help='JSON seed or single email (e.g. \'{"email":"a@b","login":"a","password":"P"}\' or alice@example.com)')
    p.add_argument("--mutations", type=int, default=10, help="number of mutations per seed")
    p.add_argument("--uniquify", action="store_true", help="append short random suffix to seed email local-part to avoid existing-user conflicts")
    return p.parse_args()

# ------------------ main ------------------
if __name__ == "__main__":
    args = parse_args()
    target = args.target

    # load API token from env or secrets file
    API_TOKEN = os.getenv("API_TOKEN")
    if not API_TOKEN and SECRETS_PATH.exists():
        API_TOKEN = SECRETS_PATH.read_text(encoding="utf-8").strip()

    # prepare base payloads
    bases = []
    if args.seed:
        try:
            seed_obj = json.loads(args.seed)
        except Exception:
            # treat as single email
            seed_obj = {"email": args.seed}
        # auto-complete login/password if missing
        if "login" not in seed_obj:
            seed_obj["login"] = seed_obj.get("email","user").split("@")[0]
        if "password" not in seed_obj:
            seed_obj["password"] = "P@ssw0rd!"
        # uniquify option
        if args.uniquify:
            em = seed_obj.get("email","")
            try:
                local, domain = em.split("@",1)
                local = local + "_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
                seed_obj["email"] = f"{local}@{domain}"
                # also adjust login if it equals previous local
                if seed_obj["login"] == em.split("@")[0]:
                    seed_obj["login"] = seed_obj["login"] + "_" + ''.join(random.choices("0123456789", k=3))
            except Exception:
                # ignore if not parseable
                pass
        bases.append(json.dumps(seed_obj, ensure_ascii=False))
    else:
        # if no seed, fail fast (we could implement schema extraction here; keep simple)
        print("[ERROR] No seed provided. Use --seed with JSON or email.", file=sys.stderr)
        sys.exit(1)

    # generate final payloads with mutations
    final_payloads = []
    for base in bases:
        final_payloads.append(base)
        if args.mutations and args.mutations > 0:
            muts = generate_mutations_from_payload(base, args.mutations)
            final_payloads.extend(muts)

    # session and logging setup
    session = make_session(retries=args.retries, backoff=args.backoff_factor, status_forcelist=args.no_retry_statuses)
    out_path = Path(args.out).resolve()
    write_header_if_needed(out_path, args.headers_to_log, args.resp_preview_length)
    ensure_dir(Path(args.responses_dir))

    headers = {"Content-Type":"application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"

    print(f"[INFO] Target: {target}, Base payloads: {len(bases)}, Final payloads: {len(final_payloads)}")
    seen_signatures = set()  # track payload json (sorted keys) already sent to avoid repeats

    for i, payload_str in enumerate(final_payloads):
        # normalise signature to detect duplicates
        try:
            parsed = json.loads(payload_str)
            signature = json.dumps(parsed, ensure_ascii=False, sort_keys=True)
        except Exception:
            signature = payload_str

        note = ""
        if signature in seen_signatures:
            note = "SKIP-DUP"
            print(f"[SKIP-DUP] payload index {i} duplicate, skipping send")
            # Still write a log row indicating skip
            row = [iso_now(), int(time.time()), i, "SKIP", "", "", "skipped duplicate", payload_str, note] + ["" for _ in args.headers_to_log]
            append_tsv(out_path, row)
            continue

        # send request
        try:
            r = session.post(target, headers=headers, json=json.loads(payload_str), timeout=args.timeout)
            status = r.status_code
            resp_bytes = r.content or b""
            resp_len = len(resp_bytes)
            try:
                txt = r.text or resp_bytes.decode("utf-8", errors="replace")
            except Exception:
                txt = resp_bytes.decode("utf-8", errors="replace")
            resp_preview = txt[:args.resp_preview_length].replace("\n","\\n") if args.resp_preview_length > 0 else ""
            header_values = [r.headers.get(hn,"") for hn in args.headers_to_log]

            if args.save_responses:
                resp_obj = {"status": r.status_code, "headers": dict(r.headers), "body_text_preview": txt[:2000]}
                save_response_json(Path(args.responses_dir), i, payload_str, resp_obj)

            # record signature as seen even if server returned 4xx/5xx to avoid resending same payload
            seen_signatures.add(signature)

            pretty = f"{iso_now()}\t{int(time.time())}\t{i}\t{status}\t{resp_len}\t{resp_preview}\t-\t{payload_str}"
            print(pretty)
            row = [iso_now(), int(time.time()), i, status, resp_len, resp_preview, "", payload_str, note] + header_values
            append_tsv(out_path, row)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            print(f"[ERR] index {i} {err}")
            row = [iso_now(), int(time.time()), i, "ERR", "", "", err, payload_str, note] + ["" for _ in args.headers_to_log]
            append_tsv(out_path, row)

        time.sleep(args.delay)
