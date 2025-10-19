#!/usr/bin/env python3
"""
pdf_mutator_upload.py
- Mutates PDF seeds and uploads to /api/upload-document
- Auth:
    * Uses token from culsterfuzzer/secrets/API_TOKEN if set
    * Else uses PASSWORD from culsterfuzzer/secrets/API_PASSWORD + hard-coded EMAIL to POST /api/login
- Saves crash samples (mutated pdf + metadata) when:
    * request exception (connection/invalid URL)
    * server returns 5xx
    * response body contains "traceback" or "segmentation"
    * 401 is also saved for triage (script will attempt login refresh if creds provided)
- Limits number of saved crash samples to avoid disk spam
"""
from __future__ import annotations
import os
import random
import time
import requests
from pathlib import Path
from typing import Optional

# ======= Configuration (edit as needed) =======
HOST = "http://127.0.0.1:5000"
UPLOAD_PATH = "/api/upload-document"
LOGIN_PATH = "/api/login"
ITERATIONS = 200
TIMEOUT = 30
SAVE_ON_ERRORS = True
MAX_SAVED_CRASHES = 200  # cap saved samples
USER_AGENT = "pdf-fuzzer/1.0"
SAVE_RESPONSE_PREVIEW = True  # include response preview in .txt metadata
MIN_PREVIEW_LEN = 0
# ==============================================

# Paths (assume script located in clusterfuzzer/blackbox)
HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parent
CORPUS_DIR = PROJECT_ROOT / "corpus"
OUT_DIR = PROJECT_ROOT / "reports" / "crashes"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ======= Secrets paths =======
SECRETS_DIR = PROJECT_ROOT / "secrets"
TOKEN_FILE = SECRETS_DIR / "API_TOKEN"
PASSWORD_FILE = SECRETS_DIR / "API_PASSWORD"
EMAIL = "fuzzuser@example.test"  # 硬编码 email，可替换为你的账号

# -----------------------
# Token management
# -----------------------
def get_token_from_secrets_or_login() -> Optional[str]:
    """Return token string or None. Prefers token from secrets folder, else attempts login."""
    # 1) try token file
    if TOKEN_FILE.exists():
        try:
            tok = TOKEN_FILE.read_text().strip()
            if tok:
                print("[*] Using token from secrets/API_TOKEN")
                return tok
        except Exception as e:
            print(f"[!] Failed to read token file: {e}")

    # 2) try login with email + password from secrets
    if PASSWORD_FILE.exists():
        try:
            password = PASSWORD_FILE.read_text().strip()
            login_url = f"{HOST.rstrip('/')}/{LOGIN_PATH.lstrip('/')}"
            print(f"[*] Attempting login to {login_url} with secrets/API_PASSWORD")
            r = requests.post(login_url, json={"email": EMAIL, "password": password}, timeout=TIMEOUT)
            data = r.json() if r.status_code == 200 else {}
            if r.status_code == 200 and (data.get("token") or data.get("access_token") or data.get("jwt")):
                tok = data.get("token") or data.get("access_token") or data.get("jwt")
                print("[*] Login succeeded, token obtained")
                return tok
            else:
                print(f"[!] Login failed (status {r.status_code}): {r.text[:500]}")
        except Exception as e:
            print(f"[!] Login request failed: {e}")

    print("[*] No token available from secrets or login")
    return None

# -----------------------
# Crash helpers
# -----------------------
def saved_crash_count() -> int:
    return len(list(OUT_DIR.glob("crash_*.pdf")))

def save_crash(data: bytes, seed_name: str, i: int, code, preview: Optional[str] = None):
    if saved_crash_count() >= MAX_SAVED_CRASHES:
        print("[!] Reached MAX_SAVED_CRASHES, not saving more samples.")
        return
    ts = int(time.time())
    safe_seed = seed_name.replace(" ", "_")
    fname = OUT_DIR / f"crash_{ts}_{i}_seed_{safe_seed}_code_{code if code is not None else 'ERR'}.pdf"
    meta = OUT_DIR / f"crash_{ts}_{i}_seed_{safe_seed}_code_{code if code is not None else 'ERR'}.txt"
    try:
        fname.write_bytes(data)
        meta_content = f"timestamp={ts}\niteration={i}\nseed={seed_name}\nstatus={code}\n"
        if preview and SAVE_RESPONSE_PREVIEW:
            meta_content += "\n--- response preview ---\n"
            meta_content += preview[:5000]
        meta.write_text(meta_content)
    except Exception as e:
        print(f"[!] Failed to save crash sample: {e}")

# -----------------------
# Mutator
# -----------------------
def mutate_bytes(data: bytes) -> bytes:
    import os, random, re

    if not data:
        return data

    b = bytearray(data)
    n = len(b)

    def safe_rand_index():
        return random.randrange(0, max(1, len(b)))

    def find_all(pattern: bytes):
        idx = 0
        res = []
        while True:
            i = b.find(pattern, idx)
            if i == -1:
                break
            res.append(i)
            idx = i + 1
        return res

    # 1) Corrupt header
    if random.random() < 0.2:
        if b[:5] == b"%PDF-":
            ver = f"{random.randint(0,9)}.{random.randint(0,9)}".encode("ascii")
            b[0:5] = b"%PDF-"
            for i, c in enumerate(ver[:3]):
                if 5+i < len(b):
                    b[5+i] = c
        else:
            for i in range(min(8, len(b))):
                b[i] = random.randrange(1,256)

    # 2) Break xref/trailer near EOF
    if random.random() < 0.25:
        startxref_pos = b.rfind(b"startxref")
        xref_pos = b.rfind(b"xref")
        trailer_pos = b.rfind(b"trailer")
        if startxref_pos != -1:
            del b[startxref_pos:]
        elif xref_pos != -1 and random.random() < 0.7:
            for i in range(xref_pos, min(len(b), xref_pos+random.randint(8,512))):
                b[i] = random.randrange(0,256)
        elif trailer_pos != -1:
            start = max(0, trailer_pos - random.randint(0,64))
            length = random.randint(4, min(2048, len(b)-start))
            del b[start:start+length]
        else:
            cut = random.randint(1, min(len(b)//4, 4096))
            del b[-cut:]

    # 3) /Length spoofing
    if random.random() < 0.3:
        for idx in find_all(b"/Length"):
            j = idx + len(b"/Length")
            while j < len(b) and b[j] in b" \t\r\n":
                j += 1
            if j < len(b) and chr(b[j]).isdigit():
                huge = str(random.choice([1, 9999999, random.randint(1000,200000)])).encode()
                mlen = min(10, len(b)-j)
                b[j:j+mlen] = huge[:mlen]

    # 4) stream/endstream blocks
    if random.random() < 0.45:
        stream_idxs = find_all(b"stream")
        random.shuffle(stream_idxs)
        for s_idx in stream_idxs[:max(1,len(stream_idxs)//3)]:
            e_idx = b.find(b"endstream", s_idx+6)
            if e_idx != -1 and e_idx > s_idx+6:
                op = random.random()
                s_start = s_idx + len(b"stream")
                while s_start < len(b) and b[s_start] in (10,13):
                    s_start += 1
                try:
                    stream_len = e_idx - s_start
                    if stream_len <= 0:
                        continue
                    if op < 0.35:
                        repl_len = random.randint(max(1, stream_len//4), max(1, stream_len*2))
                        b[s_start:e_idx] = os.urandom(repl_len)
                    elif op < 0.65:
                        cut = random.randint(1, min(stream_len, max(1, stream_len//2)))
                        del b[s_start:s_start+cut]
                    else:
                        ins = os.urandom(min(65536, max(1024, stream_len*random.randint(2,6))))
                        b[s_start:s_start] = ins
                except Exception:
                    pass

    # 5) obj blocks
    if random.random() < 0.4:
        obj_idxs = find_all(b" obj") + find_all(b"\nobj") + find_all(b"\n obj")
        if obj_idxs:
            for _ in range(random.randint(1, min(4, len(obj_idxs)))):
                idx = random.choice(obj_idxs)
                endobj = b.find(b"endobj", idx+1)
                if endobj != -1:
                    op = random.random()
                    if op < 0.4:
                        try: del b[idx:endobj+6]
                        except: pass
                    elif op < 0.75:
                        blk = b[idx:endobj+6]
                        insert_pos = random.randint(0,len(b))
                        b[insert_pos:insert_pos] = blk
                    else:
                        for i in range(idx, min(idx+32,len(b))):
                            if b[i] in b"0123456789":
                                b[i] = ord(str(random.randint(0,9)))

    # 6) chaos mutations
    for _ in range(random.randint(1,6)):
        r = random.random()
        if r < 0.3:
            for _ in range(random.randint(1,12)):
                i = safe_rand_index()
                b[i] ^= 1 << random.randrange(0,8)
        elif r < 0.5:
            if len(b) > 64:
                i1 = random.randint(0,len(b)-1)
                i2 = random.randint(0,len(b)-1)
                l1 = random.randint(1,min(1024,len(b)-i1))
                l2 = random.randint(1,min(1024,len(b)-i2))
                s1 = b[i1:i1+l1]; s2 = b[i2:i2+l2]
                if i1 + l1 <= i2:
                    b[i1:i1+l1] = s2[:l1]
                    b[i2:i2+l2] = s1[:l2]
                else:
                    for k in range(min(len(s1),len(s2))):
                        b[(i1+k)%len(b)] = s2[k]
        elif r < 0.75:
            insert_len = random.randint(8, min(65536,max(32,len(b)//2)))
            pos = random.randint(0,len(b))
            b[pos:pos] = os.urandom(insert_len)
        else:
            if len(b) > 32:
                s = random.randint(1, min(8192,len(b)//6))
                p = random.randint(0,len(b)-s)
                del b[p:p+s]

    if len(b) == 0:
        b = bytearray(os.urandom(8))

    return bytes(b)

# -----------------------
# Post file
# -----------------------
def post_file(data: bytes, token: Optional[str]) -> tuple[Optional[int], str, Optional[float]]:
    url = f"{HOST.rstrip('/')}/{UPLOAD_PATH.lstrip('/')}"
    files = {"file": ("fuzz.pdf", data, "application/pdf")}
    headers = {"User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        t0 = time.time()
        r = requests.post(url, files=files, headers=headers, timeout=TIMEOUT)
        elapsed = time.time()-t0
        preview = (r.text or "")[:5000]
        return r.status_code, preview, elapsed
    except Exception as e:
        print(f"[!] Request exception for {url}: {repr(e)}")
        return None, repr(e), None

# -----------------------
# Main fuzzing loop
# -----------------------
def main():
    token = get_token_from_secrets_or_login()
    if token is None:
        print("[!] Warning: no auth token available. If endpoint requires auth this will yield 401 responses.")
    seeds = sorted([p for p in CORPUS_DIR.glob("*.pdf")])
    if not seeds:
        print(f"[!] No PDF seeds found in {CORPUS_DIR}. Please add at least one PDF.")
        return
    print(f"[+] Found {len(seeds)} seed(s). Target: {HOST.rstrip('/')}/{UPLOAD_PATH.lstrip('/')}")
    for i in range(ITERATIONS):
        seed = random.choice(seeds)
        try:
            base = seed.read_bytes()
        except Exception as e:
            print(f"[!] Failed to read seed {seed}: {e}")
            continue
        mutated = mutate_bytes(base)
        code, preview, elapsed = post_file(mutated, token)
        print(f"[{i}] seed={seed.name} status={code} time={elapsed}")

        # detect errors
        is_error = (code is None) or (isinstance(code,int) and code>=500) or \
                   ("traceback" in (preview or "").lower()) or ("segmentation" in (preview or "").lower())

        # handle 401
        if code == 401:
            print("[!] Received 401 Unauthorized.")
            if SAVE_ON_ERRORS:
                save_crash(mutated, seed.name, i, code, preview=preview)
                print(f" --> Saved 401 sample (iteration {i})")
            if PASSWORD_FILE.exists():
                new_token = get_token_from_secrets_or_login()
                if new_token and new_token != token:
                    token = new_token
                    print("[*] Token refreshed, continuing fuzzing")
                else:
                    time.sleep(1)
            continue

        if is_error and SAVE_ON_ERRORS:
            save_crash(mutated, seed.name, i, code, preview=preview)
            print(f" --> Saved crash sample (iteration {i})")
        time.sleep(0.05)

    print("[+] Finished fuzzing")

if __name__ == "__main__":
    main()
