import requests
import time
from pathlib import Path
import sys

# è®©è„šæœ¬åŸºäºŽè‡ªèº«ä½�ç½®å®šä½�æ–‡ä»¶ï¼ˆæ›´å�¥å£®ï¼‰
HERE = Path(__file__).resolve().parent
TARGET = "http://127.0.0.1:5000/api/login"   # <- è‹¥éœ€è¦�æ”¹ç›®æ ‡ï¼Œè¯·ä¿®æ”¹è¿™é‡Œ
PAYLOAD_FILE = HERE / "json_payloads.txt"
OUT = HERE.parent / "reports" / "logs" / "json_fuzz_log.txt"
OUT.parent.mkdir(parents=True, exist_ok=True)

def load_payloads():
    if not PAYLOAD_FILE.exists():
        print(f"Payload file missing: {PAYLOAD_FILE}")
        return []
    lines = PAYLOAD_FILE.read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]

def append_log(line):
    with OUT.open("a", encoding="utf-8") as f:
        f.write(line)

def main():
    payloads = load_payloads()
    if not payloads:
        print("No payloads to test. Please check", PAYLOAD_FILE)
        return
    for i, p in enumerate(payloads):
        body = {"email": p, "password": "password123"}
        ts = int(time.time())
        try:
            r = requests.post(TARGET, json=body, timeout=10)
            s = f"{ts}\t{i}\t{r.status_code}\t{len(r.content)}\t{p}\n"
        except Exception as e:
            s = f"{ts}\t{i}\tERR\t{e}\t{p}\n"
        print(s, end="")
        append_log(s)
        time.sleep(0.1)

if __name__ == "__main__":
    main()
