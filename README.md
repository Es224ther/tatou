# Tatou 
A web platform for PDF watermarking.  
This project is intended for pedagogical use and contains known security vulnerabilities.  
Do **not** deploy it on an open or public network.

---

## 1) Overview
Tatou is a Flask-based secure PDF watermarking system designed for the Software Security course at Stockholm University.  
It integrates the RMAP (Roger Michael Authentication Protocol) to enable secure communication and watermark sharing between servers.  
The system provides REST APIs for uploading, creating, and reading watermarked PDF files.

---

## 2) Features
- **Multiple watermarking methods**
  - Invisible text watermark
  - XMP metadata watermark (secret via `TATOU_XMP_SECRET`)
  - Attachment-based watermark
- **RMAP-based exchange** between Tatou instances
- **REST APIs**: upload, create watermark, read watermark, fetch docs
- **Dockerized** stack with MariaDB
- **Testing**: `pytest` unit tests & `mutmut` mutation tests
- **Observability**: JSON logs, example log scanner & export scripts

---

## 3) Quick Start (Deployment)
**Prereqs:** Docker, Docker Compose v2, `curl`; for API smoke tests also install `jq`.

```bash
# Clone
git clone https://github.com/Es224ther/tatou.git
cd tatou

# Configure
cp sample.env .env   # edit passwords/secrets (see section 4)

# Run
docker compose up --build -d

# Health check
curl -sS http://127.0.0.1:5000/api/healthz
```

Open: http://127.0.0.1:5000

---

## 4) Configuration (.env)
```dotenv
# Database (compose service name is usually `db`)
DB_HOST=db
DB_PORT=3306
DB_NAME=tatou
DB_USER=user-name
DB_PASSWORD=change-me

# XMP watermark
TATOU_XMP_SECRET=change-me

# RMAP keys (mounted read-only)
RMAP_SERVER_KEYS_DIR=/app/secrets/server
RMAP_CLIENT_KEYS_DIR=/app/secrets/clients
```
> On host, create: `deploy/secrets/{server,clients}` and mount them via docker-compose.

**docker-compose.yml (snippet):**
```yaml
services:
  server:
    env_file: .env
    volumes:
      - ./deploy/secrets/server:/app/secrets/server:ro
      - ./deploy/secrets/clients:/app/secrets/clients:ro
      - ./server/storage:/app/storage
    ports: ["5000:5000"]
```

**Keys layout (host):**
```
deploy/secrets/
  server/{server_pub.asc, server_priv.asc}
  clients/GroupXX_public.asc
```

---

## 5) Minimal API
- `POST /api/create-user`            → body: {login,email,password}
- `POST /api/login`                  → returns bearer token
- `POST /api/upload`                 → multipart PDF (auth)
- `POST /api/create-watermark/<doc_id>` → embed watermark (auth)
- `GET  /api/read-watermark/<doc_id>`   → extract watermark (auth)
- `POST /api/rmap-initiate` & `POST /api/rmap-get-link` → inter-server RMAP

---

## 6) Tests

### 6.1 Unit tests (pytest)
```bash
cd server
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -v
```

### 6.2 Coverage
```bash
pytest --cov=server/src --cov-report=html
# Open coverage report
xdg-open htmlcov/index.html || open htmlcov/index.html
```

### 6.3 Mutation tests (mutmut)
Create a `setup.cfg` at the project root:

```ini
[mutmut]
runner = pytest -q
tests_dir = server/test
paths_to_mutate = server/src
use_coverage = true
timeout = 15
exclude = server/test*,server/static*,server/storage*,server/logs*
```

Run:
```bash
mutmut run
mutmut results
mutmut html
open html/index.html || xdg-open html/index.html
```

### 6.4 API tests (smoke, end-to-end via curl)
> Requires `jq` and a local PDF at `/path/to/sample.pdf`.

```bash
BASE=http://127.0.0.1:5000

# 1) Create user
curl -sS -X POST $BASE/api/create-user   -H 'Content-Type: application/json'   -d '{"login":"demo","email":"demo@example.com","password":"Passw0rd!"}'

# 2) Login → grab bearer
TOKEN=$(curl -sS -X POST $BASE/api/login   -H 'Content-Type: application/json'   -d '{"email":"demo@example.com","password":"Passw0rd!"}' | jq -r .token)

# 3) Upload a PDF
curl -sS -X POST $BASE/api/upload   -H "Authorization: Bearer $TOKEN"   -F "file=@/path/to/sample.pdf" -F "name=sample" | tee /tmp/upload.json
DOC_ID=$(jq -r .id /tmp/upload.json)

# 4) Create watermark (example: XMP)
curl -sS -X POST $BASE/api/create-watermark/$DOC_ID   -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json'   -d '{"method":"xmp","position":"meta","key":"","secret":"test-secret","intended_for":"Group_X"}'

# 5) Read watermark
curl -sS -X GET $BASE/api/read-watermark/$DOC_ID   -H "Authorization: Bearer $TOKEN"
```

### 6.5 RMAP endpoint tests (inter-group)
RMAP enables secure exchange between Tatou instances.

1. Ensure server keys and client public keys are mounted as shown in **Configuration**.  
2. (If testing inside a venv) install the reference RMAP library:
   ```bash
   pip install "rmap @ git+https://github.com/nharrand/RMAP-Server.git@v2.0.0"
   ```
3. Use the library or your `rmap-client` to construct Message-1/Message-2 payloads and hit:
   - `POST /api/rmap-initiate`  → returns payload with `nonceClient` and `nonceServer`
   - `POST /api/rmap-get-link`  → returns `{"result":"<32-hex>"}` (secret/link handle)

**Expected:** `rmap-get-link` responds with a 32-hex token; server generates and records the associated watermarked PDF prior to replying (verify via logs).

---

## 7) Logs
Export current container logs:
```bash
mkdir -p exports
C=tatou-server-1
sudo docker logs --timestamps "$C" > exports/${C}_ALL_$(date -u +%Y%m%dT%H%M%SZ).log 2>&1
```

---

## 8) Notes
- **Security**: project intentionally contains weaknesses for pedagogy.
- **Secrets**: never commit `.env` or private keys; ensure `chmod 400 server_priv.asc`.
- **Storage**: persisted under `server/storage` (mounted volume).


