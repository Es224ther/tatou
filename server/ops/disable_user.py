import os
import sys
import re
import json
from datetime import datetime

try:
    import pymysql
except ImportError:
    print("ERROR: PyMySQL not installed. Install with: pip install PyMySQL", file=sys.stderr)
    sys.exit(2)

def _req(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        print(f"ERROR: missing required env var {name}", file=sys.stderr)
        sys.exit(2)
    return v

def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {os.path.basename(sys.argv[0])} <login>", file=sys.stderr)
        sys.exit(1)
    login = sys.argv[1]

    # --- DB config from environment ---
    host = _req("DB_HOST")
    port = int(os.environ.get("DB_PORT", "3306"))
    user = _req("DB_USER")
    password = _req("DB_PASSWORD")
    dbname = _req("DB_NAME")
    column = os.environ.get("DISABLE_COLUMN", "is_disabled")

    # Guard against SQL injection via column name (env-controlled)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", column):
        print(f"ERROR: invalid DISABLE_COLUMN: {column!r}", file=sys.stderr)
        sys.exit(2)

    print(f"[*] Disabling user '{login}'…")

    # --- Connect & execute ---
    conn = pymysql.connect(
        host=host, port=port, user=user, password=password, database=dbname,
        autocommit=False, charset="utf8mb4", cursorclass=pymysql.cursors.Cursor,
    )
    affected = 0
    try:
        with conn.cursor() as cur:
            # Mirror the bash script's session setting
            cur.execute("SET SESSION sql_safe_updates=1;")
            # Parametrized UPDATE; column name is validated above
            sql = f"UPDATE Users SET {column}=%s WHERE login=%s LIMIT 1;"
            cur.execute(sql, (1, login))
            affected = cur.rowcount
        conn.commit()
    except pymysql.MySQLError as e:
        conn.rollback()
        # Common safe-updates error message is preserved to stderr
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(3)
    finally:
        conn.close()

    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    print(json.dumps({"event": "user_disabled", "login": login, "affected_rows": affected, "ts": ts}))

if __name__ == "__main__":
    main()
