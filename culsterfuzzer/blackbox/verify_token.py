import requests
from pathlib import Path

API_URL = "http://localhost:5000/api/user/me"  # 改成你服务器的验证端点
TOKEN_FILE = Path("../secrets/API_TOKEN")

token = TOKEN_FILE.read_text().strip()
headers = {"Authorization": f"Bearer {token}"}

r = requests.get(API_URL, headers=headers)

print(f"Status: {r.status_code}")
print("Response:", r.text)
