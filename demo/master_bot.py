#!/usr/bin/env python3
"""
BoltMart Attack Bot Simulator
Run from terminal to demonstrate Sentinel XDR detections.

Usage:
    python demo/master_bot.py scrape
    python demo/master_bot.py flood
    python demo/master_bot.py bulk
    python demo/master_bot.py honeypot
    python demo/master_bot.py crosssystem
    python demo/master_bot.py all
"""

import sys
import time
import random
import requests

BOLTMART_URL = "http://localhost:5001"
WAREHOUSEOS_URL = "http://localhost:5002"

FAKE_IPS = [
    "103.45.67.89",
    "49.36.128.200",
    "182.72.101.45",
    "203.0.113.55",
    "198.51.100.23",
    "192.168.100.10",
    "10.0.0.200",
]

FAKE_NAMES = [
    "Rahul Sharma", "Priya Patel", "Amit Kumar", "Neha Gupta",
    "Ravi Singh", "Pooja Verma", "Suresh Reddy", "Anjali Nair",
    "Deepak Joshi", "Meena Iyer", "Vikram Rao", "Kavita Das",
    "Arun Mehta", "Sunita Bose", "Rajesh Pandey", "Divya Menon",
    "Anil Kapoor", "Sarika Chauhan", "Mohan Das", "Lata Mangeshkar",
]

FAKE_ADDRESSES = [
    "Flat 4B, Sunrise Apartments, Pune",
    "12 MG Road, Bangalore",
    "45 Andheri East, Mumbai",
    "78 Koramangala, Bangalore",
    "23 Salt Lake, Kolkata",
]


def random_headers(ip):
    return {
        "X-Forwarded-For": ip,
        "User-Agent": "AttackBot/1.0",
    }


def bot_scrape():
    """Bot Attack 1: Product Scraper — hits all 12 products rapidly."""
    print("[Bot] Starting product scrape attack...")
    skus = [f"HW-{str(i).zfill(3)}" for i in range(1, 13)]
    ip = FAKE_IPS[0]

    for loop in range(5):
        for sku in skus:
            try:
                resp = requests.get(
                    f"{BOLTMART_URL}/product/{sku}",
                    headers=random_headers(ip),
                    timeout=5
                )
                print(f"  [{resp.status_code}] /product/{sku}")
            except Exception as e:
                print(f"  [ERR] {e}")
            time.sleep(0.4)

    print("[Bot] Scrape complete. 60 requests sent.")


def bot_flood():
    """Bot Attack 2: Fake Order Flood — 25 checkouts from same IP."""
    print("[Bot] Starting fake order flood attack...")
    ip = FAKE_IPS[1]
    session = requests.Session()

    session.get(f"{BOLTMART_URL}/shop", headers=random_headers(ip), timeout=5)
    session.get(f"{BOLTMART_URL}/product/HW-009", headers=random_headers(ip), timeout=5)

    for i in range(25):
        name = random.choice(FAKE_NAMES)
        data = {
            "name": name,
            "phone": f"9{random.randint(100000000, 999999999)}",
            "email": f"{name.split()[0].lower()}@fake.com",
            "address": random.choice(FAKE_ADDRESSES),
            "city": "Pune",
            "state": "Maharashtra",
            "pincode": f"41{random.randint(10000, 99999)}",
            "payment_method": "cod",
        }

        try:
            resp = session.post(
                f"{BOLTMART_URL}/checkout",
                data=data,
                headers=random_headers(ip),
                timeout=5,
                allow_redirects=False
            )
            print(f"  [{resp.status_code}] Checkout attempt {i+1}/25 as {name}")
        except Exception as e:
            print(f"  [ERR] {e}")

        time.sleep(0.2)

    print("[Bot] Flood complete. 25 checkout attempts sent.")


def bot_bulk_fraud():
    """Bot Attack 3: Bulk Order Fraud — high quantity, new session, zero browsing."""
    print("[Bot] Starting bulk order fraud attack...")
    ip = FAKE_IPS[2]
    session = requests.Session()

    session.post(
        f"{BOLTMART_URL}/cart/add",
        data={"sku": "HW-009", "quantity": "500"},
        headers=random_headers(ip),
        timeout=5,
        allow_redirects=False
    )

    data = {
        "name": "Bot Buyer",
        "phone": "9999999999",
        "email": "bot@fraud.com",
        "address": "123 Fake Street",
        "city": "Mumbai",
        "state": "Maharashtra",
        "pincode": "400001",
        "payment_method": "cod",
    }

    try:
        resp = session.post(
            f"{BOLTMART_URL}/checkout",
            data=data,
            headers=random_headers(ip),
            timeout=5,
            allow_redirects=False
        )
        print(f"  [{resp.status_code}] Bulk fraud checkout attempted (500x HW-009)")
    except Exception as e:
        print(f"  [ERR] {e}")

    print("[Bot] Bulk fraud complete.")


def bot_honeypot():
    """Bot Attack 4: Honeypot Probe — scans hidden routes."""
    print("[Bot] Starting honeypot probe attack...")
    ip = FAKE_IPS[3]
    honeypot_routes = ["/.env", "/admin", "/api/v1/users"]

    for route in honeypot_routes:
        try:
            resp = requests.get(
                f"{BOLTMART_URL}{route}",
                headers=random_headers(ip),
                timeout=5
            )
            print(f"  [{resp.status_code}] {route}")
        except Exception as e:
            print(f"  [ERR] {e}")
        time.sleep(0.5)

    print("[Bot] Honeypot probe complete.")


def bot_cross_system():
    """Bot Attack 5: Cross-system — get blocked on BoltMart, then hit WarehouseOS."""
    print("[Bot] Starting cross-system attack...")
    ip = FAKE_IPS[4]

    print("[Bot] Step 1: Hitting BoltMart honeypot to get blocked...")
    try:
        resp = requests.get(
            f"{BOLTMART_URL}/.env",
            headers=random_headers(ip),
            timeout=5
        )
        print(f"  [{resp.status_code}] /.env on BoltMart")
    except Exception as e:
        print(f"  [ERR] {e}")

    print("[Bot] Step 2: Waiting 5 seconds for Sentinel to block IP...")
    time.sleep(5)

    print("[Bot] Step 3: Attempting WarehouseOS access from blocked IP...")
    try:
        resp = requests.get(
            f"{WAREHOUSEOS_URL}/dashboard",
            headers=random_headers(ip),
            timeout=5
        )
        print(f"  [{resp.status_code}] /dashboard on WarehouseOS")
    except Exception as e:
        print(f"  [ERR] {e}")

    print("[Bot] Cross-system attack complete.")


def bot_order_enumeration():
    """Bot Attack 6: Order ID enumeration."""
    print("[Bot] Starting order ID enumeration attack...")
    ip = FAKE_IPS[5]

    for i in range(1, 51):
        order_id = f"ORD-2024-{str(i).zfill(4)}"
        try:
            resp = requests.get(
                f"{BOLTMART_URL}/track/{order_id}",
                headers=random_headers(ip),
                timeout=5
            )
            print(f"  [{resp.status_code}] /track/{order_id}")
        except Exception as e:
            print(f"  [ERR] {e}")
        time.sleep(0.1)

    print("[Bot] Enumeration complete. 50 order IDs probed.")


COMMANDS = {
    "scrape": bot_scrape,
    "flood": bot_flood,
    "bulk": bot_bulk_fraud,
    "honeypot": bot_honeypot,
    "crosssystem": bot_cross_system,
    "enum": bot_order_enumeration,
}


def run_all():
    print("=" * 60)
    print("  BOLTMART ATTACK BOT — RUNNING ALL SCENARIOS")
    print("=" * 60)

    for name, func in COMMANDS.items():
        print(f"\n{'='*60}")
        print(f"  ATTACK: {name.upper()}")
        print(f"{'='*60}")
        func()
        time.sleep(2)

    print("\n" + "=" * 60)
    print("  ALL ATTACKS COMPLETE")
    print("  Check Sentinel XDR dashboard for detections.")
    print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python demo/master_bot.py <command>")
        print(f"Commands: {', '.join(COMMANDS.keys())}, all")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "all":
        run_all()
    elif command in COMMANDS:
        COMMANDS[command]()
    else:
        print(f"Unknown command: {command}")
        print(f"Available: {', '.join(COMMANDS.keys())}, all")
        sys.exit(1)
