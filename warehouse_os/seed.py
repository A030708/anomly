import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
from supabase import create_client
from werkzeug.security import generate_password_hash

load_dotenv()

USERS = [
    {
        "username": "admin_sarah",
        "email": "admin@warehouse.com",
        "password_hash": generate_password_hash("demo123"),
        "role": "admin",
        "department": "IT",
        "is_active": True,
    },
    {
        "username": "manager_rahul",
        "email": "manager@warehouse.com",
        "password_hash": generate_password_hash("demo123"),
        "role": "manager",
        "department": "Operations",
        "is_active": True,
    },
    {
        "username": "staff_amit",
        "email": "staff@warehouse.com",
        "password_hash": generate_password_hash("demo123"),
        "role": "staff",
        "department": "Fulfillment",
        "is_active": True,
    },
    {
        "username": "delivery_vikas",
        "email": "delivery@warehouse.com",
        "password_hash": generate_password_hash("demo123"),
        "role": "delivery",
        "department": "Logistics",
        "is_active": True,
    },
]


def seed_users():
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    if not url or not key:
        print("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY")
        return

    client = create_client(url, key)

    existing = client.table("users").select("*").limit(1).execute().data
    if existing:
        print(f"Found existing users. Skipping seed.")
        return

    result = client.table("users").insert(USERS).execute()
    if result.data:
        print(f"Seeded {len(result.data)} users!")
        for u in result.data:
            print(f"  {u['email']} (Role: {u['role']}) - Password: demo123")
    else:
        print("Failed to insert users")


if __name__ == "__main__":
    seed_users()
