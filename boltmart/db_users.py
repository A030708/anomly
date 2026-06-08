import time
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
from shared.db_client import get_supabase


def generate_otp():
    return "".join(random.choices(string.digits, k=6))


def set_otp(email):
    code = generate_otp()
    expires_at = int(time.time()) + 300
    supabase = get_supabase()
    existing = supabase.table("otps").select("*").eq("email", email).execute()
    if existing.data:
        supabase.table("otps").update({"code": code, "expires_at": expires_at}).eq("email", email).execute()
    else:
        supabase.table("otps").insert({"email": email, "code": code, "expires_at": expires_at}).execute()
    return code


def get_otp(email):
    supabase = get_supabase()
    result = supabase.table("otps").select("code").eq("email", email).execute()
    return result.data[0]["code"] if result.data else None


def verify_otp(email, code):
    supabase = get_supabase()
    result = supabase.table("otps").select("*").eq("email", email).execute()
    if not result.data:
        return False
    record = result.data[0]
    if int(time.time()) > record["expires_at"]:
        supabase.table("otps").delete().eq("email", email).execute()
        return False
    if record["code"] == str(code).strip():
        supabase.table("otps").delete().eq("email", email).execute()
        return True
    return False


def record_payment_failure(identifier):
    supabase = get_supabase()
    existing = supabase.table("payment_failures").select("*").eq("identifier", identifier).execute()
    if existing.data:
        new_count = existing.data[0]["failure_count"] + 1
        supabase.table("payment_failures").update({"failure_count": new_count}).eq("identifier", identifier).execute()
        return new_count
    else:
        supabase.table("payment_failures").insert({"identifier": identifier, "failure_count": 1}).execute()
        return 1


def reset_payment_failures(identifier):
    supabase = get_supabase()
    supabase.table("payment_failures").delete().eq("identifier", identifier).execute()


def get_customer(email):
    supabase = get_supabase()
    result = supabase.table("customers").select("*").eq("email", email).execute()
    return result.data[0] if result.data else None


def create_customer(email, password, name, phone):
    supabase = get_supabase()
    existing = supabase.table("customers").select("email").eq("email", email).execute()
    if existing.data:
        return False
    hashed = generate_password_hash(password)
    supabase.table("customers").insert({
        "email": email,
        "password": hashed,
        "name": name,
        "phone": phone,
        "blocked": False
    }).execute()
    return True


def set_reset_code(email):
    code = generate_otp()
    expires_at = int(time.time()) + 300
    supabase = get_supabase()
    existing = supabase.table("password_resets").select("*").eq("email", email).execute()
    if existing.data:
        supabase.table("password_resets").update({"code": code, "expires_at": expires_at}).eq("email", email).execute()
    else:
        supabase.table("password_resets").insert({"email": email, "code": code, "expires_at": expires_at}).execute()
    return code


def verify_reset_code(email, code):
    supabase = get_supabase()
    result = supabase.table("password_resets").select("*").eq("email", email).execute()
    if not result.data:
        return False
    record = result.data[0]
    if int(time.time()) > record["expires_at"]:
        supabase.table("password_resets").delete().eq("email", email).execute()
        return False
    if record["code"] == str(code).strip():
        supabase.table("password_resets").delete().eq("email", email).execute()
        return True
    return False
