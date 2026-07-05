import time
import random
import string
from datetime import datetime, timezone, timedelta
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
    try:
        supabase = get_supabase()
        one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        result = supabase.table("orders").select("order_id", count="exact").eq("ip_address", identifier).in_("payment_status", ("failed", "abandoned")).gte("created_at", one_hour_ago).execute()
        count = result.count if hasattr(result, 'count') and result.count else len(result.data or [])
        total = count + 1
        print(f"[FAIL] IP {identifier} failed orders in last hour: {count}, this failure: {total}")
        return total
    except Exception as e:
        print(f"[FAIL] ERROR counting failures for {identifier}: {e}")
        return 1


def reset_payment_failures(identifier):
    pass


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
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
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
    
    # Parse the ISO datetime string
    expires_at_str = record["expires_at"].replace("Z", "+00:00")
    expires_at = datetime.fromisoformat(expires_at_str)
    
    if datetime.now(timezone.utc) > expires_at:
        supabase.table("password_resets").delete().eq("email", email).execute()
        return False
    if record["code"] == str(code).strip():
        supabase.table("password_resets").delete().eq("email", email).execute()
        return True
    return False


def set_checkout_block(email, duration_minutes=60):
    try:
        supabase = get_supabase()
        until = (datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)).isoformat()
        supabase.table("customers").update({"checkout_blocked_until": until}).eq("email", email).execute()
    except Exception:
        pass


def get_customer_name(email):
    try:
        supabase = get_supabase()
        result = supabase.table("customers").select("name").eq("email", email).limit(1).execute()
        return result.data[0]["name"] if result.data else "Customer"
    except Exception:
        return "Customer"


def is_checkout_blocked(email):
    if not email:
        return False
    try:
        supabase = get_supabase()
        result = supabase.table("customers").select("checkout_blocked_until").eq("email", email).limit(1).execute()
        if not result.data or not result.data[0].get("checkout_blocked_until"):
            return False
        blocked_until = datetime.fromisoformat(result.data[0]["checkout_blocked_until"].replace("Z", "+00:00"))
        if blocked_until > datetime.now(timezone.utc):
            return True
        supabase.table("customers").update({"checkout_blocked_until": None}).eq("email", email).execute()
    except Exception:
        pass
    return False
