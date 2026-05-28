import time
import random
import string

CUSTOMERS = {}  # email -> {password, name, phone, email, blocked}
OTP_CODES = {}  # email -> {code, expires_at}
PAYMENT_FAILURES = {}  # email/ip -> count

def generate_otp():
    return "".join(random.choices(string.digits, k=6))

def set_otp(email):
    code = generate_otp()
    OTP_CODES[email] = {
        "code": code,
        "expires_at": time.time() + 300  # 5 mins
    }
    return code

def verify_otp(email, code):
    record = OTP_CODES.get(email)
    if not record:
        return False
    if time.time() > record["expires_at"]:
        return False
    if record["code"] == str(code).strip():
        del OTP_CODES[email]
        return True
    return False

def record_payment_failure(identifier):
    if identifier not in PAYMENT_FAILURES:
        PAYMENT_FAILURES[identifier] = 0
    PAYMENT_FAILURES[identifier] += 1
    return PAYMENT_FAILURES[identifier]

def reset_payment_failures(identifier):
    if identifier in PAYMENT_FAILURES:
        del PAYMENT_FAILURES[identifier]

def get_customer(email):
    return CUSTOMERS.get(email)

def create_customer(email, password, name, phone):
    if email in CUSTOMERS:
        return False
    CUSTOMERS[email] = {
        "email": email,
        "password": password,
        "name": name,
        "phone": phone,
        "blocked": False
    }
    return True
