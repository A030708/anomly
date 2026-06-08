import os
from dotenv import load_dotenv

env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
load_dotenv(env_path)


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "boltmart-dev-secret")

    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY") or os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    SENTINEL_URL = os.getenv("SENTINEL_URL", "http://127.0.0.1:5003/api/ingest")
    SENTINEL_SHARED_SECRET = os.getenv("SENTINEL_SHARED_SECRET", "sentinel-secure-key-123")

    RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
    RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")

    DELIVERY_FEE = 99
    FREE_DELIVERY_THRESHOLD = 2000

    APP_URL = os.getenv("APP_URL", "http://localhost:5001")

    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASS = os.getenv("SMTP_PASS", "")
    SMTP_FROM = os.getenv("SMTP_FROM", "noreply@boltmart.in")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")

    COMPANY_NAME = "BoltMart"
    COMPANY_ADDRESS = "BoltMart Logistics, Mumbai - 400001, India"
    COMPANY_GST = "27AABCU9603R1ZL"
