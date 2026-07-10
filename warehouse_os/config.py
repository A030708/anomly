import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "warehouseos-dev-secret")

    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    SENTINEL_URL = os.getenv("SENTINEL_URL", "http://127.0.0.1:5003/api/ingest")
    SENTINEL_SHARED_SECRET = os.getenv("SENTINEL_SHARED_SECRET", "sentinel-xdr-shared-secret-2024")

    SESSION_COOKIE_NAME = "warehouseos_session"

    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
    SMTP_FROM = os.getenv("SMTP_FROM")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
