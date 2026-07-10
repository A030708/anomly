import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret")

    SENTINEL_SHARED_SECRET = os.getenv(
        "SENTINEL_SHARED_SECRET",
        "sentinel-xdr-shared-secret-2024"
    )

    ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.85"))

    VALID_SOURCES = {"boltmart", "warehouse_os", "sentinel_xdr"}

    BOLTMART_WEBHOOK = os.getenv("BOLTMART_WEBHOOK", "http://localhost:5001/api/defense_webhook")
    WAREHOUSE_WEBHOOK = os.getenv("WAREHOUSE_WEBHOOK", "http://localhost:5002/api/defense_webhook")
    BOLTMART_WEBHOOK_SECRET = os.getenv("BOLTMART_WEBHOOK_SECRET", "boltmart-webhook-secret")
    WAREHOUSE_WEBHOOK_SECRET = os.getenv("WAREHOUSE_WEBHOOK_SECRET", "warehouse-webhook-secret")

    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASS = os.getenv("SMTP_PASS", "")
    SMTP_FROM = os.getenv("SMTP_FROM", "sentinel@boltmart.in")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "abhiramkm2003@gmail.com")
