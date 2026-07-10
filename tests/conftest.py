import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

os.environ["FLASK_SECRET_KEY"] = "test-secret"
os.environ["SUPABASE_URL"] = "https://test.supabase.co"
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QiLCJpYXQiOjE1MTYyMzkwMjJ9.3t3J9s7QoPGqNcqJNfyL3e6ZnZ7wPKUaJf6HI4vWDEg"
os.environ["SENTINEL_SHARED_SECRET"] = "test-secret"
os.environ["ANOMALY_THRESHOLD"] = "0.5"
os.environ["FLASK_ENV"] = "testing"


@pytest.fixture
def boltmart_app():
    from boltmart.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def boltmart_client(boltmart_app):
    return boltmart_app.test_client()


@pytest.fixture
def warehouse_app():
    from warehouse_os.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def warehouse_client(warehouse_app):
    return warehouse_app.test_client()
