import os


class TestBoltMartConfig:
    def test_config_has_required_attrs(self):
        from boltmart.config import Config
        assert hasattr(Config, "SECRET_KEY")
        assert hasattr(Config, "SUPABASE_URL")
        assert hasattr(Config, "DELIVERY_FEE")
        assert hasattr(Config, "FREE_DELIVERY_THRESHOLD")
        assert Config.DELIVERY_FEE == 99
        assert Config.FREE_DELIVERY_THRESHOLD == 2000

    def test_config_razorpay_defaults(self):
        from boltmart.config import Config
        assert hasattr(Config, "RAZORPAY_KEY_ID")
        assert hasattr(Config, "RAZORPAY_KEY_SECRET")

    def test_config_smtp_defaults(self):
        from boltmart.config import Config
        assert Config.SMTP_HOST == "smtp.gmail.com"
        assert Config.SMTP_PORT == 587


class TestBoltMartRoutes:
    def test_home_page(self, boltmart_client):
        resp = boltmart_client.get("/")
        assert resp.status_code in (200, 302)

    def test_shop_route_exists(self, boltmart_app):
        rules = [r.rule for r in boltmart_app.url_map.iter_rules()]
        assert "/shop" in rules

    def test_cart_page(self, boltmart_client):
        resp = boltmart_client.get("/cart")
        assert resp.status_code in (200, 302)

    def test_health_endpoint(self, boltmart_client):
        resp = boltmart_client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["service"] == "boltmart"

    def test_honeypot_returns_403(self, boltmart_client):
        resp = boltmart_client.get("/.env")
        assert resp.status_code == 403

    def test_honeypot_admin_returns_403(self, boltmart_client):
        resp = boltmart_client.get("/admin")
        assert resp.status_code == 403

    def test_register_page_get(self, boltmart_client):
        resp = boltmart_client.get("/register")
        assert resp.status_code in (200, 302)

    def test_login_page_get(self, boltmart_client):
        resp = boltmart_client.get("/login")
        assert resp.status_code in (200, 302)

    def test_forgot_password_page(self, boltmart_client):
        resp = boltmart_client.get("/forgot-password")
        assert resp.status_code in (200, 302)
