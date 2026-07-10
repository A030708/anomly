import os


class TestWarehouseConfig:
    def test_config_has_required_attrs(self):
        from warehouse_os.config import Config
        assert hasattr(Config, "SECRET_KEY")
        assert hasattr(Config, "SUPABASE_URL")
        assert hasattr(Config, "SENTINEL_URL")
        assert hasattr(Config, "SESSION_COOKIE_NAME")
        assert Config.SESSION_COOKIE_NAME == "warehouseos_session"

    def test_config_smtp_defaults(self):
        from warehouse_os.config import Config
        assert Config.SMTP_HOST == "smtp.gmail.com"
        assert Config.SMTP_PORT == 587


class TestWarehouseRoutes:
    def test_login_page(self, warehouse_client):
        resp = warehouse_client.get("/login")
        assert resp.status_code in (200, 302)

    def test_health_endpoint(self, warehouse_client):
        resp = warehouse_client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["service"] == "warehouse_os"

    def test_dashboard_redirects_when_not_logged_in(self, warehouse_client):
        resp = warehouse_client.get("/")
        assert resp.status_code == 302
        assert "/login" in resp.location

    def test_inventory_redirects_when_not_logged_in(self, warehouse_client):
        resp = warehouse_client.get("/inventory")
        assert resp.status_code == 302
        assert "/login" in resp.location
