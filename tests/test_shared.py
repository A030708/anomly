from shared.constants import (
    SENTINEL_SHARED_SECRET,
    ATTACK_BRUTE_FORCE,
    ATTACK_CREDENTIAL_STUFFING,
    SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL,
    THRESHOLD_LOW, THRESHOLD_MEDIUM, THRESHOLD_HIGH, THRESHOLD_CRITICAL,
    BLOCK_DURATION,
    ACTION_BLOCK_IP, ACTION_REVOKE_SESSION,
    ROUTE_SENSITIVITY,
    PRODUCTS, DEMO_USERS,
)


class TestConstants:
    def test_secret_is_string(self):
        assert isinstance(SENTINEL_SHARED_SECRET, str)
        assert len(SENTINEL_SHARED_SECRET) > 0

    def test_attack_types_are_strings(self):
        assert ATTACK_BRUTE_FORCE == "BRUTE_FORCE"
        assert ATTACK_CREDENTIAL_STUFFING == "CREDENTIAL_STUFFING"

    def test_severity_levels(self):
        assert SEV_LOW == "low"
        assert SEV_MEDIUM == "medium"
        assert SEV_HIGH == "high"
        assert SEV_CRITICAL == "critical"

    def test_thresholds_ordered(self):
        assert THRESHOLD_LOW < THRESHOLD_MEDIUM < THRESHOLD_HIGH < THRESHOLD_CRITICAL

    def test_block_durations(self):
        assert BLOCK_DURATION[SEV_LOW] == 30
        assert BLOCK_DURATION[SEV_CRITICAL] == 10080

    def test_actions_defined(self):
        assert ACTION_BLOCK_IP == "BLOCK_IP"
        assert ACTION_REVOKE_SESSION == "REVOKE_SESSION"

    def test_route_sensitivity_has_env_endpoint(self):
        assert "/.env" in ROUTE_SENSITIVITY
        assert ROUTE_SENSITIVITY["/.env"] == 1.0

    def test_products_have_required_fields(self):
        for p in PRODUCTS:
            assert "sku" in p
            assert "name" in p
            assert "price" in p
            assert "category" in p

    def test_demo_users_have_required_fields(self):
        for u in DEMO_USERS:
            assert "username" in u
            assert "email" in u
            assert "password" in u
            assert "role" in u


class TestDbClient:
    def test_get_supabase_raises_without_url(self, monkeypatch):
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
        from shared.db_client import get_supabase
        try:
            get_supabase.cache_clear()
            get_supabase()
            assert False, "Should have raised"
        except RuntimeError as e:
            assert "SUPABASE_URL" in str(e) or "SUPABASE_SERVICE_ROLE_KEY" in str(e)
        finally:
            get_supabase.cache_clear()

    def test_insert_row_helpers_exist(self):
        from shared.db_client import insert_row, update_rows, select_rows
        assert callable(insert_row)
        assert callable(update_rows)
        assert callable(select_rows)
