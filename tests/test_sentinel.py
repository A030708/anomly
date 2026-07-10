import os


class TestSentinelConfig:
    def test_config_has_required_attrs(self):
        from sentinel_xdr.config import Config
        assert hasattr(Config, "SECRET_KEY")
        assert hasattr(Config, "SENTINEL_SHARED_SECRET")
        assert hasattr(Config, "ANOMALY_THRESHOLD")
        assert hasattr(Config, "VALID_SOURCES")
        assert "boltmart" in Config.VALID_SOURCES
        assert "warehouse_os" in Config.VALID_SOURCES

    def test_config_webhook_defaults(self):
        from sentinel_xdr.config import Config
        assert "5001" in Config.BOLTMART_WEBHOOK
        assert "5002" in Config.WAREHOUSE_WEBHOOK


class TestDatabaseModule:
    def test_database_functions_exist(self):
        import sentinel_xdr.database as db
        assert hasattr(db, "save_event")
        assert hasattr(db, "save_rejected_ingest")
        assert hasattr(db, "get_alerts_page")
        assert hasattr(db, "get_all_settings")
        assert hasattr(db, "get_dashboard_stats")


class TestAnomalyDetector:
    def test_detector_module_imports(self):
        import sentinel_xdr.anomaly_detector as ad
        assert hasattr(ad, "AnomalyDetector")

    def test_llm_analyzer_module_imports(self):
        import sentinel_xdr.llm_analyzer as llm
        assert hasattr(llm, "LLMAnalyzer")


class TestDetectionRules:
    def test_detection_rules_imports(self):
        import sentinel_xdr.detection_rules as dr
        assert hasattr(dr, "evaluate_event")
