# sentinel_xdr/anomaly_detector.py

import numpy as np
import pickle
import os
import logging
from datetime import datetime, timezone, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.model_path = "sentinel_xdr/models/isolation_forest.pkl"
        self.scaler_path = "sentinel_xdr/models/scaler.pkl"
        self._load_or_train()

    def _load_or_train(self):
        """Load existing model or train a new one."""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
                with open(self.scaler_path, "rb") as f:
                    self.scaler = pickle.load(f)
                logger.info("Anomaly detector loaded from disk")
                return
            except Exception as e:
                logger.warning(f"Failed to load model: {e}. Training new model.")

        self._train_baseline()

    def _train_baseline(self):
        """Train on synthetic normal behavior data."""
        logger.info("Training anomaly detector on baseline data...")

        os.makedirs("sentinel_xdr/models", exist_ok=True)

        # Generate synthetic normal behavior
        np.random.seed(42)
        n_samples = 2000

        normal_data = []
        for _ in range(n_samples):
            hour = np.random.choice(range(8, 22), p=[
                0.03, 0.05, 0.08, 0.10, 0.12, 0.12,
                0.10, 0.10, 0.08, 0.08, 0.06, 0.05, 0.03
            ])

            sample = [
                hour / 23.0,                          # request_hour_norm
                1 if hour >= 8 and hour <= 20 else 0, # is_business_hours
                np.random.choice([0, 1], p=[0.6, 0.4]),  # method_is_post
                np.random.uniform(0.1, 0.5),           # route_sensitivity
                np.random.randint(1, 8),               # request_count_60s
                np.random.randint(1, 5),               # unique_routes_60s
                np.random.randint(0, 3),               # post_count_60s
                np.random.randint(0, 1),               # failed_count_60s
                np.random.randint(30, 600),            # session_age_seconds
                np.random.randint(1, 10),              # pages_viewed
                np.random.randint(1, 10),              # prior_orders (changed from 0 to match real data)
                np.random.choice([0, 1], p=[0.9, 0.1]), # is_new_ip
                np.random.uniform(500, 8000),          # order_value
                np.random.uniform(-0.5, 1.5),          # order_value_zscore
                0,                                     # items_exceed_stock
                0,                                     # single_sku_order
                np.random.uniform(0.2, 0.8),           # browse_to_buy_ratio
                0,                                     # ip_prior_blocks
                np.random.randint(0, 3),               # ip_order_count_24h
                0,                                     # ip_failed_logins_24h
                np.random.randint(1, 3),               # ip_unique_sessions
                0,                                     # ip_seen_on_both_systems
                0,                                     # ip_blocked_on_other
            ]
            normal_data.append(sample)

        X = np.array(normal_data)
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_scaled)

        # Save
        with open(self.model_path, "wb") as f:
            pickle.dump(self.model, f)
        with open(self.scaler_path, "wb") as f:
            pickle.dump(self.scaler, f)

        logger.info("Anomaly detector trained and saved")

    def build_feature_vector(self, event: dict, context: dict) -> np.ndarray:
        """Build the 23-feature vector for scoring."""
        now = datetime.now(timezone.utc)
        ts_str = event.get("timestamp", now.isoformat())

        try:
            if isinstance(ts_str, str):
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                ts = ts_str
        except:
            ts = now

        hour = ts.hour
        metadata = event.get("metadata", {})

        # Route sensitivity
        route = event.get("route", "/")
        sensitivity = 0.1
        from shared.constants import ROUTE_SENSITIVITY
        for route_key, score in ROUTE_SENSITIVITY.items():
            if route_key in route:
                sensitivity = max(sensitivity, score)

        recent_events = context.get("recent_events_60s", [])
        request_count = len(recent_events)
        unique_routes = len(set(e.get("route", "") for e in recent_events))
        post_count = sum(1 for e in recent_events if e.get("method") == "POST")
        failed_count = context.get("failed_count_60s", 0)

        session_age = metadata.get("session_age", 300)
        pages_viewed = metadata.get("prior_page_views", 3)
        prior_orders = metadata.get("prior_orders", 0)

        order_value = float(metadata.get("order_value", 0))
        order_mean = context.get("order_mean", 3000)
        order_std = context.get("order_std", 2000)
        zscore = (order_value - order_mean) / max(order_std, 1)

        items_exceed = 1 if metadata.get("items_exceed_stock", False) else 0
        single_sku = 1 if metadata.get("single_sku_order", False) else 0

        page_views = max(pages_viewed, 1)
        item_count = max(metadata.get("item_count", 1), 1)
        browse_ratio = min(page_views / item_count, 10.0)

        ip_history = context.get("ip_history", {})

        features = [
            hour / 23.0,
            1 if 8 <= hour <= 20 else 0,
            1 if event.get("method") == "POST" else 0,
            sensitivity,
            min(request_count, 200) / 200.0,
            min(unique_routes, 20) / 20.0,
            min(post_count, 50) / 50.0,
            min(failed_count, 20) / 20.0,
            min(session_age, 3600) / 3600.0,
            min(pages_viewed, 50) / 50.0,
            min(prior_orders, 10) / 10.0,
            1 if ip_history.get("is_new", True) else 0,
            min(order_value, 500000) / 500000.0,
            min(max(zscore, -3), 10) / 10.0,
            float(items_exceed),
            float(single_sku),
            min(browse_ratio, 10) / 10.0,
            min(ip_history.get("prior_blocks", 0), 5) / 5.0,
            min(ip_history.get("order_count_24h", 0), 20) / 20.0,
            min(ip_history.get("failed_logins_24h", 0), 20) / 20.0,
            min(ip_history.get("unique_sessions", 1), 10) / 10.0,
            1 if ip_history.get("seen_on_both", False) else 0,
            1 if ip_history.get("blocked_on_other", False) else 0,
        ]

        return np.array(features, dtype=np.float32)

    def score(self, event: dict, context: dict) -> float:
        """Return anomaly score 0.0 to 1.0."""
        features = self.build_feature_vector(event, context)

        try:
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            raw_score = self.model.decision_function(features_scaled)[0]
            # Convert to 0-1 range (more negative = more anomalous)
            normalized = 1 / (1 + np.exp(raw_score * 2))
            score = float(np.clip(normalized, 0.0, 1.0))
        except Exception as e:
            logger.error(f"Scoring error: {e}")
            score = 0.3

        # Apply hard-coded override rules
        score = self._apply_overrides(score, event, context)

        return round(score, 4)

    def _apply_overrides(self, score: float, event: dict, context: dict) -> float:
        """Apply deterministic override rules on top of ML score."""
        ip_history = context.get("ip_history", {})
        metadata = event.get("metadata", {})

        # Blocked on other system
        if ip_history.get("blocked_on_other", False):
            score = max(score, 0.95)

        # Items exceed stock on high-value order
        if (metadata.get("items_exceed_stock", False) and
                float(metadata.get("order_value", 0)) > 50000):
            score = max(score, 0.90)

        # Repeat offender
        if ip_history.get("prior_blocks", 0) > 2:
            score = max(score, 0.88)

        # High request velocity
        recent = context.get("recent_events_60s", [])
        if len(recent) > 100:
            score = max(score, 0.85)

        # Suspicious session behavior
        session_age = metadata.get("session_age", 999)
        order_value = float(metadata.get("order_value", 0))
        if session_age < 15 and order_value > 10000:
            score = max(score, 0.75)

        # Honeypot hit
        if event.get("event_type") == "HONEYPOT_HIT":
            score = max(score, 0.96)

        # Admin access by wrong role
        if (event.get("user_role") in ["staff", "vendor"] and
                "/admin" in event.get("route", "")):
            score = max(score, 0.92)

        return score

    def classify_severity(self, score: float) -> str:
        if score >= 0.90:
            return "critical"
        elif score >= 0.75:
            return "high"
        elif score >= 0.60:
            return "medium"
        else:
            return "low"

    def detect_attack_type(self, event: dict, context: dict) -> str:
        """Heuristically classify the type of attack."""
        from shared.constants import (
            ATTACK_HONEYPOT, ATTACK_PRIVILEGE_ESCALATION,
            ATTACK_BRUTE_FORCE, ATTACK_SCRAPING,
            ATTACK_FAKE_ORDER_FLOOD, ATTACK_BULK_ORDER_FRAUD,
            ATTACK_DATA_EXFILTRATION, ATTACK_CROSS_SYSTEM,
            ATTACK_INVENTORY_FRAUD
        )

        metadata = event.get("metadata", {})
        route = event.get("route", "")
        event_type = event.get("event_type", "")
        ip_history = context.get("ip_history", {})
        recent = context.get("recent_events_60s", [])

        if event_type == "HONEYPOT_HIT":
            return ATTACK_HONEYPOT

        if ip_history.get("blocked_on_other", False):
            return ATTACK_CROSS_SYSTEM

        if (event.get("user_role") in ["staff", "vendor"] and
                "/admin" in route):
            return ATTACK_PRIVILEGE_ESCALATION

        failed = [e for e in recent if e.get("event_type") == "LOGIN_FAILURE"]
        if len(failed) >= 5:
            users = set(e.get("metadata", {}).get("attempted_username", "")
                       for e in failed)
            if len(users) >= 3:
                from shared.constants import ATTACK_CREDENTIAL_STUFFING
                return ATTACK_CREDENTIAL_STUFFING
            return ATTACK_BRUTE_FORCE

        if event_type == "DATA_EXPORT":
            exports = [e for e in recent if e.get("event_type") == "DATA_EXPORT"]
            if len(exports) >= 3:
                return ATTACK_DATA_EXFILTRATION

        if event_type == "ORDER_PLACED":
            checkouts = [e for e in recent if e.get("event_type") in
                        ["ORDER_PLACED", "CHECKOUT_ATTEMPT"]]
            if len(checkouts) >= 5:
                return ATTACK_FAKE_ORDER_FLOOD
            if metadata.get("items_exceed_stock", False):
                return ATTACK_BULK_ORDER_FRAUD

        if event_type == "WRITE_OFF":
            return ATTACK_INVENTORY_FRAUD

        product_views = [e for e in recent if e.get("event_type") == "PRODUCT_VIEW"]
        if len(product_views) >= 20:
            return ATTACK_SCRAPING

        return "SUSPICIOUS_ACTIVITY"
