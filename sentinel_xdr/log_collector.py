# sentinel_xdr/log_collector.py

import logging
from datetime import datetime, timezone, timedelta
from shared.db_client import db

logger = logging.getLogger(__name__)


class LogCollector:
    """Collects context data for ML scoring and LLM analysis."""

    def gather_context(self, event: dict) -> dict:
        """Build full context for an event."""
        ip = event.get("ip", "")
        session_id = event.get("session_id", "")

        return {
            "recent_events_60s": self._get_recent_events(ip, seconds=60),
            "recent_events_10": self._get_last_n_events(ip, n=10),
            "failed_count_60s": self._get_failed_count(ip, seconds=60),
            "ip_history": self._get_ip_history(ip),
            "session_data": self._get_session_data(session_id),
            "order_stats": self._get_order_stats(),
        }

    def _get_recent_events(self, ip: str, seconds: int = 60) -> list:
        try:
            cutoff = (datetime.now(timezone.utc) -
                     timedelta(seconds=seconds)).isoformat()
            client = db.get_client()
            result = client.table("sentinel_events")\
                .select("*")\
                .eq("ip_address", ip)\
                .gte("created_at", cutoff)\
                .execute()
            return result.data or []
        except:
            return []

    def _get_last_n_events(self, ip: str, n: int = 10) -> list:
        try:
            client = db.get_client()
            result = client.table("sentinel_events")\
                .select("*")\
                .eq("ip_address", ip)\
                .order("created_at", desc=True)\
                .limit(n)\
                .execute()
            return result.data or []
        except:
            return []

    def _get_failed_count(self, ip: str, seconds: int = 60) -> int:
        try:
            cutoff = (datetime.now(timezone.utc) -
                     timedelta(seconds=seconds)).isoformat()
            client = db.get_client()
            result = client.table("sentinel_events")\
                .select("*", count="exact")\
                .eq("ip_address", ip)\
                .eq("event_type", "LOGIN_FAILURE")\
                .gte("created_at", cutoff)\
                .execute()
            return result.count or 0
        except:
            return 0

    def _get_ip_history(self, ip: str) -> dict:
        try:
            client = db.get_client()

            # All events from this IP
            all_events = client.table("sentinel_events")\
                .select("*")\
                .eq("ip_address", ip)\
                .execute()
            events = all_events.data or []

            # Check blocked_ips
            blocks = client.table("blocked_ips")\
                .select("*")\
                .eq("ip_address", ip)\
                .execute()
            prior_blocks = len(blocks.data or [])

            # Orders from this IP in 24h
            cutoff_24h = (datetime.now(timezone.utc) -
                         timedelta(hours=24)).isoformat()
            orders = client.table("orders")\
                .select("*")\
                .eq("ip_address", ip)\
                .gte("created_at", cutoff_24h)\
                .execute()
            order_count = len(orders.data or [])

            sources = set(e.get("source", "") for e in events)
            sessions = set(e.get("session_id", "") for e in events)

            # Check if blocked on other system currently
            now = datetime.now(timezone.utc)
            currently_blocked = False
            for block in (blocks.data or []):
                if block.get("blocked_until"):
                    blocked_until = datetime.fromisoformat(
                        block["blocked_until"].replace("Z", "+00:00")
                    )
                    if blocked_until > now:
                        currently_blocked = True
                        break

            first_seen = None
            if events:
                timestamps = sorted(e.get("created_at", "") for e in events)
                first_seen = timestamps[0][:19] if timestamps else None

            return {
                "first_seen": first_seen,
                "total_events": len(events),
                "prior_blocks": prior_blocks,
                "is_new": len(events) <= 1,
                "seen_on_boltmart": "boltmart" in sources,
                "seen_on_warehouse": "warehouse_os" in sources,
                "seen_on_both": len(sources) > 1,
                "blocked_on_other": currently_blocked,
                "order_count_24h": order_count,
                "failed_logins_24h": self._get_failed_count(ip, seconds=86400),
                "unique_sessions": len(sessions),
            }
        except Exception as e:
            logger.error(f"IP history error: {e}")
            return {
                "first_seen": None,
                "total_events": 0,
                "prior_blocks": 0,
                "is_new": True,
                "seen_on_boltmart": False,
                "seen_on_warehouse": False,
                "seen_on_both": False,
                "blocked_on_other": False,
                "order_count_24h": 0,
                "failed_logins_24h": 0,
                "unique_sessions": 1,
            }

    def _get_session_data(self, session_id: str) -> dict:
        try:
            client = db.get_client()
            result = client.table("sentinel_events")\
                .select("*")\
                .eq("session_id", session_id)\
                .order("created_at", desc=False)\
                .execute()
            events = result.data or []

            return {
                "total_events": len(events),
                "first_event": events[0]["created_at"] if events else None,
                "routes_visited": list(set(e.get("route") for e in events))
            }
        except:
            return {"total_events": 0, "first_event": None, "routes_visited": []}

    def _get_order_stats(self) -> dict:
        """Get order value statistics for zscore calculation."""
        try:
            client = db.get_client()
            result = client.table("orders").select("total_value").execute()
            values = [float(o.get("total_value", 0))
                     for o in (result.data or []) if o.get("total_value")]

            if len(values) < 10:
                return {"mean": 3000, "std": 2000}

            import numpy as np
            return {
                "mean": float(np.mean(values)),
                "std": float(np.std(values))
            }
        except:
            return {"mean": 3000, "std": 2000}
