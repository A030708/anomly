import threading
import requests
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request, g, jsonify, session as flask_session, render_template

from warehouse_os.config import Config
from shared.db_client import get_supabase


def _send_to_sentinel(payload):
    headers = {
        "X-Sentinel-Secret": Config.SENTINEL_SHARED_SECRET,
        "X-Source": "warehouse_os",
        "Content-Type": "application/json",
    }
    try:
        requests.post(Config.SENTINEL_URL, json=payload, headers=headers, timeout=2)
    except Exception:
        pass


def get_request_ip():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()
    return ip


def get_response_status(result):
    try:
        if hasattr(result, "status_code"):
            return result.status_code
        if isinstance(result, tuple) and len(result) >= 2 and isinstance(result[1], int):
            return result[1]
        return 200
    except Exception:
        return 200


def sentinel_monitor(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)

        metadata = {
            "user_agent": request.headers.get("User-Agent"),
            "method": request.method,
            "response_status": get_response_status(result),
        }

        extra = getattr(g, "telemetry_metadata", None)
        if extra:
            metadata.update(extra)

        event_payload = {
            "source": "warehouse_os",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": get_request_ip(),
            "route": request.path,
            "method": request.method,
            "event_type": getattr(g, "event_type", f"PAGE_VIEW_{request.method}"),
            "session_id": flask_session.get("session_id", "anonymous"),
            "user_id": (flask_session.get("user") or {}).get("id"),
            "user_role": (flask_session.get("user") or {}).get("role"),
            "metadata": metadata,
        }

        _send_to_sentinel(event_payload)
        return result

    return wrapper


def check_blocked_ip_middleware(app):
    @app.before_request
    def before_request_check():
        if request.path.startswith("/static") or request.path == "/health":
            return

        ip = get_request_ip()

        try:
            blocks = get_supabase().table("blocked_ips").select("*").eq("ip_address", ip).execute().data or []
            active_block = None

            for b in blocks:
                if not b.get("blocked_until"):
                    continue
                until_time = datetime.fromisoformat(b["blocked_until"].replace("Z", "+00:00"))
                if until_time > datetime.now(timezone.utc):
                    active_block = b
                    break
                else:
                    get_supabase().table("blocked_ips").delete().eq("id", b["id"]).execute()

            if active_block:
                g.is_blocked = True
                return render_template(
                    "403.html",
                    ip=ip,
                    reason=active_block.get("reason"),
                    severity=active_block.get("severity"),
                    incident_id=active_block.get("incident_id"),
                    until=active_block.get("blocked_until"),
                ), 403

        except Exception:
            pass

        g.is_blocked = False

    return app


def register_defense_webhook(app):
    @app.route("/api/defense_webhook", methods=["POST"])
    def defense_webhook():
        payload = request.get_json(silent=True)
        if not payload:
            return jsonify({"success": False}), 400

        action = payload.get("action")
        ip_address = payload.get("ip")

        if action == "BLOCK_IP" and ip_address:
            blocked_until = (
                datetime.now(timezone.utc) + timedelta(minutes=payload.get("duration_minutes", 60))
            ).isoformat()

            get_supabase().table("blocked_ips").upsert({
                "ip_address": ip_address,
                "reason": payload.get("reason"),
                "severity": payload.get("severity"),
                "blocked_until": blocked_until,
                "incident_id": payload.get("incident_id"),
                "blocked_by": "sentinel_xdr",
            }, on_conflict="ip_address").execute()

            return jsonify({"success": True}), 200

        return jsonify({"success": False}), 400

    return app
