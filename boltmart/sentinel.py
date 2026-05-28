import threading
import requests
import time
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import request, g, jsonify, session as flask_session, render_template

from boltmart.config import Config
from shared.db_client import get_supabase


def _send_to_sentinel(payload):
    headers = {
        "X-Sentinel-Secret": Config.SENTINEL_SHARED_SECRET,
        "X-Source": "boltmart",
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
        if isinstance(result, tuple) and len(result) >= 2:
            if isinstance(result[1], int):
                return result[1]
        return 200
    except Exception:
        return 200


def sentinel_monitor(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)

        ip_address = get_request_ip()

        metadata = {
            "user_agent": request.headers.get("User-Agent"),
            "referrer": request.headers.get("Referer"),
            "method": request.method,
            "response_status": get_response_status(result),
        }

        extra_metadata = getattr(g, "telemetry_metadata", None)
        if extra_metadata:
            metadata.update(extra_metadata)

        event_payload = {
            "source": "boltmart",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": ip_address,
            "route": request.path,
            "method": request.method,
            "event_type": getattr(g, "event_type", f"PAGE_VIEW_{request.method}"),
            "session_id": flask_session.get("sid", "anonymous"),
            "user_id": None,
            "user_role": None,
            "metadata": metadata,
        }

        threading.Thread(target=_send_to_sentinel, args=(event_payload,), daemon=True).start()

        return result

    return wrapper


def check_blocked_ip_middleware(app):
    @app.before_request
    def before_request_check():
        if request.path.startswith("/static") or request.path in ("/health", "/api/defense_webhook"):
            return

        ip = get_request_ip()

        try:
            response = (
                get_supabase()
                .table("blocked_ips")
                .select("*")
                .eq("ip_address", ip)
                .execute()
            )

            blocks = response.data or []
            active_block = None

            for b in blocks:
                until_str = b.get("blocked_until")
                if not until_str:
                    continue
                until_time = datetime.fromisoformat(until_str.replace("Z", "+00:00"))
                if until_time > datetime.now(timezone.utc):
                    active_block = b
                    break
                else:
                    get_supabase().table("blocked_ips").delete().eq("id", b["id"]).execute()

            if active_block:
                g.is_blocked = True
                g.block_info = active_block
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
            return jsonify({"success": False, "error": "invalid_json"}), 400

        action = payload.get("action")
        ip_address = payload.get("ip")
        reason = payload.get("reason", "")
        severity = payload.get("severity", "medium")
        duration_minutes = payload.get("duration_minutes", 60)
        incident_id = payload.get("incident_id")
        groq_summary = payload.get("groq_summary", "")

        if not all([action, ip_address]):
            return jsonify({"success": False, "error": "missing_fields"}), 400

        if action == "BLOCK_IP":
            blocked_until = (
                datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
            ).isoformat()

            record = {
                "ip_address": ip_address,
                "reason": reason,
                "severity": severity,
                "blocked_until": blocked_until,
                "incident_id": incident_id,
                "groq_summary": groq_summary,
                "blocked_by": "sentinel_xdr",
            }

            get_supabase().table("blocked_ips").upsert(record, on_conflict="ip_address").execute()

            return jsonify({
                "success": True,
                "action_taken": "BLOCKED",
                "ip": ip_address,
                "incident_id": incident_id,
            }), 200

        return jsonify({"success": False, "error": "unsupported_action"}), 400

    return app
