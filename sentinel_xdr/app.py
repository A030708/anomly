# sentinel_xdr/app.py

import os
import sys
import json
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, Response, stream_with_context, redirect, url_for, session, flash

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_xdr.config import Config
import sentinel_xdr.database as database
from shared.db_client import get_supabase

from sentinel_xdr.blueprints.auth import auth_bp
from sentinel_xdr.blueprints.dashboard import dashboard_bp
from sentinel_xdr.blueprints.alerts import alerts_bp
from sentinel_xdr.blueprints.incidents import incidents_bp
from sentinel_xdr.blueprints.assets import assets_bp
from sentinel_xdr.blueprints.events import events_bp
from sentinel_xdr.blueprints.threat_intel import threat_intel_bp
from sentinel_xdr.blueprints.vulnerabilities import vulnerabilities_bp
from sentinel_xdr.blueprints.network import network_bp
from sentinel_xdr.blueprints.hunt import hunt_bp
from sentinel_xdr.blueprints.mitre import mitre_bp
from sentinel_xdr.blueprints.playbooks import playbooks_bp
from sentinel_xdr.blueprints.cases import cases_bp
from sentinel_xdr.blueprints.reports import reports_bp
from sentinel_xdr.blueprints.forensics import forensics_bp
from sentinel_xdr.blueprints.compliance import compliance_bp
from sentinel_xdr.blueprints.settings import settings_bp
from sentinel_xdr.blueprints.audit import audit_bp
from sentinel_xdr.blueprints.admin import admin_bp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Register all blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(incidents_bp)
app.register_blueprint(assets_bp)
app.register_blueprint(events_bp)
app.register_blueprint(threat_intel_bp)
app.register_blueprint(vulnerabilities_bp)
app.register_blueprint(network_bp)
app.register_blueprint(hunt_bp)
app.register_blueprint(mitre_bp)
app.register_blueprint(playbooks_bp)
app.register_blueprint(cases_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(forensics_bp)
app.register_blueprint(compliance_bp)
app.register_blueprint(settings_bp)
app.register_blueprint(audit_bp)
app.register_blueprint(admin_bp)

# Register connected systems for active response
from sentinel_xdr import active_response as ar
ar.register_connected_system("boltmart", Config.BOLTMART_WEBHOOK, Config.BOLTMART_WEBHOOK_SECRET)
ar.register_connected_system("warehouse_os", Config.WAREHOUSE_WEBHOOK, Config.WAREHOUSE_WEBHOOK_SECRET)
logger.info(f"Connected systems registered — BoltMart: {Config.BOLTMART_WEBHOOK}, WarehouseOS: {Config.WAREHOUSE_WEBHOOK}")

# Start background ingestion worker
from sentinel_xdr.worker import start_background_worker
start_background_worker()

def register_ingest_api(app):

    @app.post("/api/ingest")
    def ingest_event():
        request_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

        supplied_secret = request.headers.get("X-Sentinel-Secret")
        supplied_source = request.headers.get("X-Source")

        if supplied_secret != Config.SENTINEL_SHARED_SECRET:
            database.save_rejected_ingest(
                reason="Invalid or missing X-Sentinel-Secret",
                ip_address=request_ip,
                metadata={
                    "supplied_source": supplied_source
                }
            )

            return jsonify({
                "success": False,
                "error": "unauthorized"
            }), 401

        payload = request.get_json(silent=True)

        if not payload:
            database.save_rejected_ingest(
                reason="Missing or invalid JSON body",
                ip_address=request_ip
            )

            return jsonify({
                "success": False,
                "error": "invalid_json"
            }), 400

        required_fields = [
            "source",
            "timestamp",
            "ip",
            "route",
            "method",
            "event_type",
            "session_id"
        ]

        missing = [field for field in required_fields if field not in payload]

        if missing:
            database.save_rejected_ingest(
                reason="Missing required fields",
                ip_address=request_ip,
                metadata={
                    "missing": missing,
                    "payload": payload
                }
            )

            return jsonify({
                "success": False,
                "error": "missing_fields",
                "missing": missing
            }), 400

        if supplied_source != payload.get("source"):
            database.save_rejected_ingest(
                reason="X-Source does not match payload source",
                ip_address=request_ip,
                metadata={
                    "header_source": supplied_source,
                    "payload_source": payload.get("source")
                }
            )

            return jsonify({
                "success": False,
                "error": "source_mismatch"
            }), 400

        if payload.get("source") not in Config.VALID_SOURCES:
            database.save_rejected_ingest(
                reason="Invalid source",
                ip_address=request_ip,
                metadata={
                    "source": payload.get("source")
                }
            )

            return jsonify({
                "success": False,
                "error": "invalid_source"
            }), 400

        event = database.save_event(payload)

        from sentinel_xdr.message_queue import enqueue_event
        enqueue_event(event["event_id"])

        return jsonify({
            "success": True,
            "event_id": event["event_id"],
            "queued": True
        }), 200

register_ingest_api(app)


from sentinel_xdr.database import get_all_settings


@app.context_processor
def inject_globals():
    settings = get_all_settings()
    class CurrentUser:
        def __init__(self):
            self.username = session.get("username", "Analyst")
            self.role = session.get("role", "SOC Analyst")
            self.is_authenticated = session.get("sentinel_admin", False)
    return {
        "current_user": CurrentUser(),
        "timezone": session.get("timezone", settings.get("timezone", "Asia/Kolkata")),
        "platform_name": settings.get("platform_name", "Sentinel XDR"),
    }


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("sentinel_admin"):
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def verify_sentinel_secret(request_obj) -> bool:
    secret = request_obj.headers.get("X-Sentinel-Secret", "")
    return secret == Config.SENTINEL_SHARED_SECRET


# ─── ROOT REDIRECT ─────────────────────────────────────────────────────────

@app.route("/")
def root():
    if session.get("sentinel_admin"):
        return redirect(url_for("dashboard.index"))
    return redirect(url_for("auth.login"))


# ─── HEARTBEAT ──────────────────────────────────────────────────────────

@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    if not verify_sentinel_secret(request):
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"status": "ok"}), 200


# ─── SSE STREAMS ────────────────────────────────────────────────────────────

@app.route("/api/events/stream")
@login_required
def event_stream():
    def generate():
        last_seen = datetime.now(timezone.utc)
        while True:
            try:
                import time
                time.sleep(3)
                result = get_supabase().table("sentinel_events")\
                    .select("*")\
                    .gte("created_at", last_seen.isoformat())\
                    .order("created_at", desc=True)\
                    .limit(20)\
                    .execute()

                new_events = result.data or []
                if new_events:
                    last_seen = datetime.now(timezone.utc)
                    for evt in new_events:
                        data = json.dumps({
                            "event_id": evt.get("event_id"),
                            "source": evt.get("source"),
                            "ip": evt.get("ip_address"),
                            "route": evt.get("route"),
                            "event_type": evt.get("event_type"),
                            "score": evt.get("anomaly_score", 0),
                            "is_anomalous": evt.get("is_anomalous", False),
                            "timestamp": evt.get("created_at", "")[:19],
                        })
                        yield f"data: {data}\n\n"
                else:
                    yield f"data: {json.dumps({'heartbeat': True})}\n\n"
            except GeneratorExit:
                break
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@app.route("/api/incidents/stream")
@login_required
def incident_stream():
    def generate():
        last_seen = datetime.now(timezone.utc)
        import time
        while True:
            try:
                time.sleep(5)
                result = get_supabase().table("threat_incidents")\
                    .select("*")\
                    .gte("created_at", last_seen.isoformat())\
                    .execute()

                new = result.data or []
                if new:
                    last_seen = datetime.now(timezone.utc)
                    for inc in new:
                        yield f"data: {json.dumps(inc)}\n\n"
                else:
                    yield f"data: {json.dumps({'heartbeat': True})}\n\n"
            except GeneratorExit:
                break
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream"
    )


if __name__ == "__main__":
    app.run(debug=True, port=5003)
