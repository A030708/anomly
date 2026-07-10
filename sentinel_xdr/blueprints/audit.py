import csv
import io

from flask import Blueprint, render_template, Response

from sentinel_xdr.database import get_audit_logs
from shared.db_client import get_supabase

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


@audit_bp.route("/")
def audit_log():
    stats, logs = get_audit_logs()
    return render_template("audit/log.html", stats=stats, logs=logs)


@audit_bp.route("/export")
def export_audit():
    supa = get_supabase()
    resp = supa.table("sentinel_events").select("*").order("created_at", desc=True).limit(5000).execute()
    events = resp.data or []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "User", "Action", "Resource", "IP Address", "Status", "Details"])
    for e in events:
        writer.writerow([
            e.get("created_at", ""),
            e.get("user_id", ""),
            e.get("event_type", ""),
            e.get("route", ""),
            e.get("ip_address", ""),
            "failure" if e.get("is_anomalous") else "success",
            e.get("metadata", {}).get("reason", ""),
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=audit_log_export.csv"},
    )
