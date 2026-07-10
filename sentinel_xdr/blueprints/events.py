import csv
import io
import json

from flask import Blueprint, render_template, request, Response

from sentinel_xdr.database import get_events_page, get_event_stats
from shared.db_client import get_supabase

events_bp = Blueprint("events", __name__, url_prefix="/events")


@events_bp.route("/")
def list_events():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    events, pagination = get_events_page(page, per_page)
    stats = get_event_stats()

    return render_template("events/list.html", events=events, stats=stats, pagination=pagination)


@events_bp.route("/export")
def export_events():
    supa = get_supabase()
    resp = supa.table("sentinel_events").select("*").order("created_at", desc=True).limit(5000).execute()
    events = resp.data or []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Type", "Source", "Description", "User", "Source IP", "Raw Log"])
    for e in events:
        metadata = e.get("metadata") or {}
        writer.writerow([
            e.get("created_at", ""),
            e.get("event_type", ""),
            e.get("source", ""),
            e.get("route") or e.get("event_type", ""),
            e.get("user_id") or "SYSTEM",
            e.get("ip_address", ""),
            json.dumps(metadata, indent=2) if metadata else "",
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=events_export.csv"},
    )
