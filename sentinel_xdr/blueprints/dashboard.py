from flask import Blueprint, render_template, jsonify
from datetime import datetime, timezone
from sentinel_xdr.database import (
    get_dashboard_stats, get_chart_data, list_recent_alerts,
    get_recent_activity, get_top_threats
)

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@dashboard_bp.route("/")
def index():
    stats = get_dashboard_stats()
    chart_labels, chart_data = get_chart_data()
    recent_alerts = list_recent_alerts(5)
    activities = get_recent_activity(5)
    top_threats = get_top_threats(5)
    return render_template("dashboard/index.html",
                           stats=stats,
                           recent_alerts=recent_alerts,
                           chart_labels=chart_labels,
                           chart_data=chart_data,
                           activities=activities,
                           top_threats=top_threats,
                           now=datetime.now(timezone.utc))


@dashboard_bp.route("/api/stats")
def api_stats():
    return jsonify(get_dashboard_stats())


@dashboard_bp.route("/api/recent_anomalies")
def api_recent_anomalies():
    alerts = list_recent_alerts(15)
    now = datetime.now(timezone.utc)
    
    formatted_alerts = []
    for a in alerts:
        diff = now - a["created_at"]
        seconds = diff.total_seconds()
        
        if seconds < 60:
            time_ago = "Just now"
        elif seconds < 3600:
            mins = int(seconds / 60)
            time_ago = f"{mins}m ago"
        elif seconds < 86400:
            hrs = int(seconds / 3600)
            time_ago = f"{hrs}h ago"
        else:
            days = int(seconds / 86400)
            time_ago = f"{days}d ago"
            
        formatted_alerts.append({
            "title": a["title"],
            "alert_type": a["alert_type"],
            "severity": a["severity"],
            "time_ago": time_ago
        })
        
    return jsonify({"anomalies": formatted_alerts})

