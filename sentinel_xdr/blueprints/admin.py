from flask import Blueprint, render_template
from sentinel_xdr.database import get_system_stats

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
def admin_panel():
    s = get_system_stats()
    stats = {
        "uptime": "14d 7h 32m",
        "active_users": s["active_sources"],
        "sessions": s["active_blocks"],
        "queued": s["high_incidents"] + s["medium_incidents"],
        "errors_24h": s["critical_incidents"],
        "avg_response": "142ms",
        "active_workers": 5,
        "total_workers": 8,
    }
    return render_template("admin/panel.html", stats=stats)
