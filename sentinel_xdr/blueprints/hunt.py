from flask import Blueprint, render_template
from sentinel_xdr.database import get_system_stats

hunt_bp = Blueprint("hunt", __name__, url_prefix="/hunt")


@hunt_bp.route("/")
def hunting():
    s = get_system_stats()
    stats = {
        "queries_run": s["total_events"] // 10 + 1,
        "hits_found": s["total_incidents"] + s["active_blocks"],
        "saved_queries": s["active_sources"] + 5,
        "active_hunts": s["high_incidents"] + s["medium_incidents"],
        "avg_response": "0.9s",
    }
    return render_template("hunt/hunting.html", stats=stats)
