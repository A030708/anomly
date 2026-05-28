from flask import Blueprint, render_template
from sentinel_xdr.database import get_system_stats

forensics_bp = Blueprint("forensics", __name__, url_prefix="/forensics")


@forensics_bp.route("/")
def forensics_view():
    s = get_system_stats()
    stats = {
        "total": s["total_incidents"],
        "pending": s["critical_incidents"] + s["high_incidents"],
        "in_progress": s["medium_incidents"],
        "completed": s["low_incidents"],
        "artifacts": s["total_events"] // 10 + 1,
        "exhibits": s["active_blocks"],
    }
    return render_template("forensics/view.html", stats=stats)
