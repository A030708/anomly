from flask import Blueprint, render_template
from sentinel_xdr.database import get_system_stats

mitre_bp = Blueprint("mitre", __name__, url_prefix="/mitre")


@mitre_bp.route("/")
def mitre_map():
    s = get_system_stats()
    detected = s["critical_incidents"] + s["high_incidents"]
    covered = detected + s["medium_incidents"]
    total = max(detected + covered + s["low_incidents"] + 10, 1)
    stats = {
        "detected": detected,
        "covered": covered,
        "hunting": s["medium_incidents"],
        "partial": s["low_incidents"],
        "no_coverage": 19,
        "total": total,
        "coverage_pct": min(95, int((detected + covered) / total * 100)),
    }
    return render_template("mitre/map.html", stats=stats)
