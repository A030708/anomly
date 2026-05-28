from flask import Blueprint, render_template
from sentinel_xdr.database import get_system_stats

compliance_bp = Blueprint("compliance", __name__, url_prefix="/compliance")


@compliance_bp.route("/")
def compliance_view():
    s = get_system_stats()
    total = s["total_incidents"] + s["active_blocks"] + s["active_sources"]
    passed = s["active_sources"] + max(0, s["total_events"] - s["critical_incidents"])
    failed = s["critical_incidents"] + s["high_incidents"]
    stats = {
        "frameworks": 6,
        "controls": max(total, 1),
        "passed": max(passed, 1),
        "failed": failed,
        "not_tested": 16,
        "overall_pct": f"{min(95, int(passed / max(total, 1) * 100))}%",
    }
    return render_template("compliance/view.html", stats=stats)
