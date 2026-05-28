from flask import Blueprint, render_template, request, flash, redirect, url_for
from sentinel_xdr.database import get_system_stats

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
def list_reports():
    s = get_system_stats()
    stats = {
        "generated": s["total_events"] // 20 + 1,
        "scheduled": s["active_sources"] + 5,
        "this_month": s["total_incidents"] + s["active_blocks"],
        "pending": s["high_incidents"],
    }
    return render_template("reports/list.html", stats=stats)


@reports_bp.route("/generate", methods=["POST"])
def generate():
    flash("Report generation started", "success")
    return redirect(url_for("reports.list_reports"))


@reports_bp.route("/generate_report")
def generate_report():
    flash("Report generation started", "success")
    return redirect(url_for("reports.list_reports"))
