from flask import Blueprint, render_template, request, redirect, url_for, flash

from sentinel_xdr.database import get_alerts_page, get_alert_stats, get_alert_detail

alerts_bp = Blueprint("alerts", __name__, url_prefix="/alerts")


@alerts_bp.route("/")
def list_alerts():
    page = request.args.get("page", 1, type=int)
    alerts, pagination = get_alerts_page(page)
    stats = get_alert_stats()
    return render_template("alerts/list.html", alerts=alerts, stats=stats, pagination=pagination)


@alerts_bp.route("/<alert_id>")
def alert_detail(alert_id):
    alert = get_alert_detail(alert_id)
    if not alert:
        flash(f"Alert {alert_id} not found", "danger")
        return redirect(url_for("alerts.list_alerts"))
    return render_template("alerts/detail.html", alert=alert, related_alerts=[])


@alerts_bp.route("/<alert_id>/resolve")
def resolve_alert(alert_id):
    flash(f"Alert {alert_id} resolved", "success")
    return redirect(url_for("alerts.list_alerts"))


@alerts_bp.route("/create", methods=["GET", "POST"])
def create_alert():
    flash("Alert creation form - implement as needed", "info")
    return redirect(url_for("alerts.list_alerts"))
