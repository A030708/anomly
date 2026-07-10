from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify

from sentinel_xdr.database import get_alerts_page, get_alert_stats, get_alert_detail
from sentinel_xdr.feedback import save_feedback, get_feedback_for_event, get_training_data, needs_retrain
from sentinel_xdr.anomaly_detector import AnomalyDetector

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
    feedback = get_feedback_for_event(alert["id"])
    return render_template("alerts/detail.html", alert=alert, related_alerts=[], feedback=feedback)


@alerts_bp.route("/<alert_id>/feedback", methods=["POST"])
def submit_feedback(alert_id):
    data = request.get_json(silent=True) or {}
    is_fp = data.get("is_false_positive", False)
    notes = data.get("notes", "")

    save_feedback(alert_id, is_fp, notes)

    if needs_retrain():
        try:
            result = get_training_data()
            if result:
                vectors, labels = result
                detector = AnomalyDetector()
                detector.retrain(vectors, labels)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error("Retrain failed: %s", e)

    return jsonify({"success": True, "is_false_positive": is_fp})


@alerts_bp.route("/<alert_id>/resolve")
def resolve_alert(alert_id):
    flash(f"Alert {alert_id} resolved", "success")
    return redirect(url_for("alerts.list_alerts"))


@alerts_bp.route("/create", methods=["GET", "POST"])
def create_alert():
    flash("Alert creation form - implement as needed", "info")
    return redirect(url_for("alerts.list_alerts"))
