from flask import Blueprint, render_template, request, session, jsonify
from sentinel_xdr.database import get_all_settings, update_settings


settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("/")
def settings_view():
    settings = get_all_settings()
    selected_tz = session.get("timezone", settings.get("timezone", "Asia/Kolkata"))
    return render_template("settings/view.html", selected_tz=selected_tz, settings=settings)


@settings_bp.route("/timezone", methods=["POST"])
def set_timezone():
    tz = request.json.get("timezone", "UTC")
    session["timezone"] = tz
    return jsonify({"success": True, "timezone": tz})


@settings_bp.route("/api", methods=["GET"])
def api_settings():
    return jsonify(get_all_settings())


@settings_bp.route("/api", methods=["POST"])
def api_update_settings():
    data = request.json or {}
    updated = update_settings(data)
    return jsonify({"success": True, "settings": updated})
