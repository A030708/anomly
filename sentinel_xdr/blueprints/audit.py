from flask import Blueprint, render_template
from sentinel_xdr.database import get_audit_logs

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


@audit_bp.route("/")
def audit_log():
    stats, logs = get_audit_logs()
    return render_template("audit/log.html", stats=stats, logs=logs)
