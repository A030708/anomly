from flask import Blueprint, render_template, request

from sentinel_xdr.database import get_events_page, get_event_stats

events_bp = Blueprint("events", __name__, url_prefix="/events")


@events_bp.route("/")
def list_events():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    events, pagination = get_events_page(page, per_page)
    stats = get_event_stats()

    return render_template("events/list.html", events=events, stats=stats, pagination=pagination)
