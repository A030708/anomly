from flask import Blueprint, render_template, jsonify
from sentinel_xdr.database import get_system_stats

network_bp = Blueprint("network", __name__, url_prefix="/network")


@network_bp.route("/map")
def network_map():
    s = get_system_stats()
    stats = {
        "subnets": 14,
        "endpoints": s["total_events"] // 50 + 10,
        "servers": s["active_sources"] * 2,
        "network_devices": 9,
        "connections": s["total_incidents"] + s["total_events"],
        "isolated": s["active_blocks"],
    }
    return render_template("network/map.html", stats=stats)


@network_bp.route("/api/topology")
def topology_data():
    return jsonify({"nodes": [], "edges": []})
