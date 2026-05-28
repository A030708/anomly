from flask import Blueprint, render_template, request, flash, redirect, url_for
from datetime import datetime, timezone, timedelta
import random

assets_bp = Blueprint("assets", __name__, url_prefix="/assets")


def _sample_assets(count=18):
    types = ["Server", "Workstation", "Network Device", "Container", "Database", "Application"]
    statuses = ["online", "offline", "maintenance", "compromised"]
    os_list = ["Windows Server 2022", "Ubuntu 22.04", "macOS Ventura", "CentOS 9", "Debian 12"]
    agents = ["sentinel-agent-v3.2.1", "sentinel-agent-v3.1.0", None]
    assets = []
    for i in range(count):
        risk = random.randint(10, 95)
        assets.append({
            "id": f"AST-{str(i+1).zfill(5)}",
            "hostname": random.choice([
                "web-prod-01", "web-prod-02", "db-master-01", "db-replica-01",
                "app-worker-01", "cache-01", "queue-01", "monitor-01",
                "build-agent-01", "bastion-host", "vpn-gateway", "mail-server",
            ]) + ("" if i < 12 else f"-{i}"),
            "type": random.choice(types),
            "status": random.choice(statuses),
            "risk_score": risk,
            "os": random.choice(os_list),
            "agent": random.choice(agents),
            "ip": f"10.0.{random.randint(0,10)}.{random.randint(1,254)}",
            "last_seen": datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 1440)),
            "tags": random.sample(["production", "staging", "critical", "dmz", "internal", "compliance"], k=random.randint(1, 3)),
        })
    return assets


@assets_bp.route("/")
def list_assets():
    assets = _sample_assets()
    stats = {
        "total": len(assets),
        "online": sum(1 for a in assets if a["status"] == "online"),
        "offline": sum(1 for a in assets if a["status"] == "offline"),
        "compromised": sum(1 for a in assets if a["status"] == "compromised"),
        "maintenance": sum(1 for a in assets if a["status"] == "maintenance"),
        "critical": sum(1 for a in assets if a["risk_score"] >= 70),
    }
    return render_template("assets/list.html", assets=assets, stats=stats)


@assets_bp.route("/<asset_id>")
def asset_detail(asset_id):
    asset = {
        "id": asset_id,
        "hostname": "web-prod-01",
        "type": "Server",
        "status": "online",
        "risk_score": 72,
        "os": "Ubuntu 22.04",
        "ip": "10.0.1.50",
        "agent": "sentinel-agent-v3.2.1",
        "last_seen": datetime.now(timezone.utc),
        "tags": ["production", "critical"],
    }
    return render_template("assets/list.html", assets=[asset], stats={})


@assets_bp.route("/add", methods=["GET", "POST"])
def add_asset():
    flash("Asset creation form - implement as needed", "info")
    return redirect(url_for("assets.list_assets"))
