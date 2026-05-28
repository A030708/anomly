from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from datetime import datetime, timezone, timedelta
import random

threat_intel_bp = Blueprint("threat_intel", __name__, url_prefix="/threat_intel")

IOC_TYPES = ["IP", "Domain", "Hash", "URL", "Email", "CVE"]
TLP_LEVELS = ["WHITE", "GREEN", "AMBER", "RED"]
ACTOR_REGIONS = ["Eastern Europe", "East Asia", "Middle East", "North America", "South Asia", "West Africa"]


def _sample_iocs(count=20):
    iocs = []
    for i in range(count):
        iocs.append({
            "id": f"IOC-{str(i+1).zfill(5)}",
            "type": random.choice(IOC_TYPES),
            "value": random.choice([
                f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                f"malicious{random.randint(1,999)}.com",
                f"a1b2c3d4{random.randint(100,999)}e5f6g7h8i9j0",
                f"https://evil{random.randint(1,999)}.org/payload",
            ]),
            "tlp": random.choice(TLP_LEVELS),
            "confidence": random.randint(40, 100),
            "first_seen": datetime.now(timezone.utc) - timedelta(days=random.randint(1, 90)),
            "last_seen": datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 168)),
            "tags": ",".join(random.sample(["ransomware", "apt", "phishing", "botnet", "malware", "c2"], k=random.randint(1, 3))),
        })
    return iocs


def _sample_actors(count=6):
    actors = []
    for i in range(count):
        first_seen = datetime.now(timezone.utc) - timedelta(days=random.randint(180, 730))
        actors.append({
            "id": f"TA-{str(i+1).zfill(3)}",
            "name": random.choice(["APT-C-36", "Lazarus Group", "TA505", "FIN7", "APT29", "Silent Libra"]),
            "region": random.choice(ACTOR_REGIONS),
            "motivation": random.choice(["Financial", "Espionage", "Destruction", "Hacktivism"]),
            "confidence": random.randint(50, 95),
            "first_seen": first_seen,
            "ttps": ",".join(random.sample(["T1078", "T1041", "T1020", "T1566", "T1059", "T1204"], k=random.randint(2, 4))),
            "last_active": datetime.now(timezone.utc) - timedelta(days=random.randint(0, 30)),
        })
    return actors


@threat_intel_bp.route("/")
def list_intel():
    iocs = _sample_iocs()
    actors = _sample_actors()
    feeds = [
        {"name": "AlienVault OTX", "status": "connected", "last_updated": datetime.now(timezone.utc), "iocs_ingested": 15420},
        {"name": "VirusTotal", "status": "connected", "last_updated": datetime.now(timezone.utc), "iocs_ingested": 89230},
        {"name": "MISP Community", "status": "connected", "last_updated": datetime.now(timezone.utc), "iocs_ingested": 34100},
        {"name": "CrowdStrike Intel", "status": "connected", "last_updated": datetime.now(timezone.utc), "iocs_ingested": 67500},
    ]
    campaigns = []
    stats = {"total_iocs": len(iocs), "active_actors": len(actors), "feeds": len(feeds), "matches_today": 142}
    return render_template("threat_intel/list.html", iocs=iocs, threat_actors=actors, feeds=feeds, campaigns=campaigns, stats=stats)


@threat_intel_bp.route("/api/lookup", methods=["POST"])
def ioc_lookup():
    return jsonify({"status": "simulated", "matches": 0, "message": "IOC lookup simulation"})


@threat_intel_bp.route("/add_ioc", methods=["GET", "POST"])
def add_ioc():
    flash("IOC creation form - implement as needed", "info")
    return redirect(url_for("threat_intel.list_intel"))


@threat_intel_bp.route("/add_feed", methods=["GET", "POST"])
def add_feed():
    flash("Feed creation form - implement as needed", "info")
    return redirect(url_for("threat_intel.list_intel"))


@threat_intel_bp.route("/<intel_id>")
def intel_detail(intel_id):
    intel = {
        "id": intel_id,
        "ioc_type": random.choice(IOC_TYPES),
        "value": f"malicious{random.randint(1,999)}.com",
        "tlp": random.choice(TLP_LEVELS),
        "confidence": random.randint(40, 100),
        "status": "active",
        "source": "AlienVault OTX",
        "match_count": random.randint(0, 15),
        "description": "Indicator observed in multiple threat intelligence feeds associated with recent APT campaign.",
        "tags": "ransomware,apt,c2",
        "created_at": datetime.now(timezone.utc) - timedelta(days=random.randint(1, 30)),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=random.randint(1, 90)),
    }
    related_alerts = [
        {"id": "ALT-001", "title": "Suspicious outbound connection", "severity": "High", "source_ip": "10.0.1.50", "created_at": datetime.now(timezone.utc) - timedelta(hours=6)},
    ]
    return render_template("threat_intel/detail.html", intel=intel, related_alerts=related_alerts, related_iocs=[], confidence_history=[])


@threat_intel_bp.route("/<intel_id>/edit", methods=["GET", "POST"])
def edit_intel(intel_id):
    flash(f"Editing intel {intel_id}", "info")
    return redirect(url_for("threat_intel.intel_detail", intel_id=intel_id))


@threat_intel_bp.route("/<intel_id>/expire", methods=["POST"])
def expire_intel(intel_id):
    flash(f"Intel {intel_id} expired", "success")
    return redirect(url_for("threat_intel.list_intel"))


@threat_intel_bp.route("/<intel_id>/delete", methods=["POST"])
def delete_intel(intel_id):
    flash(f"Intel {intel_id} deleted", "success")
    return redirect(url_for("threat_intel.list_intel"))
