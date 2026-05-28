from flask import Blueprint, render_template, request, flash, redirect, url_for
from datetime import datetime, timezone, timedelta
import random

vulnerabilities_bp = Blueprint("vulnerabilities", __name__, url_prefix="/vulnerabilities")

SEVERITIES = ["Critical", "High", "Medium", "Low"]


def _sample_vulns(count=30):
    vulns = []
    for i in range(count):
        cvss = round(random.uniform(3.0, 10.0), 1)
        sev = "Critical" if cvss >= 9.0 else "High" if cvss >= 7.0 else "Medium" if cvss >= 4.0 else "Low"
        vulns.append({
            "id": f"CVE-2024-{random.randint(1000, 9999)}",
            "title": random.choice([
                "Remote Code Execution in Web Server",
                "SQL Injection in API Endpoint",
                "Privilege Escalation via Kernel Exploit",
                "Cross-Site Scripting in Admin Panel",
                "Buffer Overflow in Network Driver",
                "Authentication Bypass in VPN Gateway",
                "Insecure Direct Object Reference",
                "XML External Entity Injection",
            ]),
            "severity": sev,
            "cvss": cvss,
            "affected_asset": random.choice(["web-prod-01", "db-master-01", "vpn-gateway", "api-gateway", "app-worker-02"]),
            "patch_status": random.choice(["available", "applied", "not_available", "scheduled"]),
            "exploit_available": random.random() < 0.4,
            "discovered_at": (datetime.now(timezone.utc) - timedelta(days=random.randint(0, 90))).isoformat(),
        })
    return vulns


@vulnerabilities_bp.route("/")
def list_vulns():
    vulns = _sample_vulns()
    stats = {
        "total": len(vulns),
        "critical": sum(1 for v in vulns if v["severity"] == "Critical"),
        "high": sum(1 for v in vulns if v["severity"] == "High"),
        "exploitable": sum(1 for v in vulns if v["exploit_available"]),
        "unpatched": sum(1 for v in vulns if v["patch_status"] in ("available", "scheduled")),
    }
    return render_template("vulnerabilities/list.html", vulnerabilities=vulns, stats=stats)


@vulnerabilities_bp.route("/add", methods=["GET", "POST"])
def add_vuln():
    flash("Vulnerability creation form - implement as needed", "info")
    return redirect(url_for("vulnerabilities.list_vulns"))


@vulnerabilities_bp.route("/<vuln_id>")
def vuln_detail(vuln_id):
    vuln = {
        "id": vuln_id,
        "title": "Remote Code Execution in Web Server",
        "severity": "Critical",
        "cvss": 9.1,
        "affected_asset": "web-prod-01",
        "patch_status": "available",
        "exploit_available": True,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }
    return render_template("vulnerabilities/list.html", vulnerabilities=[vuln], stats={})
