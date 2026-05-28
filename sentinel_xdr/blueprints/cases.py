from flask import Blueprint, render_template, request, redirect, url_for, flash
from datetime import datetime, timezone, timedelta
import random

cases_bp = Blueprint("cases", __name__, url_prefix="/cases")

STATUSES = ["Open", "In Progress", "Pending Review", "Closed"]
PRIORITIES = ["Critical", "High", "Medium", "Low"]


def _sample_cases(count=12):
    cases = []
    for i in range(count):
        ts = datetime.now(timezone.utc) - timedelta(days=random.randint(0, 14))
        priority = random.choice(PRIORITIES)
        sla_hours = {"Critical": 4, "High": 8, "Medium": 24, "Low": 48}[priority]
        elapsed = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
        sla_ratio = elapsed / sla_hours
        sla_status = "breached" if sla_ratio > 1 else "warning" if sla_ratio > 0.75 else "ok"
        cases.append({
            "id": f"CASE-{ts.strftime('%Y%m%d')}-{str(i+1).zfill(3)}",
            "title": random.choice([
                "Investigate unusual API traffic pattern",
                "Review compromised credentials report",
                "Analyze ransomware alert in production",
                "Phishing campaign targeting executives",
                "Data leakage through third-party integration",
            ]),
            "status": random.choice(STATUSES),
            "priority": priority,
            "assignee": random.choice(["Alice Chen", "Bob Martinez", "Carol Smith", None]),
            "sla_status": sla_status,
            "tags": ",".join(random.sample(["phishing", "ransomware", "insider", "malware", "compliance", "network"], k=random.randint(1, 3))),
            "created_at": ts,
            "updated_at": ts + timedelta(hours=random.randint(1, 48)),
            "due_date": ts + timedelta(days={
                "Critical": 1, "High": 2, "Medium": 5, "Low": 10
            }.get(priority, 5)),
        })
    return cases


@cases_bp.route("/")
def list_cases():
    cases = _sample_cases()
    stats = {"total": len(cases), "open": sum(1 for c in cases if c["status"] == "Open"), "critical": sum(1 for c in cases if c["priority"] == "Critical"), "breached_sla": sum(1 for c in cases if c["sla_status"] == "breached")}
    return render_template("cases/list.html", cases=cases, stats=stats)


@cases_bp.route("/<case_id>")
def case_detail(case_id):
    ts = datetime.now(timezone.utc) - timedelta(days=random.randint(0, 7))
    case = {
        "id": case_id,
        "title": "Investigate unusual API traffic pattern",
        "status": random.choice(STATUSES),
        "priority": random.choice(PRIORITIES),
        "description": "Detailed investigation into anomalous API activity detected by the monitoring system.",
        "assigned_to": random.choice(["Alice Chen", "Bob Martinez"]),
        "due_date": datetime.now(timezone.utc) + timedelta(days=random.randint(1, 14)),
        "alert_count": random.randint(2, 8),
        "incident_count": random.randint(1, 3),
        "created_at": ts,
        "updated_at": ts + timedelta(hours=random.randint(1, 48)),
    }
    linked_alerts = [
        {"id": "ALT-001", "title": "Suspicious outbound connection", "severity": "High", "source_ip": "10.0.1.50", "created_at": datetime.now(timezone.utc) - timedelta(hours=6)},
        {"id": "ALT-002", "title": "Multiple failed login attempts", "severity": "Medium", "source_ip": "10.0.1.50", "created_at": datetime.now(timezone.utc) - timedelta(hours=5)},
    ]
    activities = [
        {"timestamp": datetime.now(timezone.utc) - timedelta(hours=2), "description": "Case assigned to Alice Chen"},
        {"timestamp": datetime.now(timezone.utc) - timedelta(hours=1), "description": "New evidence uploaded - network capture"},
    ]
    return render_template("cases/detail.html", case=case, linked_alerts=linked_alerts, activities=activities)


@cases_bp.route("/create", methods=["GET", "POST"])
def create_case():
    flash("Case creation form - implement as needed", "info")
    return redirect(url_for("cases.list_cases"))


@cases_bp.route("/<case_id>/edit", methods=["GET", "POST"])
def edit_case(case_id):
    flash(f"Editing case {case_id}", "info")
    return redirect(url_for("cases.case_detail", case_id=case_id))


@cases_bp.route("/<case_id>/close", methods=["POST"])
def close_case(case_id):
    flash(f"Case {case_id} closed", "success")
    return redirect(url_for("cases.list_cases"))
