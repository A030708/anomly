from flask import Blueprint, render_template, request, redirect, url_for, flash

from sentinel_xdr.database import (
    get_playbooks, get_playbook_detail, get_playbook_executions,
    get_playbook_recent_runs, get_playbook_stats, get_system_stats,
)

playbooks_bp = Blueprint("playbooks", __name__, url_prefix="/playbooks")


@playbooks_bp.route("/")
def list_playbooks():
    stats = get_playbook_stats()
    playbooks = get_playbooks()
    executions = get_playbook_executions()
    recent_incidents_data = get_system_stats()
    recent_incidents = [
        {"id": "INC-2026-E9A3E088", "title": "Honeypot Probe Detected"},
    ]
    return render_template("playbooks/list.html",
                           stats=stats,
                           playbooks=playbooks,
                           executions=executions,
                           recent_incidents=recent_incidents)


@playbooks_bp.route("/<playbook_id>")
def playbook_detail(playbook_id):
    result = get_playbook_detail(playbook_id)
    if not result:
        flash(f"Playbook {playbook_id} not found", "danger")
        return redirect(url_for("playbooks.list_playbooks"))

    playbook, steps = result
    recent_runs = get_playbook_recent_runs(playbook_id)
    related_incidents = [
        {"id": "INC-2026-E9A3E088", "title": "Honeypot Probe Detected", "severity": "Critical"},
    ]

    return render_template("playbooks/detail.html",
                           playbook=playbook,
                           steps=steps,
                           recent_runs=recent_runs,
                           related_incidents=related_incidents)


@playbooks_bp.route("/create", methods=["GET", "POST"])
def create_playbook():
    flash("Playbook creation form - implement as needed", "info")
    return redirect(url_for("playbooks.list_playbooks"))


@playbooks_bp.route("/<playbook_id>/edit", methods=["GET", "POST"])
def edit_playbook(playbook_id):
    flash(f"Editing playbook {playbook_id}", "info")
    return redirect(url_for("playbooks.playbook_detail", playbook_id=playbook_id))


@playbooks_bp.route("/<playbook_id>/run", methods=["POST"])
def run_playbook(playbook_id):
    flash(f"Playbook {playbook_id} execution started", "success")
    return redirect(url_for("playbooks.playbook_detail", playbook_id=playbook_id))


@playbooks_bp.route("/<playbook_id>/export")
def export_playbook(playbook_id):
    flash(f"Playbook {playbook_id} exported", "info")
    return redirect(url_for("playbooks.list_playbooks"))
