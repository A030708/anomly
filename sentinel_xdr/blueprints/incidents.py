import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify

from sentinel_xdr.database import (
    get_incidents_page, get_incident_stats, get_incident_detail,
    update_incident_status as db_update_status,
    investigate_incident as db_investigate,
)
from sentinel_xdr.notifier import send_account_deactivation
from shared.db_client import get_supabase

logger = logging.getLogger(__name__)

incidents_bp = Blueprint("incidents", __name__, url_prefix="/incidents")


@incidents_bp.route("/")
def list_incidents():
    page = request.args.get("page", 1, type=int)
    incidents, pagination = get_incidents_page(page)
    stats = get_incident_stats()
    return render_template("incidents/list.html", incidents=incidents, stats=stats)


@incidents_bp.route("/<incident_id>")
def incident_detail(incident_id):
    result = get_incident_detail(incident_id)
    if not result:
        flash(f"Incident {incident_id} not found", "danger")
        return redirect(url_for("incidents.list_incidents"))

    incident, related_alerts = result

    return render_template("incidents/detail.html",
                           incident=incident,
                           timeline=[],
                           related_alerts=related_alerts,
                           iocs=[],
                           affected_assets=[],
                           notes=[],
                           evidence=[])


@incidents_bp.route("/<incident_id>/investigate", methods=["POST"])
def investigate(incident_id):
    try:
        from sentinel_xdr.llm_analyzer import LLMAnalyzer

        supa = get_supabase()
        inc_resp = supa.table("threat_incidents").select("*").eq("incident_id", incident_id).limit(1).execute()
        if not inc_resp.data:
            return jsonify({"success": False, "error": "Incident not found"}), 404

        incident = inc_resp.data[0]

        event_ids = incident.get("event_ids") or []
        events = []
        for eid in event_ids:
            ev = supa.table("sentinel_events").select("*").eq("event_id", eid).limit(1).execute()
            if ev.data:
                events.append(ev.data[0])

        primary_event = events[0] if events else {}

        ip = incident.get("ip_address", primary_event.get("ip_address", "unknown"))
        ip_events = (
            supa.table("sentinel_events")
            .select("*")
            .eq("ip_address", ip)
            .order("created_at", desc=True)
            .limit(20)
            .execute()
        ).data or []

        context = {
            "recent_events_10": ip_events[:10],
            "ip_history": {
                "total_events": len(ip_events),
                "prior_blocks": 0,
                "seen_on_both": False,
                "blocked_on_other": False,
                "is_new": len(ip_events) < 3,
            },
        }

        analyzer = LLMAnalyzer()
        result = analyzer.analyze(
            event=primary_event,
            context=context,
            attack_type=incident.get("attack_type", "Unknown"),
            score=incident.get("anomaly_score", 0),
            severity=incident.get("severity", "low"),
        )

        analysis_text = (
            f"ANALYSIS: {result.get('analysis', '')}\n"
            f"BUSINESS_IMPACT: {result.get('business_impact', '')}\n"
            f"ATTACKER_GOAL: {result.get('attacker_goal', '')}\n"
            f"RECOMMENDATION: {result.get('recommendation', 'WATCH_AND_LOG')}\n"
            f"REASONING: {result.get('reasoning', '')}"
        )

        db_investigate(incident_id, analysis_text)

        return jsonify({
            "success": True,
            "analysis": result.get("analysis", ""),
            "business_impact": result.get("business_impact", ""),
            "attacker_goal": result.get("attacker_goal", ""),
            "recommendation": result.get("recommendation", ""),
            "reasoning": result.get("reasoning", ""),
            "full_text": result.get("full_text", ""),
        })

    except Exception as e:
        logger.error("Investigation failed for %s: %s", incident_id, e)
        return jsonify({"success": False, "error": str(e)}), 500


@incidents_bp.route("/<incident_id>/resolve", methods=["POST"])
def resolve_incident(incident_id):
    action = request.json.get("action", "keep")

    db_update_status(incident_id, "resolved", deactivate=(action == "deactivate"))

    if action == "deactivate":
        supa = get_supabase()
        inc = supa.table("threat_incidents").select("*").eq("incident_id", incident_id).limit(1).execute()
        if inc.data:
            incident = inc.data[0]
            affected_user = incident.get("affected_user")

            if affected_user:
                user_resp = supa.table("users").select("email,username").eq("id", affected_user).limit(1).execute()
                if user_resp.data:
                    user_email = user_resp.data[0].get("email")
                    if user_email:
                        send_account_deactivation(
                            user_email=user_email,
                            incident_id=incident_id,
                            attack_type=incident.get("attack_type", "Unknown"),
                            reason=incident.get("groq_analysis", "Suspicious activity detected"),
                        )

    return jsonify({"success": True, "action": action})


@incidents_bp.route("/delete_all", methods=["POST"])
def delete_all_incidents():
    try:
        supa = get_supabase()
        all_incidents = supa.table("threat_incidents").select("incident_id").execute()
        ids = [row["incident_id"] for row in (all_incidents.data or [])]
        if ids:
            supa.table("threat_incidents").delete().in_("incident_id", ids).execute()
        flash("All incidents deleted successfully", "success")
    except Exception as e:
        logger.error("Failed to delete all incidents: %s", e)
        flash("Failed to delete incidents", "danger")
    return redirect(url_for("incidents.list_incidents"))


@incidents_bp.route("/create", methods=["GET", "POST"])
def create_incident():
    flash("Incident creation form - implement as needed", "info")
    return redirect(url_for("incidents.list_incidents"))


@incidents_bp.route("/<incident_id>/note", methods=["POST"])
def add_note(incident_id):
    flash(f"Note added to {incident_id}", "success")
    return redirect(url_for("incidents.incident_detail", incident_id=incident_id))


@incidents_bp.route("/<incident_id>/status")
def update_status(incident_id):
    new_status = request.args.get("status", "open")
    db_update_status(incident_id, new_status)
    flash(f"Incident {incident_id} status updated to {new_status}", "success")
    return redirect(url_for("incidents.incident_detail", incident_id=incident_id))
