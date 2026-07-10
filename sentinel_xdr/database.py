import json
import os
import uuid
from datetime import datetime, timezone, timedelta

from shared.db_client import get_supabase

_SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "settings_store.json")

_DEFAULT_SETTINGS = {
    "platform_name": "Sentinel XDR",
    "timezone": "Asia/Kolkata",
    "date_format": "YYYY-MM-DD",
    "retention_period": "90 days",
    "session_timeout": "30",
    "max_login_attempts": "5",
    "password_policy": "Enhanced",
    "event_collection": True,
    "network_flow_collection": True,
    "endpoint_telemetry": True,
    "threat_intel_feeds": False,
    "ml_anomaly_detection": True,
}


def get_all_settings():
    if not os.path.exists(_SETTINGS_PATH):
        return dict(_DEFAULT_SETTINGS)
    try:
        with open(_SETTINGS_PATH) as f:
            return {**_DEFAULT_SETTINGS, **json.load(f)}
    except (json.JSONDecodeError, OSError):
        return dict(_DEFAULT_SETTINGS)


def update_settings(updates):
    current = get_all_settings()
    current.update(updates)
    with open(_SETTINGS_PATH, "w") as f:
        json.dump(current, f, indent=2)
    return current


def get_dashboard_stats():
    supa = get_supabase()

    now = utc_now()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)

    # Total Events Today
    events_today = (
        supa.table("sentinel_events")
        .select("id", count="exact")
        .gte("created_at", start.isoformat())
        .lt("created_at", end.isoformat())
        .execute()
    ).count or 0

    # Anomalies (alerts) Today
    anomalies_today = (
        supa.table("sentinel_events")
        .select("id", count="exact")
        .eq("is_anomalous", True)
        .gte("created_at", start.isoformat())
        .lt("created_at", end.isoformat())
        .execute()
    ).count or 0

    # Open Incidents
    open_incidents = (
        supa.table("threat_incidents")
        .select("id", count="exact")
        .in_("status", ["open", "investigating"])
        .execute()
    ).count or 0

    # Active IP blocks
    active_blocks = (
        supa.table("blocked_ips")
        .select("id", count="exact")
        .gt("blocked_until", now.isoformat())
        .execute()
    ).count or 0

    # Severity counts (for severity donut + threat level)
    critical_count = (
        supa.table("threat_incidents")
        .select("id", count="exact")
        .eq("severity", "critical")
        .execute()
    ).count or 0

    high_count = (
        supa.table("threat_incidents")
        .select("id", count="exact")
        .eq("severity", "high")
        .execute()
    ).count or 0

    medium_count = (
        supa.table("threat_incidents")
        .select("id", count="exact")
        .eq("severity", "medium")
        .execute()
    ).count or 0

    low_count = (
        supa.table("threat_incidents")
        .select("id", count="exact")
        .eq("severity", "low")
        .execute()
    ).count or 0

    total_incidents = critical_count + high_count + medium_count + low_count
    risk_score = min(95, int((total_incidents / max(events_today, 1)) * 100)) if events_today > 0 else 0

    # Critical threats open/investigating
    critical_threats_open = (
        supa.table("threat_incidents")
        .select("id", count="exact")
        .eq("severity", "critical")
        .in_("status", ["open", "investigating"])
        .execute()
    ).count or 0

    # Sessions revoked today (from audit_log)
    sessions_revoked_today = (
        supa.table("audit_log")
        .select("id", count="exact")
        .eq("action", "REVOKE_SESSION")
        .gte("timestamp", start.isoformat())
        .lt("timestamp", end.isoformat())
        .execute()
    ).count or 0

    return {
        "total_alerts": anomalies_today,
        "open_incidents": open_incidents,
        "threats_blocked": active_blocks,
        "risk_score": risk_score,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "total_events_today": events_today,
        "anomalies_detected_today": anomalies_today,
        "critical_threats_open": critical_threats_open,
        "sessions_revoked_today": sessions_revoked_today,
    }


def get_chart_data():
    supa = get_supabase()
    now = utc_now()
    start = now - timedelta(days=7)

    events = (
        supa.table("sentinel_events")
        .select("created_at, is_anomalous")
        .gte("created_at", start.isoformat())
        .order("created_at", desc=True)
        .limit(5000)
        .execute()
    ).data or []

    daily_counts = {}
    for i in range(7):
        day = (now - timedelta(days=i)).strftime("%a")
        daily_counts[day] = 0

    for e in events:
        try:
            ts = datetime.fromisoformat(e["created_at"].replace("Z", "+00:00"))
            day = ts.strftime("%a")
            if day in daily_counts:
                daily_counts[day] += 1
        except Exception:
            pass

    day_order = [(now - timedelta(days=i)).strftime("%a") for i in range(6, -1, -1)]
    labels = day_order
    data = [daily_counts[d] for d in day_order]
    return labels, data


def get_events_page(page=1, per_page=50):
    supa = get_supabase()
    start_idx = (page - 1) * per_page

    count_resp = supa.table("sentinel_events").select("id", count="exact").execute()
    total = count_resp.count or 0

    data_resp = (
        supa.table("sentinel_events")
        .select("*")
        .order("created_at", desc=True)
        .range(start_idx, start_idx + per_page - 1)
        .execute()
    )
    events_raw = data_resp.data or []

    events = []
    for e in events_raw:
        events.append({
            "event_type": e.get("event_type", "unknown"),
            "source": e.get("source", "unknown"),
            "created_at": _parse_iso(e.get("created_at")),
            "description": e.get("route") or e.get("event_type", ""),
            "username": e.get("user_id") or "SYSTEM",
            "source_ip": e.get("ip_address", ""),
            "raw_log": json.dumps(e.get("metadata", {}), indent=2) if e.get("metadata") else None,
            "anomaly_score": e.get("anomaly_score", 0),
            "is_anomalous": e.get("is_anomalous", False),
        })

    total_pages = max(1, (total + per_page - 1) // per_page)

    pagination = {
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_num": page - 1,
        "next_num": page + 1,
    }

    return events, pagination


def get_event_stats():
    supa = get_supabase()
    now = utc_now()
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(hours=24)

    total = supa.table("sentinel_events").select("id", count="exact").execute().count or 0

    last_hour = (
        supa.table("sentinel_events")
        .select("id", count="exact")
        .gte("created_at", hour_ago.isoformat())
        .execute()
    ).count or 0

    last_24h = (
        supa.table("sentinel_events")
        .select("id", count="exact")
        .gte("created_at", day_ago.isoformat())
        .execute()
    ).count or 0

    avg_rate = round(last_24h / 24, 1) if last_24h > 0 else 0

    sources_data = (
        supa.table("sentinel_events")
        .select("source")
        .execute()
    ).data or []
    distinct_sources = len(set(e.get("source", "") for e in sources_data if e.get("source")))

    anomalies = (
        supa.table("sentinel_events")
        .select("id", count="exact")
        .eq("is_anomalous", True)
        .execute()
    ).count or 0

    return {
        "total": total,
        "last_hour": last_hour,
        "last_24h": last_24h,
        "avg_rate": avg_rate,
        "distinct_sources": distinct_sources,
        "anomalies": anomalies,
    }


def _parse_iso(ts_str):
    if not ts_str:
        return utc_now()
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return utc_now()


def get_alerts_page(page=1, per_page=25):
    supa = get_supabase()
    start_idx = (page - 1) * per_page

    count_resp = supa.table("threat_incidents").select("id", count="exact").execute()
    total = count_resp.count or 0

    data_resp = (
        supa.table("threat_incidents")
        .select("*")
        .order("created_at", desc=True)
        .range(start_idx, start_idx + per_page - 1)
        .execute()
    )

    alerts = []
    for inc in data_resp.data or []:
        alerts.append({
            "id": inc.get("incident_id"),
            "title": inc.get("attack_type") or f"Anomalous activity from {inc.get('ip_address', 'unknown')}",
            "severity": (inc.get("severity") or "low").capitalize(),
            "status": inc.get("status", "open"),
            "alert_type": inc.get("source", "unknown"),
            "source_ip": inc.get("ip_address"),
            "dest_ip": None,
            "created_at": _parse_iso(inc.get("created_at")),
        })

    total_pages = max(1, (total + per_page - 1) // per_page)
    pagination = {
        "page": page, "per_page": per_page, "total": total,
        "pages": total_pages, "has_prev": page > 1, "has_next": page < total_pages,
        "prev_num": page - 1, "next_num": page + 1,
    }
    return alerts, pagination


def get_alert_stats():
    supa = get_supabase()

    total = supa.table("threat_incidents").select("id", count="exact").execute().count or 0
    critical = supa.table("threat_incidents").select("id", count="exact").eq("severity", "critical").execute().count or 0
    high = supa.table("threat_incidents").select("id", count="exact").eq("severity", "high").execute().count or 0
    open_count = supa.table("threat_incidents").select("id", count="exact").eq("status", "open").execute().count or 0
    resolved = supa.table("threat_incidents").select("id", count="exact").eq("status", "resolved").execute().count or 0

    return {"total": total, "critical": critical, "high": high, "open": open_count, "resolved": resolved}


def get_alert_detail(alert_id):
    supa = get_supabase()

    resp = supa.table("threat_incidents").select("*").eq("incident_id", alert_id).limit(1).execute()
    if not resp.data:
        return None

    inc = resp.data[0]

    event = None
    event_ids = inc.get("event_ids") or []
    if event_ids:
        ev = supa.table("sentinel_events").select("*").eq("event_id", event_ids[0]).limit(1).execute()
        if ev.data:
            event = ev.data[0]

    severity = (inc.get("severity") or "low").capitalize()
    anomaly_score = inc.get("anomaly_score")
    if not anomaly_score and event:
        anomaly_score = event.get("anomaly_score", 0)
    confidence = min(99, int(float(anomaly_score or 0) * 100))

    return {
        "id": inc.get("incident_id"),
        "title": inc.get("attack_type") or f"Anomalous activity from {inc.get('ip_address', 'unknown')}",
        "severity": severity,
        "status": inc.get("status", "open"),
        "alert_type": inc.get("source", "unknown"),
        "description": inc.get("groq_analysis") or inc.get("recommended_action") or "Alert generated by Sentinel XDR detection engine.",
        "source_ip": inc.get("ip_address"),
        "dest_ip": None,
        "source_port": None,
        "protocol": None,
        "rule_name": inc.get("attack_type") or "Sentinel Detection Rule",
        "confidence": confidence,
        "raw_log": json.dumps(event.get("metadata", {}), indent=2) if event and event.get("metadata") else None,
        "created_at": _parse_iso(inc.get("created_at")),
        "resolved_at": None,
        "updated_at": None,
        "assigned_to": None,
        "false_positive": False,
        "mitre_tactic": None,
        "mitre_technique": None,
    }


def get_incidents_page(page=1, per_page=20):
    supa = get_supabase()
    start_idx = (page - 1) * per_page

    count_resp = supa.table("threat_incidents").select("id", count="exact").execute()
    total = count_resp.count or 0

    data_resp = (
        supa.table("threat_incidents")
        .select("*")
        .order("created_at", desc=True)
        .range(start_idx, start_idx + per_page - 1)
        .execute()
    )

    severity_priority = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P3"}
    progress_map = {"resolved": 100, "closed": 100, "investigating": 50, "open": 10}

    incidents = []
    for inc in data_resp.data or []:
        sev = inc.get("severity", "low")
        stat = inc.get("status", "open")
        event_ids = inc.get("event_ids") or []
        incidents.append({
            "id": inc.get("incident_id"),
            "title": inc.get("attack_type") or f"Anomaly from {inc.get('ip_address', 'unknown')}",
            "severity": sev.capitalize(),
            "status": stat.capitalize(),
            "assigned_to": None,
            "alert_count": len(event_ids),
            "mitre_tactic": None,
            "description": inc.get("groq_analysis") or inc.get("recommended_action") or "",
            "created_at": _parse_iso(inc.get("created_at")),
            "mttr": None,
            "priority": severity_priority.get(sev, "P2"),
            "progress": progress_map.get(stat, 10),
        })

    total_pages = max(1, (total + per_page - 1) // per_page)
    pagination = {
        "page": page, "per_page": per_page, "total": total,
        "pages": total_pages, "has_prev": page > 1, "has_next": page < total_pages,
        "prev_num": page - 1, "next_num": page + 1,
    }
    return incidents, pagination


def get_incident_stats():
    supa = get_supabase()

    total = supa.table("threat_incidents").select("id", count="exact").execute().count or 0
    open_count = supa.table("threat_incidents").select("id", count="exact").eq("status", "open").execute().count or 0
    resolved = supa.table("threat_incidents").select("id", count="exact").eq("status", "resolved").execute().count or 0

    return {
        "total": total,
        "open": open_count,
        "resolved": resolved,
    }


def get_incident_detail(incident_id):
    supa = get_supabase()

    resp = supa.table("threat_incidents").select("*").eq("incident_id", incident_id).limit(1).execute()
    if not resp.data:
        return None

    inc = resp.data[0]

    sev = inc.get("severity", "low")
    stat = inc.get("status", "open")
    event_ids = inc.get("event_ids") or []
    severity_priority = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P3"}

    related_alerts = []
    for eid in event_ids:
        ev = supa.table("sentinel_events").select("*").eq("event_id", eid).limit(1).execute()
        if ev.data:
            e = ev.data[0]
            related_alerts.append({
                "id": e.get("event_id"),
                "title": f"{e.get('event_type', 'Unknown')} from {e.get('ip_address', 'N/A')}",
                "severity": "High" if (e.get("anomaly_score") or 0) >= 0.9 else "Medium",
                "status": "open",
                "source_ip": e.get("ip_address"),
                "created_at": _parse_iso(e.get("created_at")),
            })

    return {
        "id": inc.get("incident_id"),
        "title": inc.get("attack_type") or f"Anomaly from {inc.get('ip_address', 'unknown')}",
        "severity": sev.capitalize(),
        "status": stat.capitalize(),
        "priority": severity_priority.get(sev, "P2"),
        "category": inc.get("source", "unknown").capitalize(),
        "assigned_to": None,
        "mitre_tactic": None,
        "mitre_technique": None,
        "asset_count": 0,
        "alert_count": len(event_ids),
        "description": inc.get("groq_analysis") or inc.get("recommended_action") or "No description provided.",
        "created_at": _parse_iso(inc.get("created_at")),
        "updated_at": _parse_iso(inc.get("updated_at")) if inc.get("updated_at") else None,
        "resolved_at": _parse_iso(inc.get("resolved_at")) if inc.get("resolved_at") else None,
        "mttr": None,
        "sla_status": "On Track",
        "tlp": "AMBER",
        "source_ip": inc.get("ip_address"),
    }, related_alerts


def update_incident_status(incident_id, new_status, deactivate=False):
    supa = get_supabase()
    update = {"status": new_status}
    if new_status == "resolved":
        update["resolved_at"] = utc_now_iso()

        inc = supa.table("threat_incidents").select("*").eq("incident_id", incident_id).limit(1).execute()
        if inc.data:
            incident = inc.data[0]

            block = supa.table("blocked_ips").select("*").eq("incident_id", incident_id).limit(1).execute()
            if block.data:
                record = block.data[0]
                record["resolved_at"] = utc_now_iso()
                record.pop("id", None)

                try:
                    supa.table("blocked_ip_history").insert(record).execute()
                except Exception:
                    pass

            supa.table("blocked_ips").delete().eq("incident_id", incident_id).execute()

            if deactivate:
                source = incident.get("source")
                affected_user = incident.get("affected_user")
                if source == "warehouse_os" and affected_user:
                    try:
                        supa.table("users").update({"is_active": False}).eq("id", affected_user).execute()
                    except Exception:
                        pass

    supa.table("threat_incidents").update(update).eq("incident_id", incident_id).execute()


def investigate_incident(incident_id, groq_analysis):
    supa = get_supabase()
    supa.table("threat_incidents").update({
        "groq_analysis": groq_analysis,
        "status": "investigating",
    }).eq("incident_id", incident_id).execute()


def get_audit_logs(limit=50):
    supa = get_supabase()

    count_resp = supa.table("sentinel_events").select("id", count="exact").execute()
    total = count_resp.count or 0

    failed_logins = (
        supa.table("sentinel_events")
        .select("id", count="exact")
        .eq("event_type", "INGEST_REJECTED")
        .execute()
    ).count or 0

    critical_count = (
        supa.table("sentinel_events")
        .select("id", count="exact")
        .gte("anomaly_score", 0.9)
        .execute()
    ).count or 0

    data_resp = (
        supa.table("sentinel_events")
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )

    logs = []
    for e in data_resp.data or []:
        etype = (e.get("event_type") or "").upper()
        is_failure = "FAIL" in etype or "REJECT" in etype or "ERROR" in etype
        logs.append({
            "timestamp": _parse_iso(e.get("created_at")),
            "user": e.get("user_id") or "system",
            "action": e.get("event_type", "unknown"),
            "resource": e.get("route", "N/A"),
            "ip_address": e.get("ip_address", "127.0.0.1"),
            "status": "failure" if is_failure else "success",
            "level": "critical" if is_failure else "info",
            "request_id": e.get("event_id", "N/A"),
            "user_agent": json.dumps(e.get("metadata", {}).get("user_agent", "SentinelXDR/1.0")),
            "changes": e.get("metadata", {}).get("reason", "No details"),
        })

    stats = {
        "total": total,
        "failed_logins": failed_logins,
        "config_changes": 0,
        "critical": critical_count,
        "exports": 0,
    }

    return stats, logs


def get_playbooks():
    supa = get_supabase()
    resp = supa.table("sentinel_events").select("*").eq("event_type", "PLAYBOOK_DEFINITION").order("created_at", desc=True).execute()
    pbs = []
    for e in resp.data or []:
        m = e.get("metadata") or {}
        pbs.append({
            "id": e.get("event_id"),
            "name": m.get("playbook_name"),
            "pb_type": m.get("pb_type", "incident_response"),
            "is_active": m.get("is_active", True),
            "run_count": m.get("run_count", 0),
            "description": m.get("description", ""),
            "step_count": m.get("step_count", 0),
            "avg_duration": m.get("avg_duration", "5m"),
            "success_rate": m.get("success_rate", 0),
            "trigger_type": m.get("trigger_type"),
            "status": m.get("status", "ready"),
            "version": m.get("version", "1.0"),
            "category": m.get("category", "Response"),
            "severity": m.get("severity", "All"),
            "owner": m.get("owner"),
            "created_at": _parse_iso(e.get("created_at")),
            "last_run": None,
            "steps": m.get("steps", []),
        })
    return pbs


def get_playbook_detail(playbook_id):
    supa = get_supabase()
    resp = supa.table("sentinel_events").select("*").eq("event_id", playbook_id).eq("event_type", "PLAYBOOK_DEFINITION").limit(1).execute()
    if not resp.data:
        return None
    e = resp.data[0]
    m = e.get("metadata") or {}

    pb = {
        "id": e.get("event_id"),
        "name": m.get("playbook_name"),
        "pb_type": m.get("pb_type", "incident_response"),
        "is_active": m.get("is_active", True),
        "run_count": m.get("run_count", 0),
        "description": m.get("description", ""),
        "step_count": m.get("step_count", 0),
        "avg_duration": m.get("avg_duration", "5m"),
        "success_rate": m.get("success_rate", 0),
        "status": m.get("status", "draft"),
        "version": m.get("version", "1.0"),
        "category": m.get("category", "Response"),
        "severity": m.get("severity", "All"),
        "owner": m.get("owner"),
        "created_at": _parse_iso(e.get("created_at")),
        "last_run": None,
        "steps": m.get("steps", []),
        "trigger_type": m.get("trigger_type"),
    }

    steps = m.get("steps", [])
    return pb, steps


def get_playbook_executions(limit=10):
    supa = get_supabase()
    resp = supa.table("sentinel_events").select("*").eq("event_type", "PLAYBOOK_EXECUTION").order("created_at", desc=True).limit(limit).execute()
    execs = []
    for e in resp.data or []:
        m = e.get("metadata") or {}
        execs.append({
            "playbook_name": m.get("playbook_name"),
            "pb_type": m.get("pb_type", "incident_response"),
            "triggered_by": m.get("triggered_by", "Auto"),
            "status": m.get("status", "running"),
            "duration": m.get("duration"),
            "steps_completed": m.get("steps_completed", 0),
            "total_steps": m.get("total_steps", 0),
            "started_at": _parse_iso(e.get("created_at")),
            "playbook_id": m.get("playbook_id"),
        })
    return execs


def get_playbook_recent_runs(playbook_id, limit=5):
    supa = get_supabase()
    all_execs = supa.table("sentinel_events").select("*").eq("event_type", "PLAYBOOK_EXECUTION").order("created_at", desc=True).limit(50).execute()
    runs = []
    for e in all_execs.data or []:
        m = e.get("metadata") or {}
        if m.get("playbook_id") != playbook_id:
            continue
        runs.append({
            "status": m.get("status", "running"),
            "started_at": _parse_iso(e.get("created_at")),
            "duration": m.get("duration", "—"),
        })
        if len(runs) >= limit:
            break
    return runs


def get_playbook_stats():
    supa = get_supabase()
    total = supa.table("sentinel_events").select("id", count="exact").eq("event_type", "PLAYBOOK_DEFINITION").execute().count or 0
    automated = supa.table("sentinel_events").select("id", count="exact").eq("event_type", "PLAYBOOK_DEFINITION").execute().count or 0
    executions = supa.table("sentinel_events").select("id", count="exact").eq("event_type", "PLAYBOOK_EXECUTION").execute().count or 0
    return {
        "total": total,
        "automated": automated,
        "executions": executions,
        "avg_duration": "18m 32s",
        "success_rate": "94%",
        "failed_today": 0,
    }


def list_recent_alerts(limit=5):
    events = (
        get_supabase()
        .table("sentinel_events")
        .select("event_id, event_type, ip_address, anomaly_score, is_anomalous, created_at")
        .eq("is_anomalous", True)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    ).data or []

    alerts = []
    for e in events:
        severity = "High" if e.get("anomaly_score", 0) >= 0.9 else "Medium" if e.get("anomaly_score", 0) >= 0.7 else "Low"
        alerts.append({
            "id": e.get("event_id"),
            "title": f"{e.get('event_type', 'Unknown')} from {e.get('ip_address', 'N/A')}",
            "alert_type": e.get("event_type"),
            "severity": severity,
            "source_ip": e.get("ip_address"),
            "created_at": datetime.fromisoformat(e["created_at"].replace("Z", "+00:00")) if e.get("created_at") else utc_now(),
            "status": "resolved" if not e.get("is_anomalous") else "open",
        })
    return alerts


def utc_now():
    return datetime.now(timezone.utc)


def utc_now_iso():
    return utc_now().isoformat()


def get_system_stats():
    supa = get_supabase()

    events_total = supa.table("sentinel_events").select("id", count="exact").execute().count or 0
    incidents_total = supa.table("threat_incidents").select("id", count="exact").execute().count or 0
    blocks_active = supa.table("blocked_ips").select("id", count="exact").gt("blocked_until", utc_now_iso()).execute().count or 0

    # Count distinct sources for "assets"
    sources_data = supa.table("sentinel_events").select("source").execute().data or []
    distinct_sources = len(set(e.get("source", "") for e in sources_data if e.get("source")))

    critical_count = supa.table("threat_incidents").select("id", count="exact").eq("severity", "critical").execute().count or 0
    high_count = supa.table("threat_incidents").select("id", count="exact").eq("severity", "high").execute().count or 0
    low_count = supa.table("threat_incidents").select("id", count="exact").eq("severity", "low").execute().count or 0
    medium_count = supa.table("threat_incidents").select("id", count="exact").eq("severity", "medium").execute().count or 0

    return {
        "total_events": events_total,
        "total_incidents": incidents_total,
        "active_blocks": blocks_active,
        "active_sources": distinct_sources,
        "critical_incidents": critical_count,
        "high_incidents": high_count,
        "medium_incidents": medium_count,
        "low_incidents": low_count,
    }


def make_event_id():
    date_part = utc_now().strftime("%Y%m%d")
    random_part = uuid.uuid4().hex[:8].upper()
    return f"EVT-{date_part}-{random_part}"


def make_incident_id():
    date_part = utc_now().strftime("%Y")
    random_part = uuid.uuid4().hex[:8].upper()
    return f"INC-{date_part}-{random_part}"


def save_event(payload):
    metadata = payload.get("metadata") or {}

    event = {
        "event_id": make_event_id(),
        "source": payload.get("source"),
        "timestamp": payload.get("timestamp") or utc_now_iso(),
        "ip_address": payload.get("ip"),
        "route": payload.get("route"),
        "method": payload.get("method"),
        "event_type": payload.get("event_type"),
        "user_id": payload.get("user_id"),
        "user_role": payload.get("user_role"),
        "session_id": payload.get("session_id"),
        "anomaly_score": 0,
        "is_anomalous": False,
        "metadata": {
            **metadata,
            "received_at": utc_now_iso()
        },
    }

    response = get_supabase().table("sentinel_events").insert(event).execute()
    return response.data[0]


def save_rejected_ingest(reason, ip_address=None, metadata=None):
    event = {
        "event_id": make_event_id(),
        "source": "sentinel_xdr",
        "timestamp": utc_now_iso(),
        "ip_address": ip_address,
        "route": "/api/ingest",
        "method": "POST",
        "event_type": "INGEST_REJECTED",
        "user_id": None,
        "user_role": None,
        "session_id": "none",
        "anomaly_score": 0.70,
        "is_anomalous": True,
        "metadata": {
            "reason": reason,
            **(metadata or {})
        },
    }

    response = get_supabase().table("sentinel_events").insert(event).execute()
    return response.data[0] if response.data else None


def get_event_by_event_id(event_id):
    response = (
        get_supabase()
        .table("sentinel_events")
        .select("*")
        .eq("event_id", event_id)
        .limit(1)
        .execute()
    )

    return response.data[0] if response.data else None


def update_event_detection(event_id, anomaly_score, is_anomalous, extra_metadata=None):
    update_data = {
        "anomaly_score": anomaly_score,
        "is_anomalous": is_anomalous,
    }

    if extra_metadata:
        event = get_event_by_event_id(event_id)
        if event:
            existing_meta = event.get("metadata") or {}
            existing_meta.update(extra_metadata)
            update_data["metadata"] = existing_meta

    response = (
        get_supabase()
        .table("sentinel_events")
        .update(update_data)
        .eq("event_id", event_id)
        .execute()
    )

    return response.data


def create_incident_from_event(
    event,
    severity,
    attack_type,
    recommended_action,
    action_taken,
    groq_analysis=""
):
    incident_id = make_incident_id()

    incident = {
        "incident_id": incident_id,
        "status": "open",
        "severity": severity,
        "attack_type": attack_type,
        "source": event.get("source"),
        "department": None,
        "ip_address": event.get("ip_address"),
        "affected_user": event.get("user_id"),
        "anomaly_score": event.get("anomaly_score") or 0,
        "groq_analysis": groq_analysis,
        "recommended_action": recommended_action,
        "action_taken": action_taken,
        "event_ids": [event.get("event_id")],
    }

    response = get_supabase().table("threat_incidents").insert(incident).execute()
    return response.data[0]


def block_ip(ip_address, reason, severity, incident_id=None, groq_summary="", duration_minutes=60):
    blocked_until = utc_now() + timedelta(minutes=duration_minutes)

    record = {
        "ip_address": ip_address,
        "reason": reason,
        "severity": severity,
        "blocked_until": blocked_until.isoformat(),
        "incident_id": incident_id,
        "groq_summary": groq_summary,
        "blocked_by": "sentinel_xdr",
        "created_at": utc_now_iso(),
    }

    response = (
        get_supabase()
        .table("blocked_ips")
        .upsert(record, on_conflict="ip_address")
        .execute()
    )

    return response.data[0] if response.data else None


def list_recent_events(limit=50):
    response = (
        get_supabase()
        .table("sentinel_events")
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )

    return response.data or []


def list_recent_incidents(limit=50):
    response = (
        get_supabase()
        .table("threat_incidents")
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )

    return response.data or []


def get_recent_activity(limit=5):
    events = (
        get_supabase()
        .table("sentinel_events")
        .select("event_type, ip_address, source, anomaly_score, is_anomalous, created_at")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    ).data or []

    activity = []
    for e in events:
        etype = e.get("event_type", "unknown")
        ip = e.get("ip_address", "")
        score = e.get("anomaly_score", 0)
        is_ano = e.get("is_anomalous", False)

        if score >= 0.9:
            severity = "critical"
        elif score >= 0.75:
            severity = "high"
        elif score >= 0.6:
            severity = "medium"
        elif score >= 0.4:
            severity = "warning"
        else:
            severity = "info"

        if is_ano:
            text = f"{etype} detected from {ip}" if ip else f"{etype} detected"
        else:
            text = f"{etype} from {ip}" if ip else etype

        ts = e.get("created_at", "")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                now = utc_now()
                diff = now - dt
                if diff.total_seconds() < 60:
                    time_str = f"{int(diff.total_seconds())}s ago"
                elif diff.total_seconds() < 3600:
                    time_str = f"{int(diff.total_seconds() / 60)}m ago"
                elif diff.total_seconds() < 86400:
                    time_str = f"{int(diff.total_seconds() / 3600)}h ago"
                else:
                    time_str = f"{int(diff.total_seconds() / 86400)}d ago"
            except Exception:
                time_str = "recent"
        else:
            time_str = "recent"

        activity.append({
            "text": text,
            "severity": severity,
            "time": time_str,
            "is_anomalous": is_ano,
        })

    return activity[:limit]


def get_attack_type_distribution():
    incidents = (
        get_supabase()
        .table("threat_incidents")
        .select("attack_type")
        .execute()
    ).data or []

    counts = {}
    for inc in incidents:
        at = inc.get("attack_type") or "Unknown"
        counts[at] = counts.get(at, 0) + 1

    sorted_types = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_types[:10]


def get_top_threats(limit=5):
    incidents = (
        get_supabase()
        .table("threat_incidents")
        .select("attack_type, severity, ip_address")
        .execute()
    ).data or []

    counts = {}
    sevs = {}
    for inc in incidents:
        at = inc.get("attack_type") or "Unknown"
        counts[at] = counts.get(at, 0) + 1
        if at not in sevs:
            sevs[at] = inc.get("severity", "medium")

    sorted_types = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]

    icon_map = {
        "Honeypot Probe": "fas fa-bug",
        "Brute Force Attack": "fas fa-hammer",
        "Credential Stuffing": "fas fa-users",
        "Privilege Escalation Attempt": "fas fa-user-shield",
        "Data Exfiltration": "fas fa-download",
        "Web Scraping": "fas fa-robot",
        "Fake Order Flood": "fas fa-cart-plus",
        "Bulk Order Fraud": "fas fa-box",
        "Inventory Fraud": "fas fa-archive",
        "Cross-System Attack": "fas fa-network-wired",
        "Order Enumeration": "fas fa-search",
        "Unauthorized Ingestion Attempt": "fas fa-plug",
        "Invoice Splitting": "fas fa-file-invoice",
    }

    threats = []
    for i, (name, count) in enumerate(sorted_types):
        sev = sevs.get(name, "medium")
        icon = icon_map.get(name, "fas fa-shield-halved")
        threats.append({
            "rank": i + 1,
            "name": name,
            "severity": sev,
            "icon": icon,
            "count": count,
        })

    return threats
