from datetime import datetime, timezone, timedelta

from shared.db_client import get_supabase

HONEYPOT_ROUTES = {"/.env", "/admin", "/api/v1/users"}


def _base():
    return {
        "score": 0.10,
        "is_anomalous": False,
        "severity": "low",
        "attack_type": "Normal Activity",
        "recommended_action": "WATCH_AND_LOG",
        "action_taken": "NONE",
        "reason": "Event is within normal behavior range.",
    }


def _alert(score, severity, attack_type, action, reason):
    return {
        "score": score,
        "is_anomalous": True,
        "severity": severity,
        "attack_type": attack_type,
        "recommended_action": action,
        "action_taken": action,
        "reason": reason,
    }


def _count_events(ip_address, event_types, seconds=60):
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
        q = get_supabase().table("sentinel_events").select("id", count="exact")
        q = q.eq("ip_address", ip_address)
        if isinstance(event_types, str):
            q = q.eq("event_type", event_types)
        else:
            q = q.in_("event_type", event_types)
        q = q.gte("created_at", cutoff)
        result = q.execute()
        return result.count or 0
    except Exception:
        return 0


def _count_distinct_users(ip_address, event_type, seconds=120):
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
        result = (
            get_supabase().table("sentinel_events")
            .select("user_id")
            .eq("ip_address", ip_address)
            .eq("event_type", event_type)
            .gte("created_at", cutoff)
            .execute()
        )
        users = set(e.get("user_id") for e in (result.data or []) if e.get("user_id"))
        return len(users)
    except Exception:
        return 0


def _count_other_sources(ip_address, exclude_source, seconds=3600):
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
        result = (
            get_supabase().table("sentinel_events")
            .select("source")
            .eq("ip_address", ip_address)
            .neq("source", exclude_source)
            .gte("created_at", cutoff)
            .execute()
        )
        sources = set(e.get("source") for e in (result.data or []) if e.get("source"))
        return len(sources)
    except Exception:
        return 0


def _count_unique_order_tracks(session_id, seconds=1800):
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
        result = (
            get_supabase().table("sentinel_events")
            .select("route")
            .eq("session_id", session_id)
            .eq("event_type", "ORDER_TRACK")
            .gte("created_at", cutoff)
            .execute()
        )
        routes = set(e.get("route") for e in (result.data or []) if e.get("route"))
        return len(routes)
    except Exception:
        return 0


def evaluate_event(event):
    route = event.get("route") or ""
    event_type = event.get("event_type") or ""
    method = event.get("method") or "GET"
    ip = event.get("ip_address") or ""
    session_id = event.get("session_id") or ""
    metadata = event.get("metadata") or {}

    # ── Honeypot probe ─────────────────────────────────────────────────────
    if route in HONEYPOT_ROUTES or event_type == "HONEYPOT_PROBE":
        return _alert(0.95, "critical", "Honeypot Probe", "BLOCK_IP",
                      f"IP accessed hidden honeypot route {route}.")

    # ── Unauthorized ingestion ─────────────────────────────────────────────
    if event_type == "INGEST_REJECTED":
        return _alert(0.70, "medium", "Unauthorized Ingestion Attempt",
                      "WATCH_AND_LOG",
                      "Request attempted to send telemetry without valid Sentinel authentication.")

    # ── Privilege escalation ───────────────────────────────────────────────
    if event_type == "PRIVILEGE_ESCALATION_ATTEMPT":
        attempted_role = metadata.get("attempted_role", "unknown")
        return _alert(0.90, "critical", "Privilege Escalation Attempt",
                      "BLOCK_IP",
                      f"User {event.get('user_id', 'unknown')} attempted escalation to {attempted_role}.")

    # ── Data exfiltration ──────────────────────────────────────────────────
    if event_type == "DATA_EXPORT":
        export_count = metadata.get("export_count", 0) or metadata.get("record_count", 0)
        if export_count >= 100:
            return _alert(0.85, "high", "Data Exfiltration", "BLOCK_IP",
                          f"Bulk data export of {export_count} records from IP {ip}.")
        if export_count >= 50:
            return _alert(0.65, "medium", "Data Exfiltration", "WATCH_AND_LOG",
                          f"Large data export of {export_count} records from IP {ip}.")

    # ── Web scraping ───────────────────────────────────────────────────────
    if event_type in ("PRODUCT_VIEW", "PAGE_VIEW_GET") and "product" in route:
        count = _count_events(ip, event_type, seconds=60)
        if count >= 30:
            return _alert(0.80, "high", "Web Scraping", "RATE_LIMIT",
                          f"Rapid product views ({count}/min) from IP {ip}.")

    # ── Brute force ───────────────────────────────────────────────────────
    if event_type == "LOGIN_FAILURE":
        count = _count_events(ip, "LOGIN_FAILURE", seconds=120)
        if count >= 20:
            return _alert(0.95, "critical", "Brute Force Attack", "BLOCK_IP",
                          f"Rapid login failures ({count}) from IP {ip}.")
        if count >= 10:
            return _alert(0.85, "high", "Brute Force Attack", "RATE_LIMIT",
                          f"Multiple login failures ({count}) from IP {ip}.")
        if count >= 5:
            return _alert(0.60, "medium", "Brute Force Attack", "WATCH_AND_LOG",
                          f"Elevated login failures ({count}) from IP {ip}.")

    # ── Credential stuffing ────────────────────────────────────────────────
    if event_type in ("LOGIN_FAILURE", "LOGIN_ATTEMPT"):
        users = _count_distinct_users(ip, "LOGIN_FAILURE", seconds=120)
        if users >= 10:
            return _alert(0.90, "critical", "Credential Stuffing", "BLOCK_IP",
                          f"Login failures against {users} different accounts from IP {ip}.")
        if users >= 5:
            return _alert(0.75, "high", "Credential Stuffing", "RATE_LIMIT",
                          f"Login failures against {users} different accounts from IP {ip}.")

    # ── Fake order flood ───────────────────────────────────────────────────
    if event_type == "CHECKOUT_ATTEMPT":
        count = _count_events(ip, "CHECKOUT_ATTEMPT", seconds=60)
        if count >= 15:
            return _alert(0.92, "critical", "Fake Order Flood", "BLOCK_IP",
                          f"Rapid checkout attempts ({count}/min) from IP {ip}.")
        if count >= 8:
            return _alert(0.80, "high", "Fake Order Flood", "RATE_LIMIT",
                          f"Elevated checkout attempts ({count}/min) from IP {ip}.")

    # ── Bulk order fraud ───────────────────────────────────────────────────
    if event_type == "ORDER_PLACED":
        count = _count_events(ip, "ORDER_PLACED", seconds=300)
        if count >= 10:
            return _alert(0.90, "critical", "Bulk Order Fraud", "BLOCK_IP",
                          f"Rapid order placement ({count} in 5 min) from IP {ip}.")
        if count >= 5:
            return _alert(0.80, "high", "Bulk Order Fraud", "HOLD_FOR_REVIEW",
                          f"Elevated order placement ({count} in 5 min) from IP {ip}.")

    # ── Inventory fraud ────────────────────────────────────────────────────
    if event_type == "WRITE_OFF":
        qty = metadata.get("quantity", 0)
        unit_value = metadata.get("unit_value", 0)
        total_value = qty * unit_value
        if qty >= 100 or total_value >= 100000:
            return _alert(0.90, "critical", "Inventory Fraud", "HOLD_FOR_REVIEW",
                          f"Large write-off: {qty} units (${total_value}) by {event.get('user_id', 'unknown')}.")
        if qty >= 50:
            return _alert(0.70, "medium", "Inventory Fraud", "WATCH_AND_LOG",
                          f"Write-off of {qty} units by {event.get('user_id', 'unknown')}.")

    # ── Invoice splitting ──────────────────────────────────────────────────
    if event_type == "INVOICE_SUBMIT":
        amount = metadata.get("amount", 0)
        if amount and amount < 1000:
            count = _count_events(ip, "INVOICE_SUBMIT", seconds=3600)
            if count >= 5:
                return _alert(0.75, "high", "Invoice Splitting", "HOLD_FOR_REVIEW",
                              f"Multiple small invoices ({count} in 1h) from IP {ip}.")

    # ── Cross-system attack ────────────────────────────────────────────────
    if ip and event.get("source"):
        other = _count_other_sources(ip, event.get("source"), seconds=3600)
        if other >= 2:
            return _alert(0.85, "high", "Cross-System Attack", "BLOCK_IP",
                          f"IP {ip} active across {other + 1} systems — possible horizontal movement.")

    # ── Order enumeration ──────────────────────────────────────────────────
    if event_type == "ORDER_TRACK":
        unique = _count_unique_order_tracks(session_id, seconds=1800)
        if unique >= 30:
            return _alert(0.80, "high", "Order Enumeration", "RATE_LIMIT",
                          f"Session tracked {unique} different orders — possible enumeration.")
        if unique >= 15:
            return _alert(0.60, "medium", "Order Enumeration", "WATCH_AND_LOG",
                          f"Session tracked {unique} different orders.")

    # ── Normal / checkout ──────────────────────────────────────────────────
    if method == "POST" and route == "/checkout":
        result = _base()
        result["score"] = 0.25
        result["attack_type"] = "Checkout Activity"
        return result

    return _base()
