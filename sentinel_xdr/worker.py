import threading
import time
import logging
from datetime import datetime, timezone

from sentinel_xdr.message_queue import dequeue_event, mark_done
from sentinel_xdr.detection_rules import evaluate_event
from sentinel_xdr import active_response, database
from sentinel_xdr.notifier import send_incident_alert
from sentinel_xdr.anomaly_detector import AnomalyDetector

logger = logging.getLogger(__name__)

_anomaly_detector = AnomalyDetector()


_worker_started = False


def _build_ip_history(ip_address):
    """Build minimal ip_history context for ML scoring."""
    history = {"is_new": True, "prior_blocks": 0, "order_count_24h": 0,
               "failed_logins_24h": 0, "unique_sessions": 1,
               "seen_on_both": False, "blocked_on_other": False}
    if not ip_address:
        return history
    try:
        recent = database.list_recent_events(limit=100)
        ip_events = [e for e in recent if e.get("ip_address") == ip_address]
        if ip_events:
            history["is_new"] = len(ip_events) < 3
            history["prior_blocks"] = sum(1 for e in ip_events if e.get("is_anomalous") and e.get("anomaly_score", 0) > 0.8)
            history["order_count_24h"] = sum(1 for e in ip_events if e.get("event_type") == "ORDER_PLACED")
            history["failed_logins_24h"] = sum(1 for e in ip_events if e.get("event_type") == "LOGIN_FAILURE")
            sources = set(e.get("source") for e in ip_events if e.get("source"))
            history["seen_on_both"] = len(sources) > 1
    except Exception:
        pass
    return history


def process_event(event_id):
    event = database.get_event_by_event_id(event_id)

    if not event:
        return

    created_at_str = event.get("created_at")
    detection_seconds = None
    if created_at_str:
        try:
            created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
            detection_seconds = (datetime.now(timezone.utc) - created_at).total_seconds()
        except Exception:
            detection_seconds = None

    result = evaluate_event(event)

    ml_score = 0.0
    try:
        recent = database.list_recent_events(limit=200)
        ip_address = event.get("ip_address", "")
        context = {
            "recent_events_60s": recent[:50],
            "ip_history": _build_ip_history(ip_address),
        }
        ml_score = _anomaly_detector.score(event, context)
    except Exception as e:
        logger.warning("ML scoring failed for %s: %s", event_id, e)

    final_score = max(result["score"], ml_score)
    is_anomalous = result["is_anomalous"] or ml_score >= 0.6

    extra_meta = {"detection_seconds": detection_seconds,
                  "ml_score": round(ml_score, 4)} if detection_seconds is not None else {"ml_score": round(ml_score, 4)}
    database.update_event_detection(
        event_id=event_id,
        anomaly_score=final_score,
        is_anomalous=is_anomalous,
        extra_metadata=extra_meta
    )

    event["anomaly_score"] = final_score
    event["is_anomalous"] = is_anomalous

    if not is_anomalous:
        return

    ml_only = ml_score >= 0.6 and not result["is_anomalous"]
    if ml_only:
        attack_type = "ML_DETECTED_ANOMALY"
        severity = _anomaly_detector.classify_severity(ml_score)
        reason = f"ML model flagged anomaly (score={ml_score:.4f})"
        recommended_action = "WATCH_AND_LOG"
        action_taken = "NONE"
    else:
        attack_type = result["attack_type"]
        severity = result["severity"]
        reason = result["reason"]
        recommended_action = result["recommended_action"]
        action_taken = result["action_taken"]

    groq_placeholder = (
        f"{attack_type} detected. "
        f"{reason} "
        f"Recommended action: {recommended_action}."
    )

    incident = database.create_incident_from_event(
        event=event,
        severity=severity,
        attack_type=attack_type,
        recommended_action=recommended_action,
        action_taken=action_taken,
        groq_analysis=groq_placeholder
    )

    send_incident_alert(incident)

    duration = 60
    if severity == "high":
        duration = 1440
    elif severity == "critical":
        duration = 10080

    if recommended_action == "BLOCK_IP" and event.get("ip_address"):
        database.block_ip(
            ip_address=event["ip_address"],
            reason=reason,
            severity=severity,
            incident_id=incident["incident_id"],
            groq_summary=groq_placeholder,
            duration_minutes=duration
        )

        active_response.dispatch_block_action(
            ip=event["ip_address"],
            reason=reason,
            severity=severity,
            incident_id=incident["incident_id"],
            duration_minutes=duration,
            groq_summary=groq_placeholder
        )

    elif recommended_action == "HOLD_FOR_REVIEW" and event.get("ip_address"):
        database.block_ip(
            ip_address=event["ip_address"],
            reason=reason,
            severity=severity,
            incident_id=incident["incident_id"],
            groq_summary=groq_placeholder,
            duration_minutes=duration
        )

        active_response.dispatch_hold_orders(
            ip=event["ip_address"],
            incident_id=incident["incident_id"]
        )

    elif recommended_action == "RATE_LIMIT" and event.get("ip_address"):
        active_response.dispatch_rate_limit(
            ip=event["ip_address"],
            incident_id=incident["incident_id"]
        )

    elif recommended_action == "REVOKE_SESSION":
        active_response.dispatch_revoke_session(
            session_id=event.get("session_id", ""),
            ip=event.get("ip_address", ""),
            incident_id=incident["incident_id"]
        )


def worker_loop():
    while True:
        event_id = dequeue_event(timeout=1)

        if not event_id:
            time.sleep(0.1)
            continue

        try:
            process_event(event_id)
        except Exception as exc:
            print(f"[Sentinel Worker] Error processing {event_id}: {exc}")
        finally:
            mark_done()


def start_background_worker():
    global _worker_started

    if _worker_started:
        return

    thread = threading.Thread(target=worker_loop, daemon=True)
    thread.start()
    _worker_started = True

    print("[Sentinel Worker] Background worker started")
