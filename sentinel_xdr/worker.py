import threading
import time
from datetime import datetime, timezone

from sentinel_xdr.message_queue import dequeue_event, mark_done
from sentinel_xdr.detection_rules import evaluate_event
from sentinel_xdr import active_response, database
from sentinel_xdr.notifier import send_incident_alert


_worker_started = False


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

    extra_meta = {"detection_seconds": detection_seconds} if detection_seconds is not None else None
    database.update_event_detection(
        event_id=event_id,
        anomaly_score=result["score"],
        is_anomalous=result["is_anomalous"],
        extra_metadata=extra_meta
    )

    event["anomaly_score"] = result["score"]
    event["is_anomalous"] = result["is_anomalous"]

    if not result["is_anomalous"]:
        return

    groq_placeholder = (
        f"{result['attack_type']} detected. "
        f"{result['reason']} "
        f"Recommended action: {result['recommended_action']}."
    )

    incident = database.create_incident_from_event(
        event=event,
        severity=result["severity"],
        attack_type=result["attack_type"],
        recommended_action=result["recommended_action"],
        action_taken=result["action_taken"],
        groq_analysis=groq_placeholder
    )

    send_incident_alert(incident)

    duration = 60
    if result["severity"] == "high":
        duration = 1440
    elif result["severity"] == "critical":
        duration = 10080

    if result["recommended_action"] == "BLOCK_IP" and event.get("ip_address"):
        database.block_ip(
            ip_address=event["ip_address"],
            reason=result["reason"],
            severity=result["severity"],
            incident_id=incident["incident_id"],
            groq_summary=groq_placeholder,
            duration_minutes=duration
        )

        active_response.dispatch_block_action(
            ip=event["ip_address"],
            reason=result["reason"],
            severity=result["severity"],
            incident_id=incident["incident_id"],
            duration_minutes=duration,
            groq_summary=groq_placeholder
        )

    elif result["recommended_action"] == "HOLD_FOR_REVIEW" and event.get("ip_address"):
        database.block_ip(
            ip_address=event["ip_address"],
            reason=result["reason"],
            severity=result["severity"],
            incident_id=incident["incident_id"],
            groq_summary=groq_placeholder,
            duration_minutes=duration
        )

        active_response.dispatch_hold_orders(
            ip=event["ip_address"],
            incident_id=incident["incident_id"]
        )

    elif result["recommended_action"] == "RATE_LIMIT" and event.get("ip_address"):
        active_response.dispatch_rate_limit(
            ip=event["ip_address"],
            incident_id=incident["incident_id"]
        )

    elif result["recommended_action"] == "REVOKE_SESSION":
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
