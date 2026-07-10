import json
import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_FEEDBACK_PATH = os.path.join(os.path.dirname(__file__), "feedback_store.json")

_MIN_FEEDBACK_FOR_RETRAIN = 10


def _ensure_store():
    if not os.path.exists(_FEEDBACK_PATH):
        with open(_FEEDBACK_PATH, "w") as f:
            json.dump([], f)


def get_all_feedback():
    _ensure_store()
    try:
        with open(_FEEDBACK_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def save_feedback(event_id, is_false_positive, notes=""):
    _ensure_store()
    all_fb = get_all_feedback()

    existing = [fb for fb in all_fb if fb.get("event_id") == event_id]
    if existing:
        existing[0].update({
            "is_false_positive": is_false_positive,
            "notes": notes,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        entry = existing[0]
    else:
        entry = {
            "event_id": event_id,
            "is_false_positive": is_false_positive,
            "notes": notes,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        all_fb.append(entry)

    with open(_FEEDBACK_PATH, "w") as f:
        json.dump(all_fb, f, indent=2)

    logger.info("Feedback saved for event %s: FP=%s", event_id, is_false_positive)
    return entry


def get_feedback_for_event(event_id):
    all_fb = get_all_feedback()
    for fb in all_fb:
        if fb.get("event_id") == event_id:
            return fb
    return None


def needs_retrain():
    all_fb = get_all_feedback()
    return len(all_fb) >= _MIN_FEEDBACK_FOR_RETRAIN


def get_training_data():
    from sentinel_xdr.database import list_recent_events
    from sentinel_xdr.anomaly_detector import AnomalyDetector
    from shared.db_client import get_supabase

    all_fb = get_all_feedback()
    feedback_map = {fb["event_id"]: fb["is_false_positive"] for fb in all_fb}

    real_events = list_recent_events(limit=500)
    if not real_events:
        return None

    detector = AnomalyDetector()
    training_vectors = []
    labels = []

    for event in real_events:
        eid = event.get("event_id")
        context = {"recent_events_60s": [], "ip_history": {}}
        try:
            vec = detector.build_feature_vector(event, context)
        except Exception:
            continue

        is_anomalous = event.get("is_anomalous", False)
        if eid in feedback_map:
            label = 0 if feedback_map[eid] else 1
        else:
            label = 1 if is_anomalous else 0

        training_vectors.append(vec)
        labels.append(label)

    if len(training_vectors) < 50:
        return None

    return training_vectors, labels
