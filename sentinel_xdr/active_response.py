import hmac
import hashlib
import json
import logging
import requests
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_connected_systems = []


def register_connected_system(name, webhook_url, secret):
    _connected_systems.append({
        "name": name, "webhook_url": webhook_url, "secret": secret,
    })
    logger.info(f"Registered connected system: {name} @ {webhook_url}")


def dispatch_block_action(ip, reason, severity, incident_id, duration_minutes, groq_summary=""):
    payload = {
        "action": "BLOCK_IP",
        "ip": ip,
        "reason": reason,
        "severity": severity,
        "duration_minutes": duration_minutes,
        "incident_id": incident_id,
        "groq_summary": groq_summary[:500] if groq_summary else "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    results = {}
    for system in _connected_systems:
        ok = _send_signed_webhook(system["webhook_url"], payload, system["secret"])
        results[system["name"]] = ok
        if ok:
            logger.info(f"BLOCK_IP dispatched to {system['name']} for IP {ip}")
        else:
            logger.warning(f"BLOCK_IP FAILED to {system['name']} for IP {ip}")
    return results


def dispatch_hold_orders(ip, incident_id):
    payload = {
        "action": "HOLD_FOR_REVIEW",
        "ip": ip,
        "incident_id": incident_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    results = {}
    for system in _connected_systems:
        ok = _send_signed_webhook(system["webhook_url"], payload, system["secret"])
        results[system["name"]] = ok
    return results


def dispatch_rate_limit(ip, incident_id):
    payload = {
        "action": "RATE_LIMIT",
        "ip": ip,
        "incident_id": incident_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    results = {}
    for system in _connected_systems:
        ok = _send_signed_webhook(system["webhook_url"], payload, system["secret"])
        results[system["name"]] = ok
    return results


def dispatch_revoke_session(session_id, ip, incident_id):
    payload = {
        "action": "REVOKE_SESSION",
        "session_id": session_id,
        "ip": ip,
        "incident_id": incident_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    results = {}
    for system in _connected_systems:
        ok = _send_signed_webhook(system["webhook_url"], payload, system["secret"])
        results[system["name"]] = ok
    return results


def _send_signed_webhook(url, payload, secret):
    try:
        body = json.dumps(payload)
        signature = hmac.new(
            secret.encode(), body.encode(), hashlib.sha256
        ).hexdigest()
        response = requests.post(
            url, data=body,
            headers={
                "Content-Type": "application/json",
                "X-Sentinel-Signature": f"sha256={signature}",
                "X-Sentinel-Source": "sentinel_xdr",
            },
            timeout=5,
        )
        return response.status_code == 200
    except Exception as e:
        logger.warning(f"Webhook to {url} failed: {e}")
        return False
