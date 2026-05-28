import smtplib
import logging
from email.mime.text import MIMEText

from sentinel_xdr.config import Config

logger = logging.getLogger(__name__)


def send_account_deactivation(user_email, incident_id, attack_type, reason):
    if not Config.SMTP_HOST:
        logger.info(
            "SMTP not configured. Deactivation email skipped for %s. "
            "Would notify about incident %s (%s)",
            user_email, incident_id, attack_type,
        )
        return

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,sans-serif;background:#f3f4f6;margin:0;padding:24px;">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
<div style="background:#dc2626;padding:24px;text-align:center;">
<h1 style="color:#fff;margin:0;font-size:20px;">&#9888; Account Deactivated</h1>
<p style="color:rgba(255,255,255,0.8);margin:8px 0 0;font-size:14px;">Security Action — Sentinel XDR</p>
</div>
<div style="padding:32px;">
<p style="font-size:15px;color:#374151;">Hello,</p>
<p style="font-size:14px;color:#6b7280;line-height:1.6;">
Your account has been deactivated due to suspicious activity detected by our security system.
</p>
<div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px;margin:16px 0;">
<table style="width:100%;font-size:13px;">
<tr><td style="color:#6b7280;padding:4px 0;">Incident ID</td><td style="text-align:right;font-weight:600;color:#111827;">{incident_id}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Issue</td><td style="text-align:right;font-weight:600;color:#111827;">{attack_type}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Reason</td><td style="text-align:right;font-weight:600;color:#dc2626;">{reason}</td></tr>
</table>
</div>
<p style="font-size:13px;color:#6b7280;line-height:1.6;">
If you believe this is a mistake, please contact your system administrator or IT support team to review and reinstate your access.
</p>
</div>
<div style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;">
<p style="font-size:12px;color:#9ca3af;margin:0;">Sentinel XDR &mdash; Automated Security Monitoring<br/>This is an automated message. Do not reply.</p>
</div>
</div>
</body>
</html>"""

    try:
        msg = MIMEText(html, "html")
        msg["Subject"] = f"Account Deactivated - {attack_type} - {incident_id}"
        msg["From"] = Config.SMTP_FROM
        msg["To"] = user_email

        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(Config.SMTP_USER, Config.SMTP_PASS)
            server.send_message(msg)

        logger.info("Deactivation email sent to %s for incident %s", user_email, incident_id)
    except Exception as e:
        logger.error("Failed to send deactivation email: %s", e)


def send_incident_alert(incident):
    if not Config.SMTP_HOST:
        logger.info(
            "SMTP not configured. Incident alert email skipped. "
            "Would send to %s about incident %s: %s",
            Config.ADMIN_EMAIL,
            incident.get("incident_id"),
            incident.get("attack_type"),
        )
        return

    incident_id = incident.get("incident_id", "N/A")
    attack_type = incident.get("attack_type", "Unknown")
    severity = incident.get("severity", "low")
    ip_address = incident.get("ip_address", "Unknown")
    source = incident.get("source", "Unknown")
    groq_analysis = incident.get("groq_analysis", "")
    anomaly_score = incident.get("anomaly_score", 0)

    body = f"""
Security Incident Detected — Sentinel XDR

Incident ID: {incident_id}
Attack Type: {attack_type}
Severity: {severity.upper()}
Anomaly Score: {anomaly_score}
Source: {source}
IP Address: {ip_address}

Analysis:
{groq_analysis}

Action Required: Review and investigate this incident immediately.
Dashboard: http://localhost:5003/incidents/{incident_id}
"""

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,sans-serif;background:#f3f4f6;margin:0;padding:24px;">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
<div style="background:{'#dc2626' if severity == 'critical' else '#ea580c' if severity == 'high' else '#ca8a04'};padding:24px;text-align:center;">
<h1 style="color:#fff;margin:0;font-size:20px;">&#9888; Security Incident Detected</h1>
<p style="color:rgba(255,255,255,0.8);margin:8px 0 0;font-size:14px;">Sentinel XDR - Automated Alert</p>
</div>
<div style="padding:32px;">
<div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px;margin-bottom:16px;">
<table style="width:100%;font-size:13px;">
<tr><td style="color:#6b7280;padding:4px 0;">Incident ID</td><td style="text-align:right;font-weight:600;color:#111827;">{incident_id}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Attack Type</td><td style="text-align:right;font-weight:600;color:#111827;">{attack_type}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Severity</td><td style="text-align:right;font-weight:600;color:#dc2626;">{severity.upper()}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Score</td><td style="text-align:right;font-weight:600;color:#111827;">{anomaly_score}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Source</td><td style="text-align:right;font-weight:600;color:#111827;">{source}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">IP Address</td><td style="text-align:right;font-weight:600;color:#00d4ff;font-family:monospace;">{ip_address}</td></tr>
</table>
</div>
<div style="background:#f9fafb;border-radius:8px;padding:16px;border:1px solid #e5e7eb;">
<p style="font-size:13px;color:#374151;margin:0;white-space:pre-wrap;">{groq_analysis}</p>
</div>
<div style="margin-top:16px;text-align:center;">
<a href="http://localhost:5003/incidents/{incident_id}" style="display:inline-block;padding:12px 24px;background:#2563eb;color:#fff;text-decoration:none;border-radius:8px;font-size:14px;">View in Dashboard</a>
</div>
</div>
<div style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;">
<p style="font-size:12px;color:#9ca3af;margin:0;">Sentinel XDR &mdash; Automated Security Monitoring<br/>This is an automated alert. Do not reply.</p>
</div>
</div>
</body>
</html>"""

    try:
        msg = MIMEText(html, "html")
        msg["Subject"] = f"[{severity.upper()}] Security Incident - {attack_type} - {incident_id}"
        msg["From"] = Config.SMTP_FROM
        msg["To"] = Config.ADMIN_EMAIL
        msg["X-Incident-ID"] = incident_id

        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(Config.SMTP_USER, Config.SMTP_PASS)
            server.send_message(msg)

        logger.info("Incident alert sent to %s for incident %s", Config.ADMIN_EMAIL, incident_id)
    except Exception as e:
        logger.error("Failed to send incident alert email: %s", e)
