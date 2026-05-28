import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

logger = logging.getLogger(__name__)


def send_order_notification(order, pdf_bytes):
    from boltmart.config import Config

    email = order.get("email")
    if not email:
        logger.warning("No email on order %s, skipping notification", order.get("order_id"))
        return

    items = order.get("items", [])
    if isinstance(items, str):
        import json
        items = json.loads(items)

    item_lines = ""
    for i in items:
        item_lines += (
            f"<tr>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{i.get('name', '')}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;text-align:center;'>{i.get('quantity', 0)}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;'>&#8377;{i.get('line_total', 0):,.0f}</td>"
            f"</tr>"
        )

    payment_method = order.get("payment_method", "N/A").upper()
    transaction_id = order.get("transaction_id") or f"TXN-{order_id[-12:]}"
    order_id = order.get("order_id", "N/A")
    total = order.get("total_value", 0)

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,sans-serif;background:#f3f4f6;margin:0;padding:24px;">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
<div style="background:#1a56db;padding:24px;text-align:center;">
<h1 style="color:#fff;margin:0;font-size:22px;">&#9889; Order Confirmed!</h1>
<p style="color:#93c5fd;margin:8px 0 0;font-size:14px;">Thank you for shopping at BoltMart</p>
</div>
<div style="padding:32px;">
<p style="font-size:15px;color:#374151;">Hi <strong>{order.get('customer_name', '')}</strong>,</p>
<p style="font-size:14px;color:#6b7280;line-height:1.6;">Your order has been placed successfully and is being processed. Here's a summary:</p>

<div style="background:#f9fafb;border-radius:8px;padding:16px;margin:16px 0;border:1px solid #e5e7eb;">
<table style="width:100%;font-size:13px;">
<tr><td style="color:#6b7280;padding:4px 0;">Order ID</td><td style="text-align:right;font-weight:600;color:#111827;">{order_id}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Transaction ID</td><td style="text-align:right;font-weight:600;color:#111827;">{transaction_id}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Payment</td><td style="text-align:right;font-weight:600;color:#111827;">{payment_method}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Status</td><td style="text-align:right;font-weight:600;color:#059669;">PAID</td></tr>
</table>
</div>

<table style="width:100%;border-collapse:collapse;font-size:13px;margin:16px 0;">
<thead>
<tr style="background:#f3f4f6;">
<th style="padding:8px;text-align:left;color:#374151;">Item</th>
<th style="padding:8px;text-align:center;color:#374151;">Qty</th>
<th style="padding:8px;text-align:right;color:#374151;">Amount</th>
</tr>
</thead>
<tbody>
{item_lines}
</tbody>
</table>

<div style="border-top:2px solid #1a56db;padding:12px 0;text-align:right;">
<p style="font-size:18px;font-weight:700;color:#111827;margin:0;">&#8377;{total:,.0f}</p>
</div>

<div style="background:#f0fdf4;border-radius:8px;padding:16px;margin:16px 0;border:1px solid #bbf7d0;">
<p style="font-size:13px;color:#166534;margin:0;"><strong>Delivering to:</strong><br/>
{order.get('customer_name', '')}<br/>
{order.get('address', '')}, {order.get('city', '')} - {order.get('pincode', '')}</p>
</div>

<p style="font-size:13px;color:#6b7280;">Invoice PDF is attached. You can also download it from your <a href="{Config.APP_URL}/invoice/{order_id}" style="color:#1a56db;">order page</a>.</p>
</div>
<div style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;">
<p style="font-size:12px;color:#9ca3af;margin:0;">BoltMart &mdash; Industrial & Safety Equipment Supply<br/>
Need help? <a href="mailto:support@boltmart.in" style="color:#1a56db;">support@boltmart.in</a></p>
</div>
</div>
</body>
</html>"""

    if not Config.SMTP_HOST:
        logger.info("SMTP not configured. Email for %s:\nSubject: Order Confirmed - %s\nTo: %s\n(order email logged instead of sent)", order_id, order_id, email)
        logger.debug("Email HTML body:\n%s", html)
        return

    try:
        msg = MIMEMultipart("mixed")
        msg["Subject"] = f"Order Confirmed - {order_id}"
        msg["From"] = Config.SMTP_FROM
        msg["To"] = email
        msg["X-Transaction-ID"] = transaction_id
        msg["X-Order-ID"] = order_id

        msg_alt = MIMEMultipart("alternative")
        msg_alt.attach(MIMEText(f"Order {order_id} confirmed. Total: Rs.{total:,.0f}. Transaction: {transaction_id}", "plain"))
        msg_alt.attach(MIMEText(html, "html"))
        msg.attach(msg_alt)

        if pdf_bytes:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(pdf_bytes)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f'attachment; filename="invoice-{order_id[:12]}.pdf"')
            msg.attach(part)

        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(Config.SMTP_USER, Config.SMTP_PASS)
            server.send_message(msg)
            logger.info("Order notification sent to %s for order %s", email, order_id)

    except Exception as e:
        logger.error("Failed to send email for order %s: %s", order_id, e)

def send_fraud_alert(ip_address, event_type, metadata):
    logger.info("FRAUD ALERT EMAIL TO ADMIN: High risk activity detected from %s. Event: %s, Details: %s", ip_address, event_type, metadata)
    # Simulation: We only log the email sent

def send_user_suspended(email, reason):
    logger.info("USER SUSPENSION EMAIL TO %s: Your account has been suspended. Reason: %s", email, reason)
    # Simulation: We only log the email sent