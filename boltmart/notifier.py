import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

logger = logging.getLogger(__name__)


def _get_smtp_config():
    from boltmart.config import Config
    return Config


def _send_email(to_email, subject, html_body, plain_body=None, attachments=None, extra_headers=None):
    """Core email sender used by all notification functions."""
    config = _get_smtp_config()

    if not config.SMTP_HOST:
        logger.info("SMTP not configured. Email logged:\nSubject: %s\nTo: %s", subject, to_email)
        return False

    try:
        msg = MIMEMultipart("mixed")
        msg["Subject"] = subject
        msg["From"] = config.SMTP_FROM
        msg["To"] = to_email

        if extra_headers:
            for key, value in extra_headers.items():
                msg[key] = value

        msg_alt = MIMEMultipart("alternative")
        if plain_body:
            msg_alt.attach(MIMEText(plain_body, "plain"))
        msg_alt.attach(MIMEText(html_body, "html"))
        msg.attach(msg_alt)

        if attachments:
            for filename, data in attachments:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(data)
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
                msg.attach(part)

        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(config.SMTP_USER, config.SMTP_PASS)
            server.send_message(msg)
            logger.info("Email sent to %s — Subject: %s", to_email, subject)
            return True

    except Exception as e:
        logger.error("Failed to send email to %s: %s", to_email, e)
        return False


# ─────────────────────────────────────────────
# 1. WELCOME EMAIL (on registration)
# ─────────────────────────────────────────────

def send_welcome_email(customer):
    """Send a welcome email when a new customer registers."""
    config = _get_smtp_config()
    email = customer.get("email")
    name = customer.get("name", "Customer")

    if not email:
        logger.warning("No email for customer, skipping welcome email")
        return

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,sans-serif;background:#f3f4f6;margin:0;padding:24px;">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
<div style="background:linear-gradient(135deg,#1a56db,#3b82f6);padding:40px 24px;text-align:center;">
<h1 style="color:#fff;margin:0;font-size:28px;">&#9889; Welcome to BoltMart!</h1>
<p style="color:#93c5fd;margin:12px 0 0;font-size:16px;">Your account has been created successfully</p>
</div>
<div style="padding:32px;">
<p style="font-size:16px;color:#374151;">Hi <strong>{name}</strong>,</p>
<p style="font-size:14px;color:#6b7280;line-height:1.8;">
Thank you for registering with <strong>BoltMart</strong> — your trusted destination for industrial hardware and safety equipment.
</p>

<div style="background:#f0fdf4;border-radius:8px;padding:20px;margin:24px 0;border:1px solid #bbf7d0;">
<h3 style="color:#166534;margin:0 0 12px;font-size:15px;">&#127919; What you can do now:</h3>
<ul style="color:#166534;font-size:13px;line-height:2;margin:0;padding-left:20px;">
<li>Browse our catalog of professional-grade tools</li>
<li>Add items to your cart and wishlist</li>
<li>Place orders with secure payment options</li>
<li>Track your shipments in real-time</li>
<li>Download invoices for all your purchases</li>
</ul>
</div>

<div style="text-align:center;margin:32px 0;">
<a href="{config.APP_URL}/shop" style="background:#1a56db;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:600;font-size:16px;display:inline-block;">
Start Shopping &#8594;
</a>
</div>

<div style="background:#f9fafb;border-radius:8px;padding:16px;border:1px solid #e5e7eb;">
<p style="font-size:12px;color:#6b7280;margin:0;">
<strong>Account Details:</strong><br/>
Email: {email}<br/>
Registered: Just now
</p>
</div>
</div>
<div style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;">
<p style="font-size:12px;color:#9ca3af;margin:0;">BoltMart &mdash; Industrial &amp; Safety Equipment Supply<br/>
Need help? <a href="mailto:support@boltmart.in" style="color:#1a56db;">support@boltmart.in</a></p>
</div>
</div>
</body>
</html>"""

    plain = f"Welcome to BoltMart, {name}! Your account has been created. Visit {config.APP_URL}/shop to start shopping."

    _send_email(email, "Welcome to BoltMart! 🎉", html, plain)


# ─────────────────────────────────────────────
# 2. OTP EMAIL (on login)
# ─────────────────────────────────────────────

def send_otp_email(email, otp_code):
    """Send the OTP verification code via email."""
    config = _get_smtp_config()

    if not email:
        return

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,sans-serif;background:#f3f4f6;margin:0;padding:24px;">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
<div style="background:#1a56db;padding:24px;text-align:center;">
<h1 style="color:#fff;margin:0;font-size:22px;">&#128274; Verify Your Login</h1>
</div>
<div style="padding:32px;text-align:center;">
<p style="font-size:14px;color:#6b7280;">Use the following code to complete your login:</p>

<div style="background:#f0f5ff;border:2px dashed #1a56db;border-radius:12px;padding:24px;margin:24px auto;max-width:250px;">
<p style="font-size:36px;font-weight:800;color:#1a56db;letter-spacing:8px;margin:0;">{otp_code}</p>
</div>

<p style="font-size:13px;color:#9ca3af;">This code expires in <strong>5 minutes</strong>.</p>
<p style="font-size:12px;color:#d1d5db;">If you didn't request this, please ignore this email.</p>
</div>
<div style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;">
<p style="font-size:12px;color:#9ca3af;margin:0;">BoltMart &mdash; Industrial &amp; Safety Equipment Supply</p>
</div>
</div>
</body>
</html>"""

    plain = f"Your BoltMart verification code is: {otp_code}. It expires in 5 minutes."

    _send_email(email, f"Your BoltMart Login OTP: {otp_code}", html, plain)


# ─────────────────────────────────────────────
# 3. ORDER CONFIRMATION EMAIL (on purchase)
# ─────────────────────────────────────────────

def send_order_notification(order, pdf_bytes):
    """Send order confirmation email with invoice PDF attached."""
    config = _get_smtp_config()

    email = order.get("email")
    if not email:
        logger.warning("No email on order %s, skipping notification", order.get("order_id"))
        return

    # FIX: order_id must be defined BEFORE using it
    order_id = order.get("order_id", "N/A")
    transaction_id = order.get("transaction_id") or f"TXN-{order_id[-12:]}"

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
    total = order.get("total_value", 0)
    payment_status = "PAID"

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
<tr><td style="color:#6b7280;padding:4px 0;">Status</td><td style="text-align:right;font-weight:600;color:#059669;">{payment_status}</td></tr>
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

<div style="background:#eff6ff;border-radius:8px;padding:16px;margin:16px 0;border:1px solid #bfdbfe;">
<p style="font-size:13px;color:#1e40af;margin:0;">
&#128666; <strong>Estimated Delivery:</strong> 3-5 business days<br/>
&#128196; Track your order: <a href="{config.APP_URL}/track/{order_id}" style="color:#1a56db;">{config.APP_URL}/track/{order_id}</a>
</p>
</div>

<p style="font-size:13px;color:#6b7280;">Invoice PDF is attached. You can also download it from your <a href="{config.APP_URL}/invoice/{order_id}" style="color:#1a56db;">order page</a>.</p>
</div>
<div style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;">
<p style="font-size:12px;color:#9ca3af;margin:0;">BoltMart &mdash; Industrial &amp; Safety Equipment Supply<br/>
Need help? <a href="mailto:support@boltmart.in" style="color:#1a56db;">support@boltmart.in</a></p>
</div>
</div>
</body>
</html>"""

    plain = f"Order {order_id} confirmed. Total: Rs.{total:,.0f}. Transaction: {transaction_id}"

    attachments = []
    if pdf_bytes:
        attachments.append((f"invoice-{order_id[:12]}.pdf", pdf_bytes))

    _send_email(
        email,
        f"Order Confirmed - {order_id}",
        html, plain,
        attachments=attachments,
        extra_headers={"X-Transaction-ID": transaction_id, "X-Order-ID": order_id}
    )


# ─────────────────────────────────────────────
# 4. ORDER STATUS UPDATE EMAIL
# ─────────────────────────────────────────────

def send_order_status_email(order, new_status):
    """Send email when order status changes (shipped, delivered, cancelled)."""
    config = _get_smtp_config()
    email = order.get("email")
    if not email:
        return

    order_id = order.get("order_id", "N/A")
    name = order.get("customer_name", "Customer")

    status_config = {
        "confirmed": {"icon": "&#9989;", "color": "#059669", "title": "Order Confirmed"},
        "packed": {"icon": "&#128230;", "color": "#d97706", "title": "Order Packed"},
        "shipped": {"icon": "&#128666;", "color": "#2563eb", "title": "Order Shipped"},
        "out_for_delivery": {"icon": "&#128690;", "color": "#7c3aed", "title": "Out for Delivery"},
        "delivered": {"icon": "&#127881;", "color": "#059669", "title": "Order Delivered"},
        "cancelled": {"icon": "&#10060;", "color": "#dc2626", "title": "Order Cancelled"},
    }

    sc = status_config.get(new_status, {"icon": "&#128276;", "color": "#6b7280", "title": f"Order {new_status.title()}"})

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,sans-serif;background:#f3f4f6;margin:0;padding:24px;">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,0.08);">
<div style="background:{sc['color']};padding:24px;text-align:center;">
<h1 style="color:#fff;margin:0;font-size:22px;">{sc['icon']} {sc['title']}</h1>
</div>
<div style="padding:32px;">
<p style="font-size:15px;color:#374151;">Hi <strong>{name}</strong>,</p>
<p style="font-size:14px;color:#6b7280;">Your order <strong>{order_id}</strong> status has been updated to:</p>
<div style="text-align:center;margin:24px 0;">
<span style="background:{sc['color']};color:#fff;padding:12px 32px;border-radius:24px;font-weight:700;font-size:16px;display:inline-block;">
{sc['icon']} {new_status.upper().replace('_', ' ')}
</span>
</div>
<p style="font-size:13px;color:#6b7280;text-align:center;">
<a href="{config.APP_URL}/track/{order_id}" style="color:#1a56db;">Track your order →</a>
</p>
</div>
<div style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;">
<p style="font-size:12px;color:#9ca3af;margin:0;">BoltMart &mdash; Industrial &amp; Safety Equipment Supply</p>
</div>
</div>
</body>
</html>"""

    _send_email(email, f"{sc['title']} - {order_id}", html, f"Order {order_id} is now {new_status}")


# ─────────────────────────────────────────────
# 5. FRAUD ALERT EMAIL (to admin)
# ─────────────────────────────────────────────

def send_fraud_alert(ip_address, event_type, metadata):
    """Send fraud alert email to admin — actually sends now."""
    config = _get_smtp_config()
    admin_email = config.ADMIN_EMAIL if hasattr(config, 'ADMIN_EMAIL') else None

    if not admin_email:
        logger.info("FRAUD ALERT (no admin email configured): IP=%s Event=%s Details=%s", ip_address, event_type, metadata)
        return

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,sans-serif;background:#f3f4f6;margin:0;padding:24px;">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,0.08);border-top:4px solid #dc2626;">
<div style="background:#fef2f2;padding:24px;text-align:center;">
<h1 style="color:#dc2626;margin:0;font-size:22px;">&#128680; Fraud Alert — BoltMart</h1>
</div>
<div style="padding:32px;">
<p style="font-size:14px;color:#374151;">A high-risk activity has been detected:</p>
<div style="background:#fef2f2;border-radius:8px;padding:16px;margin:16px 0;border:1px solid #fecaca;">
<table style="width:100%;font-size:13px;">
<tr><td style="color:#6b7280;padding:4px 0;">IP Address</td><td style="text-align:right;font-weight:600;color:#dc2626;">{ip_address}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Event Type</td><td style="text-align:right;font-weight:600;color:#111827;">{event_type}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Failures</td><td style="text-align:right;font-weight:600;color:#111827;">{metadata.get('failures', 'N/A')}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Reason</td><td style="text-align:right;font-weight:600;color:#111827;">{metadata.get('reason', 'N/A')}</td></tr>
<tr><td style="color:#6b7280;padding:4px 0;">Action Taken</td><td style="text-align:right;font-weight:600;color:#dc2626;">{metadata.get('action_taken', 'N/A')}</td></tr>
</table>
</div>
</div>
</div>
</body>
</html>"""

    _send_email(admin_email, f"🚨 FRAUD ALERT: {event_type} from {ip_address}", html,
                f"Fraud Alert: {event_type} from IP {ip_address}. Details: {metadata}")


# ─────────────────────────────────────────────
# 6. USER SUSPENDED EMAIL (to user)
# ─────────────────────────────────────────────

def send_user_suspended(email, reason):
    """Send account suspension notification to user — actually sends now."""
    config = _get_smtp_config()

    if not email:
        return

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Segoe UI,sans-serif;background:#f3f4f6;margin:0;padding:24px;">
<div style="max-width:600px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,0.08);border-top:4px solid #dc2626;">
<div style="background:#fef2f2;padding:24px;text-align:center;">
<h1 style="color:#dc2626;margin:0;font-size:22px;">&#9888;&#65039; Account Suspended</h1>
</div>
<div style="padding:32px;">
<p style="font-size:14px;color:#374151;">Your BoltMart account has been temporarily suspended.</p>
<div style="background:#fef2f2;border-radius:8px;padding:16px;margin:16px 0;border:1px solid #fecaca;">
<p style="font-size:13px;color:#991b1b;margin:0;"><strong>Reason:</strong> {reason}</p>
</div>
<p style="font-size:13px;color:#6b7280;">If you believe this is a mistake, please contact our support team at <a href="mailto:support@boltmart.in" style="color:#1a56db;">support@boltmart.in</a>.</p>
</div>
<div style="background:#f9fafb;padding:16px 32px;text-align:center;border-top:1px solid #e5e7eb;">
<p style="font-size:12px;color:#9ca3af;margin:0;">BoltMart &mdash; Industrial &amp; Safety Equipment Supply</p>
</div>
</div>
</body>
</html>"""

    _send_email(email, "Account Suspended — BoltMart", html,
                f"Your BoltMart account has been suspended. Reason: {reason}")