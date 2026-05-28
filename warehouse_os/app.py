import os
import sys
import csv
import io
import json
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timezone
from uuid import uuid4
from functools import wraps
import requests as req

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import (
    Flask, render_template, request, redirect,
    url_for, session as flask_session, g, abort, jsonify, Response, flash
)
from werkzeug.security import check_password_hash, generate_password_hash

from warehouse_os.config import Config
from warehouse_os.sentinel import (
    sentinel_monitor,
    check_blocked_ip_middleware,
    register_defense_webhook,
)
from shared.db_client import get_supabase
from postgrest.exceptions import APIError


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    check_blocked_ip_middleware(app)
    register_defense_webhook(app)

    def get_db():
        return get_supabase()

    def current_user():
        return flask_session.get("user")

    def login_required(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user():
                return redirect(url_for("login"))
            return func(*args, **kwargs)

        return wrapper

    def role_required(*roles):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                user = current_user()
                if not user:
                    return redirect(url_for("login"))
                if user.get("role") not in roles:
                    from warehouse_os.sentinel import _send_to_sentinel
                    _send_to_sentinel({
                        "source": "warehouse_os",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
                        "route": request.path,
                        "method": request.method,
                        "event_type": "PRIVILEGE_ESCALATION_ATTEMPT",
                        "session_id": flask_session.get("session_id", "anonymous"),
                        "user_id": user.get("id"),
                        "user_role": user.get("role"),
                        "metadata": {
                            "required_roles": list(roles),
                            "actual_role": user.get("role"),
                            "attempted_route": request.path,
                        },
                    })
                    abort(403)
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def audit(action, module, affected_record=None, details=None):
        user = current_user() or {}
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user.get("id"),
            "username": user.get("username"),
            "role": user.get("role"),
            "action": action,
            "module": module,
            "affected_record": affected_record,
            "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr),
            "session_id": flask_session.get("session_id"),
            "details": details or {},
        }
        try:
            get_db().table("audit_log").insert(record).execute()
        except Exception:
            pass

    @app.before_request
    def ensure_session_id():
        if "session_id" not in flask_session:
            flask_session["session_id"] = str(uuid4())

    @app.context_processor
    def inject_user():
        return {"current_user": current_user()}

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("403.html"), 403

    # ---------------- AUTH ----------------

    @app.route("/login", methods=["GET", "POST"])
    @sentinel_monitor
    def login():
        g.event_type = "LOGIN_PAGE"

        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")

            resp = (
                get_db()
                .table("users")
                .select("*")
                .eq("email", email)
                .eq("is_active", True)
                .limit(1)
                .execute()
            )

            user = resp.data[0] if resp.data else None

            if not user or not check_password_hash(user["password_hash"], password):
                g.event_type = "LOGIN_FAILED"
                g.telemetry_metadata = {"email": email}
                return render_template("login.html", error="Invalid email or password"), 401

            flask_session["user"] = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "department": user["department"],
            }

            get_db().table("users").update({
                "last_login": datetime.now(timezone.utc).isoformat(),
                "failed_attempts": 0,
            }).eq("id", user["id"]).execute()

            g.event_type = "LOGIN_SUCCESS"
            g.telemetry_metadata = {"user_id": user["id"], "role": user["role"]}

            audit("LOGIN_SUCCESS", "auth", user["id"])

            return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.route("/logout")
    @login_required
    @sentinel_monitor
    def logout():
        g.event_type = "LOGOUT"
        audit("LOGOUT", "auth", current_user().get("id"))
        flask_session.clear()
        return redirect(url_for("login"))

    # ---------------- DASHBOARD ----------------

    @app.route("/")
    @login_required
    @sentinel_monitor
    def dashboard():
        g.event_type = "WAREHOUSE_DASHBOARD_VIEW"

        db = get_db()
        user = current_user()
        role = user.get("role")

        # Basic data needed across roles
        all_products = (
            db.table("products")
            .select("*")
            .execute()
            .data or []
        )

        low_stock_count = len([
            p for p in all_products
            if int(p.get("stock_count") or 0) <= int(p.get("reorder_level") or 0)
        ])

        if role == "admin":
            now_iso = datetime.now(timezone.utc).isoformat()
            blocked_count = (
                db.table("blocked_ips")
                .select("id", count="exact")
                .gte("blocked_until", now_iso)
                .execute()
                .count or 0
            )

            today_start = datetime.now(timezone.utc).isoformat()[:10]
            audit_today_count = (
                db.table("audit_log")
                .select("id", count="exact")
                .gte("timestamp", today_start)
                .execute()
                .count or 0
            )

            total_users_count = (
                db.table("users")
                .select("id", count="exact")
                .execute()
                .count or 0
            )

            recent_security_events = (
                db.table("audit_log")
                .select("*")
                .order("timestamp", desc=True)
                .limit(5)
                .execute()
                .data or []
            )

            total_products = len(all_products)
            total_stock_units = sum(int(p.get("stock_count") or 0) for p in all_products)

            order_counts = {}
            for s in ("pending", "packed", "shipped", "delivered"):
                c = db.table("orders").select("id", count="exact").eq("status", s).execute().count or 0
                order_counts[s] = c

            low_stock_products = [
                {"sku": p["sku"], "name": p["name"], "stock": p["stock_count"], "reorder": p["reorder_level"]}
                for p in all_products
                if int(p.get("stock_count") or 0) <= int(p.get("reorder_level") or 0)
            ]

            return render_template(
                "dashboard.html",
                blocked_count=blocked_count,
                audit_today_count=audit_today_count,
                total_users_count=total_users_count,
                low_stock_count=low_stock_count,
                low_stock_products=low_stock_products,
                recent_security_events=recent_security_events,
                total_products=total_products,
                total_stock_units=total_stock_units,
                order_counts=order_counts,
            )

        elif role == "manager":
            total_valuation = sum(
                float(p.get("stock_count") or 0) * float(p.get("unit_value") or 0)
                for p in all_products
            )

            today_start = datetime.now(timezone.utc).isoformat()[:10]
            writeoffs_today = (
                db.table("inventory_movements")
                .select("quantity, sku")
                .eq("action", "writeoff")
                .gte("timestamp", today_start)
                .execute()
                .data or []
            )
            product_values = {p["sku"]: float(p.get("unit_value") or 0) for p in all_products}
            writeoff_value_today = sum(
                float(w.get("quantity") or 0) * product_values.get(w.get("sku"), 0)
                for w in writeoffs_today
            )

            pending_count = (
                db.table("orders")
                .select("id", count="exact")
                .eq("status", "pending")
                .execute()
                .count or 0
            )

            recent_orders = (
                db.table("orders")
                .select("*")
                .order("created_at", desc=True)
                .limit(5)
                .execute()
                .data or []
            )

            packed_today_all = (
                db.table("inventory_movements")
                .select("id", count="exact")
                .eq("action", "dispatched")
                .gte("timestamp", today_start)
                .execute()
                .count or 0
            )

            total_products = len(all_products)

            order_counts = {}
            for s in ("pending", "packed", "shipped", "delivered"):
                c = db.table("orders").select("id", count="exact").eq("status", s).execute().count or 0
                order_counts[s] = c

            low_stock_products = [
                {"sku": p["sku"], "name": p["name"], "stock": p["stock_count"], "reorder": p["reorder_level"]}
                for p in all_products
                if int(p.get("stock_count") or 0) <= int(p.get("reorder_level") or 0)
            ]

            return render_template(
                "dashboard.html",
                total_valuation=total_valuation,
                writeoff_value_today=writeoff_value_today,
                pending_count=pending_count,
                low_stock_count=low_stock_count,
                low_stock_products=low_stock_products,
                recent_orders=recent_orders,
                packed_today_all=packed_today_all,
                total_products=total_products,
                order_counts=order_counts,
            )

        elif role == 'delivery':
            today_start = datetime.now(timezone.utc).isoformat()[:10]
            delivered_today_count = (
                db.table("orders")
                .select("id", count="exact")
                .eq("status", "delivered")
                .gte("updated_at", today_start)
                .execute().count or 0
            )
            shipped_orders = (
                db.table("orders")
                .select("*")
                .eq("status", "shipped")
                .order("updated_at", desc=True)
                .limit(5)
                .execute().data or []
            )
            order_counts = {}
            for s in ("pending", "packed", "shipped", "delivered"):
                c = db.table("orders").select("id", count="exact").eq("status", s).execute().count or 0
                order_counts[s] = c
            return render_template(
                "dashboard.html",
                shipped_orders=shipped_orders,
                delivered_today_count=delivered_today_count,
                order_counts=order_counts,
            )

        else: # staff
            pending_count = (
                db.table("orders")
                .select("id", count="exact")
                .eq("status", "pending")
                .execute()
                .count or 0
            )

            today_start = datetime.now(timezone.utc).isoformat()[:10]
            packed_today_count = (
                db.table("inventory_movements")
                .select("id", count="exact")
                .eq("action", "dispatched")
                .eq("performed_by", user.get("id"))
                .gte("timestamp", today_start)
                .execute()
                .count or 0
            )

            recent_orders = (
                db.table("orders")
                .select("*")
                .eq("status", "pending")
                .order("created_at", desc=True)
                .limit(5)
                .execute()
                .data or []
            )

            low_stock_products = [
                {"sku": p["sku"], "name": p["name"], "stock": p["stock_count"], "reorder": p["reorder_level"]}
                for p in all_products
                if int(p.get("stock_count") or 0) <= int(p.get("reorder_level") or 0)
            ]

            order_counts = {}
            for s in ("pending", "packed", "shipped", "delivered"):
                c = db.table("orders").select("id", count="exact").eq("status", s).execute().count or 0
                order_counts[s] = c

            return render_template(
                "dashboard.html",
                pending_count=pending_count,
                packed_today_count=packed_today_count,
                low_stock_count=low_stock_count,
                low_stock_products=low_stock_products,
                recent_orders=recent_orders,
                order_counts=order_counts,
            )

    # ---------------- FULFILLMENT ----------------

    @app.route("/fulfillment")
    @login_required
    @sentinel_monitor
    def fulfillment():
        g.event_type = "FULFILLMENT_QUEUE_VIEW"

        status = request.args.get("status", "pending")

        orders = (
            get_db()
            .table("orders")
            .select("*")
            .eq("source", "boltmart")
            .eq("status", status)
            .order("created_at")
            .execute()
            .data or []
        )

        invoice_threshold = _load_config().get("invoice_threshold", 25000)
        return render_template("fulfillment.html", orders=orders, status=status, invoice_threshold=invoice_threshold)

    @app.route("/orders/<order_id>")
    @login_required
    @sentinel_monitor
    def order_detail(order_id):
        g.event_type = "ORDER_DETAIL_VIEW"
        g.telemetry_metadata = {"order_id": order_id}

        resp = (
            get_db()
            .table("orders")
            .select("*")
            .eq("order_id", order_id)
            .limit(1)
            .execute()
        )

        order = resp.data[0] if resp.data else None

        if not order:
            return "Order not found", 404

        if isinstance(order.get("items"), str):
            order["items"] = json.loads(order["items"])
        elif not isinstance(order.get("items"), list):
            order["items"] = []

        return render_template("order_detail.html", order=order)

    @app.route("/orders/<order_id>/mark-packed", methods=["POST"])
    @login_required
    @sentinel_monitor
    def mark_packed(order_id):
        g.event_type = "ORDER_MARK_PACKED"

        db = get_db()

        resp = (
            db.table("orders")
            .select("*")
            .eq("order_id", order_id)
            .limit(1)
            .execute()
        )

        order = resp.data[0] if resp.data else None

        if not order:
            return "Order not found", 404

        if order.get("status") not in ("pending", "assigned"):
            return "Order cannot be packed from current status", 400

        items = order.get("items") or []

        for item in items:
            sku = item.get("sku")
            quantity = int(item.get("quantity") or 0)

            product_resp = (
                db.table("products")
                .select("*")
                .eq("sku", sku)
                .limit(1)
                .execute()
            )

            product = product_resp.data[0] if product_resp.data else None

            if not product:
                continue

            current_stock = int(product.get("stock_count") or 0)
            new_stock = max(0, current_stock - quantity)

            db.table("products").update({"stock_count": new_stock}).eq("sku", sku).execute()

            db.table("inventory_movements").insert({
                "sku": sku,
                "action": "dispatched",
                "quantity": quantity,
                "reason": f"Order packed: {order_id}",
                "performed_by": current_user().get("id"),
                "order_id": order_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr),
                "session_id": flask_session.get("session_id"),
            }).execute()

        db.table("orders").update({
            "status": "packed",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("order_id", order_id).execute()

        g.telemetry_metadata = {
            "order_id": order_id,
            "item_count": len(items),
            "total_value": float(order.get("total_value") or 0),
        }

        audit("ORDER_MARK_PACKED", "fulfillment", order_id, {
            "items": items,
            "total_value": order.get("total_value"),
        })

        return redirect(url_for("order_detail", order_id=order_id))

    @app.route("/orders/<order_id>/mark-shipped", methods=["POST"])
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def mark_shipped(order_id):
        g.event_type = "ORDER_MARK_SHIPPED"

        db = get_db()
        resp = db.table("orders").select("*").eq("order_id", order_id).limit(1).execute()
        order = resp.data[0] if resp.data else None
        if not order:
            return "Order not found", 404
        if order.get("status") != "packed":
            return "Order must be packed first", 400

        db.table("orders").update({
            "status": "shipped",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("order_id", order_id).execute()

        audit("ORDER_MARK_SHIPPED", "fulfillment", order_id)
        return redirect(url_for("order_detail", order_id=order_id))

    @app.route("/orders/<order_id>/mark-delivered", methods=["POST"])
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def mark_delivered(order_id):
        g.event_type = "ORDER_MARK_DELIVERED"

        db = get_db()
        resp = db.table("orders").select("*").eq("order_id", order_id).limit(1).execute()
        order = resp.data[0] if resp.data else None
        if not order:
            return "Order not found", 404
        if order.get("status") != "shipped":
            return "Order must be shipped first", 400

        db.table("orders").update({
            "status": "delivered",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("order_id", order_id).execute()

        audit("ORDER_MARK_DELIVERED", "fulfillment", order_id)
        return redirect(url_for("order_detail", order_id=order_id))

    # ---------------- DELIVERY ----------------

    @app.route("/delivery")
    @login_required
    @sentinel_monitor
    def delivery_queue():
        g.event_type = "DELIVERY_QUEUE_VIEW"
        orders = (
            get_db().table("orders")
            .select("*")
            .eq("status", "shipped")
            .order("updated_at", desc=True)
            .execute().data or []
        )
        return render_template("delivery.html", orders=orders)

    @app.route("/delivery/<order_id>/deliver", methods=["POST"])
    @login_required
    @sentinel_monitor
    def deliver_order(order_id):
        g.event_type = "ORDER_DELIVERED"

        db = get_db()
        resp = db.table("orders").select("*").eq("order_id", order_id).limit(1).execute()
        order = resp.data[0] if resp.data else None
        if not order:
            return "Order not found", 404
        if order.get("status") != "shipped":
            return "Order must be shipped first", 400

        recipient_name = request.form.get("recipient_name", "").strip()
        delivery_notes = request.form.get("delivery_notes", "").strip()
        payment_collected = request.form.get("payment_collected") == "on"

        update_data = {
            "status": "delivered",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if payment_collected and order.get("payment_method") == "cod":
            update_data["payment_status"] = "collected"

        db.table("orders").update(update_data).eq("order_id", order_id).execute()

        audit("ORDER_DELIVERED", "delivery", order_id, {
            "delivered_by": current_user().get("username"),
            "recipient_name": recipient_name or "Not recorded",
            "delivery_notes": delivery_notes or "",
            "payment_collected": payment_collected,
            "payment_method": order.get("payment_method"),
        })
        flash(f"Order {order_id[:12]}... delivered to {recipient_name or 'recipient'}.")
        return redirect(url_for("delivery_queue"))

    # ---------------- PRODUCT IMAGE HELPERS ----------------

    PRODUCT_IMG_DIR = os.path.join(app.static_folder, "product_images")
    os.makedirs(PRODUCT_IMG_DIR, exist_ok=True)

    def _save_product_image(file, sku):
        if file and file.filename:
            ext = os.path.splitext(file.filename)[1] or ".jpg"
            filename = f"{sku}{ext}"
            filepath = os.path.join(PRODUCT_IMG_DIR, filename)
            file.save(filepath)
            return filename
        return None

    def _product_image_url(product):
        if product and product.get("image_url"):
            return url_for("static", filename=f"product_images/{product['image_url']}")
        return None

    # ---------------- EMAIL NOTIFIER ----------------

    def _send_email(subject, body):
        try:
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = Config.SMTP_FROM
            msg["To"] = Config.ADMIN_EMAIL
            with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT) as server:
                server.starttls()
                server.login(Config.SMTP_USER, Config.SMTP_PASS)
                server.send_message(msg)
        except Exception:
            pass

    # ---------------- PRODUCT CRUD ----------------

    @app.route("/products/new", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def product_new():
        g.event_type = "PRODUCT_CREATE_VIEW"

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            category = request.form.get("category", "").strip()
            stock_count = int(request.form.get("stock_count") or 0)
            reorder_level = int(request.form.get("reorder_level") or 0)
            unit_value = float(request.form.get("unit_value") or 0)

            if not name or not category:
                flash("Name and Category are required.")
                return render_template("product_form.html", product=None, categories=_load_categories())

            prefix_map = {
                "Electronics": "ELEC", "Hardware": "HW", "Raw Material": "RAW",
                "Packaging": "PKG", "Consumables": "CONS", "Furniture": "FURN",
                "Textiles": "TEX", "Food & Beverage": "FNB",
            }
            prefix = prefix_map.get(category, "GEN")
            existing_count = (
                get_db().table("products")
                .select("id", count="exact")
                .like("sku", f"{prefix}-%")
                .execute().count or 0
            )
            sku = f"{prefix}-{existing_count + 1:03d}"

            image_filename = _save_product_image(request.files.get("product_image"), sku)

            get_db().table("products").insert({
                "sku": sku, "name": name, "category": category,
                "stock_count": stock_count, "reorder_level": reorder_level,
                "unit_value": unit_value,
                "image_url": image_filename,
            }).execute()

            audit("PRODUCT_CREATED", "inventory", sku, {"name": name, "category": category})
            flash(f"Product '{name}' created. SKU: {sku}")
            return redirect(url_for("inventory"))

        return render_template("product_form.html", product=None, categories=_load_categories())

    @app.route("/products/<sku>/edit", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def product_edit(sku):
        g.event_type = "PRODUCT_EDIT_VIEW"

        resp = get_db().table("products").select("*").eq("sku", sku).limit(1).execute()
        product = resp.data[0] if resp.data else None
        if not product:
            abort(404)

        categories = _load_categories()

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            category = request.form.get("category", "").strip()
            stock_count = int(request.form.get("stock_count") or 0)
            reorder_level = int(request.form.get("reorder_level") or 0)
            unit_value = float(request.form.get("unit_value") or 0)

            if not name:
                flash("Name is required.")
                return render_template("product_form.html", product=product, categories=categories)

            image_filename = _save_product_image(request.files.get("product_image"), sku)

            update_data = {
                "name": name, "category": category,
                "stock_count": stock_count, "reorder_level": reorder_level,
                "unit_value": unit_value,
            }
            if image_filename:
                update_data["image_url"] = image_filename

            get_db().table("products").update(update_data).eq("sku", sku).execute()

            audit("PRODUCT_UPDATED", "inventory", sku, {"name": name})
            flash(f"Product '{name}' updated.")
            return redirect(url_for("inventory"))

        return render_template("product_form.html", product=product, categories=categories)

    @app.route("/products/<sku>/delete", methods=["POST"])
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def product_delete(sku):
        g.event_type = "PRODUCT_DELETE"

        resp = get_db().table("products").select("*").eq("sku", sku).limit(1).execute()
        product = resp.data[0] if resp.data else None
        if not product:
            abort(404)

        # delete image file if exists
        if product.get("image_url"):
            img_path = os.path.join(PRODUCT_IMG_DIR, product["image_url"])
            if os.path.exists(img_path):
                os.remove(img_path)

        get_db().table("products").delete().eq("sku", sku).execute()
        get_db().table("inventory_movements").delete().eq("sku", sku).execute()

        audit("PRODUCT_DELETED", "inventory", sku, {"name": product.get("name")})
        flash(f"Product '{product.get('name')}' deleted.")
        return redirect(url_for("inventory"))

    # ---------------- STOCK RECEIVING ----------------

    @app.route("/inventory/stock-in", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def stock_in():
        g.event_type = "STOCK_IN_VIEW"

        products = get_db().table("products").select("*").order("name").execute().data or []
        po_id_param = request.args.get("po") or request.form.get("po_id")
        selected_po = None
        po_items = []

        if po_id_param:
            po_resp = get_db().table("purchase_orders").select("*").eq("id", po_id_param).limit(1).execute()
            if po_resp.data:
                selected_po = po_resp.data[0]
                po_items = get_db().table("purchase_order_items").select("*").eq("po_id", po_id_param).execute().data or []

        recent_stockins = (
            get_db().table("inventory_movements")
            .select("*")
            .eq("action", "stock_in")
            .order("timestamp", desc=True)
            .limit(10)
            .execute().data or []
        )

        if request.method == "POST":
            sku = request.form.get("sku")
            quantity = int(request.form.get("quantity") or 0)
            reason = request.form.get("reason", "Restock")
            po_item_id = request.form.get("po_item_id")

            if not sku or quantity <= 0:
                flash("Invalid stock-in data.")
                return redirect(url_for("stock_in"))

            product_resp = get_db().table("products").select("*").eq("sku", sku).limit(1).execute()
            product = product_resp.data[0] if product_resp.data else None
            if not product:
                flash("Product not found.")
                return redirect(url_for("stock_in"))

            current_stock = int(product.get("stock_count") or 0)
            new_stock = current_stock + quantity

            get_db().table("products").update({"stock_count": new_stock}).eq("sku", sku).execute()

            get_db().table("inventory_movements").insert({
                "sku": sku, "action": "stock_in", "quantity": quantity,
                "reason": reason,
                "performed_by": current_user().get("id"),
                "order_id": po_id_param,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr),
                "session_id": flask_session.get("session_id"),
            }).execute()

            # Update PO item if receiving against a PO
            if po_item_id and po_id_param:
                item_resp = get_db().table("purchase_order_items").select("*").eq("id", po_item_id).limit(1).execute()
                if item_resp.data:
                    item = item_resp.data[0]
                    new_received = item.get("received_qty", 0) + quantity
                    get_db().table("purchase_order_items").update({"received_qty": new_received}).eq("id", po_item_id).execute()
                    # Check if all items fully received → mark PO received
                    all_items = get_db().table("purchase_order_items").select("*").eq("po_id", po_id_param).execute().data or []
                    if all(it.get("received_qty", 0) >= it.get("ordered_qty", 0) for it in all_items):
                        get_db().table("purchase_orders").update({"status": "received"}).eq("id", po_id_param).execute()
                        po_data = get_db().table("purchase_orders").select("po_number").eq("id", po_id_param).limit(1).execute()
                        po_num = po_data.data[0]["po_number"] if po_data.data else po_id_param
                        flash(f"PO {po_num} fully received!")

            audit("STOCK_IN", "inventory", sku, {"quantity": quantity, "reason": reason})

            performed_by = current_user().get("username", "Unknown")
            product_name = product.get("name", sku)
            unit_value = float(product.get("unit_value") or 0)
            total_value = unit_value * quantity
            _send_email(
                f"Stock Received: {quantity}x {product_name} ({sku})",
                f"Stock has been received in WarehouseOS.\n\n"
                f"Product: {product_name}\n"
                f"SKU: {sku}\n"
                f"Quantity Received: {quantity}\n"
                f"Unit Value: ₹{unit_value:,.0f}\n"
                f"Total Value: ₹{total_value:,.0f}\n"
                f"Source: {reason}\n"
                f"Performed By: {performed_by}\n"
                f"Previous Stock: {current_stock}\n"
                f"New Stock: {new_stock}\n\n"
                f"WarehouseOS — Stock Receiving Notification"
            )

            flash(f"Stock added: {quantity}x {sku}. New stock: {new_stock}")
            return redirect(url_for("stock_in"))

        return render_template(
            "stock_in.html",
            products=products,
            recent_stockins=recent_stockins,
            selected_po=selected_po,
            po_items=po_items,
        )

    # ---------------- ADMIN ----------------

    @app.route("/admin/users")
    @login_required
    @role_required("admin")
    @sentinel_monitor
    def admin_users():
        g.event_type = "ADMIN_USERS_VIEW"

        users = (
            get_db()
            .table("users")
            .select("id, username, email, role, department, is_active, last_login")
            .order("username")
            .execute()
            .data or []
        )

        return render_template("admin.html", users=users, active_tab="users")

    @app.route("/admin/blocked-ips")
    @login_required
    @role_required("admin")
    @sentinel_monitor
    def blocked_ips():
        g.event_type = "ADMIN_BLOCKED_IPS_VIEW"

        now = datetime.now(timezone.utc)

        ips = (
            get_db()
            .table("blocked_ips")
            .select("*")
            .order("created_at", desc=True)
            .limit(50)
            .execute()
            .data or []
        )

        for ip in ips:
            blocked_until = ip.get("blocked_until")
            if blocked_until:
                until_dt = datetime.fromisoformat(blocked_until.replace("Z", "+00:00"))
                ip["is_active"] = until_dt > now
            else:
                ip["is_active"] = False

        return render_template("admin.html", users=[], blocked_ips_list=ips, active_tab="blocked_ips")

    CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config_store.json")

    def _load_config():
        if not os.path.exists(CONFIG_FILE):
            defaults = {"invoice_threshold": 25000, "writeoff_threshold": 10000}
            _save_config(defaults)
            return defaults
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)

    def _save_config(data):
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)

    @app.route("/admin/config", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    @sentinel_monitor
    def admin_config():
        g.event_type = "ADMIN_CONFIG_ACCESS"

        if request.method == "POST":
            cfg = {
                "invoice_threshold": int(request.form.get("invoice_threshold") or 25000),
                "writeoff_threshold": int(request.form.get("writeoff_threshold") or 10000),
            }
            _save_config(cfg)
            audit("CONFIG_UPDATED", "config", None, cfg)
            flash("Configuration saved.")
            return redirect(url_for("admin_config"))

        cfg = _load_config()
        return render_template("admin.html", users=[], active_tab="config", cfg=cfg)

    # ---------------- CATEGORY MANAGER (JSON-backed) ----------------

    CATEGORIES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "categories_store.json")

    def _load_categories():
        if not os.path.exists(CATEGORIES_FILE):
            defaults = ["Electronics", "Hardware", "Raw Material", "Packaging",
                        "Consumables", "Furniture", "Textiles", "Food & Beverage"]
            _save_categories(defaults)
            return defaults
        with open(CATEGORIES_FILE, "r") as f:
            return json.load(f)

    def _save_categories(categories):
        with open(CATEGORIES_FILE, "w") as f:
            json.dump(categories, f, indent=2)

    @app.route("/admin/categories", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    @sentinel_monitor
    def admin_categories():
        g.event_type = "ADMIN_CATEGORIES_VIEW"

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            if name:
                cats = _load_categories()
                if name not in cats:
                    cats.append(name)
                    cats.sort()
                    _save_categories(cats)
                    audit("CATEGORY_CREATED", "config", name)
                    flash(f"Category '{name}' added.")
                else:
                    flash(f"Category '{name}' already exists.")
            return redirect(url_for("admin_categories"))

        categories = _load_categories()
        return render_template("categories.html", categories=categories)

    @app.route("/admin/categories/<name>/delete", methods=["POST"])
    @login_required
    @role_required("admin")
    @sentinel_monitor
    def category_delete(name):
        g.event_type = "CATEGORY_DELETE"

        cats = _load_categories()
        if name in cats:
            cats.remove(name)
            _save_categories(cats)
            audit("CATEGORY_DELETED", "config", name)
            flash(f"Category '{name}' removed.")

        return redirect(url_for("admin_categories"))

    # ---------------- USER CRUD ----------------

    @app.route("/admin/users/new", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    @sentinel_monitor
    def user_new():
        g.event_type = "USER_CREATE_VIEW"

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "staff")
            department = request.form.get("department", "").strip()

            if not username or not email or not password:
                flash("Username, email, and password are required.")
                return render_template("user_form.html", user=None)

            existing_email = get_db().table("users").select("id").eq("email", email).limit(1).execute().data
            existing_username = get_db().table("users").select("id").eq("username", username).limit(1).execute().data
            if existing_email or existing_username:
                flash("A user with that email or username already exists.")
                return render_template("user_form.html", user=None)

            password_hash = generate_password_hash(password)
            get_db().table("users").insert({
                "username": username, "email": email,
                "password_hash": password_hash,
                "role": role, "department": department,
                "is_active": True,
            }).execute()

            audit("USER_CREATED", "auth", email, {"username": username, "role": role})
            flash(f"User '{username}' created successfully.")
            return redirect(url_for("admin_users"))

        return render_template("user_form.html", user=None)

    @app.route("/admin/users/<user_id>/edit", methods=["GET", "POST"])
    @login_required
    @role_required("admin")
    @sentinel_monitor
    def user_edit(user_id):
        g.event_type = "USER_EDIT_VIEW"

        resp = get_db().table("users").select("*").eq("id", user_id).limit(1).execute()
        user = resp.data[0] if resp.data else None
        if not user:
            abort(404)

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "staff")
            department = request.form.get("department", "").strip()
            is_active = request.form.get("is_active") == "on"

            if not username or not email:
                flash("Username and email are required.")
                return render_template("user_form.html", user=user)

            update_data = {
                "username": username, "email": email,
                "role": role, "department": department,
                "is_active": is_active,
            }
            if password:
                update_data["password_hash"] = generate_password_hash(password)

            get_db().table("users").update(update_data).eq("id", user_id).execute()

            audit("USER_UPDATED", "auth", user_id, {"username": username, "role": role})
            flash(f"User '{username}' updated.")
            return redirect(url_for("admin_users"))

        return render_template("user_form.html", user=user)

    @app.route("/admin/users/<user_id>/delete", methods=["POST"])
    @login_required
    @role_required("admin")
    @sentinel_monitor
    def user_delete(user_id):
        g.event_type = "USER_DELETE"

        resp = get_db().table("users").select("id,username").eq("id", user_id).limit(1).execute()
        user = resp.data[0] if resp.data else None
        if not user:
            abort(404)

        get_db().table("users").delete().eq("id", user_id).execute()
        audit("USER_DELETED", "auth", user_id, {"username": user.get("username")})
        flash(f"User '{user.get('username')}' deleted.")
        return redirect(url_for("admin_users"))

    # ---------------- CHANGE PASSWORD ----------------

    @app.route("/profile/password", methods=["GET", "POST"])
    @login_required
    @sentinel_monitor
    def change_password():
        g.event_type = "CHANGE_PASSWORD_VIEW"

        if request.method == "POST":
            current_pw = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            confirm_pw = request.form.get("confirm_password", "")

            if not current_pw or not new_pw or not confirm_pw:
                flash("All fields are required.")
                return render_template("change_password.html")

            if new_pw != confirm_pw:
                flash("New passwords do not match.")
                return render_template("change_password.html")

            user = current_user()
            user_resp = get_db().table("users").select("password_hash").eq("id", user["id"]).limit(1).execute()
            user_data = user_resp.data[0] if user_resp.data else None
            if not user_data or not check_password_hash(user_data["password_hash"], current_pw):
                flash("Current password is incorrect.")
                return render_template("change_password.html")

            get_db().table("users").update({
                "password_hash": generate_password_hash(new_pw)
            }).eq("id", user["id"]).execute()

            audit("PASSWORD_CHANGED", "auth", user["id"])
            flash("Password changed successfully.")
            return redirect(url_for("dashboard"))

        return render_template("change_password.html")

    @app.route("/api/alerts/stream")
    @login_required
    @role_required("admin")
    def alerts_stream():
        def generate():
            last_timestamp = datetime.now(timezone.utc).isoformat()
            db = get_db()
            import time
            while True:
                time.sleep(2)
                try:
                    events = (
                        db.table("sentinel_events")
                        .select("*")
                        .eq("is_anomalous", True)
                        .gt("timestamp", last_timestamp)
                        .order("timestamp", desc=False)
                        .execute()
                        .data or []
                    )
                    for event in events:
                        last_timestamp = event["timestamp"]
                        yield f"data: {json.dumps(event)}\n\n"
                except Exception:
                    pass
        return Response(generate(), mimetype="text/event-stream")

    @app.route("/admin/stop-attack", methods=["POST"])
    @login_required
    @role_required("admin")
    @sentinel_monitor
    def stop_attack():
        g.event_type = "EMERGENCY_STOP_ATTACK"
        ip_to_block = request.json.get("ip_address")
        if ip_to_block:
            now = datetime.now(timezone.utc)
            from datetime import timedelta
            block_until = (now + timedelta(hours=24)).isoformat()
            try:
                get_db().table("blocked_ips").insert({
                    "ip_address": ip_to_block,
                    "reason": "Emergency Stop Attack Triggered via Admin",
                    "blocked_until": block_until,
                    "created_at": now.isoformat()
                }).execute()
                
                # We can simulate sending an email here
                print(f"FRAUD ALERT: Attack from {ip_to_block} stopped.")
                
                return jsonify({"status": "success", "message": f"IP {ip_to_block} blocked for 24h."})
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500
        return jsonify({"status": "error", "message": "No IP provided."}), 400

    # ---------------- INVENTORY ----------------

    @app.route("/inventory")
    @login_required
    @sentinel_monitor
    def inventory():
        g.event_type = "INVENTORY_VIEW"

        products = (
            get_db()
            .table("products")
            .select("*")
            .order("name")
            .execute()
            .data or []
        )

        return render_template("inventory.html", products=products)

    # ---------------- INVENTORY MOVEMENTS ----------------

    @app.route("/inventory/movements")
    @login_required
    @sentinel_monitor
    def inventory_movements():
        g.event_type = "INVENTORY_MOVEMENTS_VIEW"

        action_filter = request.args.get("action", "")
        sku_filter = request.args.get("sku", "")
        page = int(request.args.get("page", 1))
        per_page = 50

        db = get_db()
        query = db.table("inventory_movements").select("*")

        if action_filter:
            query = query.eq("action", action_filter)
        if sku_filter:
            query = query.eq("sku", sku_filter)

        movements = (
            query
            .order("timestamp", desc=True)
            .range((page - 1) * per_page, page * per_page - 1)
            .execute()
            .data or []
        )

        all_products = db.table("products").select("sku,name").execute().data or []
        product_names = {p["sku"]: p["name"] for p in all_products}

        unique_actions = sorted(set(
            m.get("action") for m in
            db.table("inventory_movements").select("action").limit(200).execute().data or []
            if m.get("action")
        ))
        unique_skus = sorted(set(
            m.get("sku") for m in
            db.table("inventory_movements").select("sku").limit(200).execute().data or []
            if m.get("sku")
        ))

        return render_template(
            "movements.html",
            movements=movements,
            product_names=product_names,
            action_filter=action_filter,
            sku_filter=sku_filter,
            unique_actions=unique_actions,
            unique_skus=unique_skus,
            page=page,
        )

    # ---------------- WRITEOFF ----------------

    @app.route("/inventory/writeoff", methods=["GET"])
    @login_required
    @sentinel_monitor
    def writeoff_page():
        g.event_type = "WRITEOFF_PAGE_VIEW"

        products = get_db().table("products").select("*").order("name").execute().data or []

        recent_writeoffs = (
            get_db()
            .table("inventory_movements")
            .select("*")
            .eq("action", "writeoff")
            .order("timestamp", desc=True)
            .limit(10)
            .execute()
            .data or []
        )

        return render_template("writeoff.html", products=products, recent_writeoffs=recent_writeoffs)

    @app.route("/inventory/writeoff", methods=["POST"])
    @login_required
    @sentinel_monitor
    def submit_writeoff():
        g.event_type = "WRITEOFF_SUBMITTED"

        sku = request.form.get("sku")
        quantity = int(request.form.get("quantity") or 0)
        reason = request.form.get("reason")
        notes = request.form.get("notes", "")

        if not sku or quantity <= 0:
            flash("Invalid write-off data.")
            return redirect(url_for("writeoff_page"))

        product_resp = (
            get_db()
            .table("products")
            .select("*")
            .eq("sku", sku)
            .limit(1)
            .execute()
        )

        product = product_resp.data[0] if product_resp.data else None
        if not product:
            flash("Product not found.")
            return redirect(url_for("writeoff_page"))

        unit_value = float(product.get("unit_value") or 0)
        total_value = unit_value * quantity

        role = flask_session.get("user", {}).get("role")
        writeoff_limit = _load_config().get("writeoff_threshold", 10000)
        if role == "staff" and total_value >= writeoff_limit:
            flash(f"Unauthorized: Write-offs of ₹{writeoff_limit:,} or above require Manager or Admin approval (Estimated: ₹{total_value:,.0f}).")
            
            # Log the blocked attempt in sentinel
            from warehouse_os.sentinel import _send_to_sentinel
            _send_to_sentinel({
                "source": "warehouse_os",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
                "route": request.path,
                "method": request.method,
                "event_type": "HIGH_VALUE_WRITEOFF_BLOCKED",
                "session_id": flask_session.get("session_id", "anonymous"),
                "user_id": flask_session.get("user", {}).get("id"),
                "user_role": role,
                "metadata": {
                    "sku": sku,
                    "quantity": quantity,
                    "total_value": total_value,
                    "reason": reason,
                },
            })
            return redirect(url_for("writeoff_page"))

        current_stock = int(product.get("stock_count") or 0)
        new_stock = max(0, current_stock - quantity)

        now = datetime.now(timezone.utc)
        g.telemetry_metadata = {
            "sku": sku,
            "quantity": quantity,
            "unit_value": unit_value,
            "total_value": total_value,
            "reason": reason,
            "notes": notes,
            "timestamp_hour": now.hour,
            "outside_business_hours": now.hour < 8 or now.hour > 20,
            "user_role": flask_session.get("user", {}).get("role"),
        }

        get_db().table("products").update({
            "stock_count": new_stock
        }).eq("sku", sku).execute()

        get_db().table("inventory_movements").insert({
            "sku": sku,
            "action": "writeoff",
            "quantity": quantity,
            "reason": f"{reason}: {notes}" if notes else reason,
            "performed_by": flask_session.get("user", {}).get("id"),
            "order_id": None,
            "timestamp": now.isoformat(),
            "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr),
            "session_id": flask_session.get("session_id"),
        }).execute()

        audit("INVENTORY_WRITEOFF", "inventory", sku, {
            "quantity": quantity,
            "reason": reason,
            "total_value": total_value,
        })

        performed_by = flask_session.get("user", {}).get("username", "Unknown")
        product_name = product.get("name", sku)
        _send_email(
            f"Write-Off Alert: {quantity}x {product_name} ({sku})",
            f"A write-off has been recorded in WarehouseOS.\n\n"
            f"Product: {product_name}\n"
            f"SKU: {sku}\n"
            f"Quantity: {quantity}\n"
            f"Unit Value: ₹{unit_value:,.0f}\n"
            f"Total Value: ₹{total_value:,.0f}\n"
            f"Reason: {reason}\n"
            f"Notes: {notes or 'N/A'}\n"
            f"Performed By: {performed_by}\n"
            f"Timestamp (UTC): {now.isoformat()[:19]}\n"
            f"Remaining Stock: {new_stock}\n\n"
            f"WarehouseOS — Stock Write-Off Notification"
        )

        flash(f"Write-off submitted: {quantity}x {sku} ({reason}). Value: ₹{total_value:,.0f}")
        return redirect(url_for("writeoff_page"))

    # ---------------- AUDIT ----------------

    @app.route("/admin/audit")
    @login_required
    @role_required("admin")
    @sentinel_monitor
    def audit_page():
        g.event_type = "AUDIT_LOG_VIEW"

        action_filter = request.args.get("action", "")
        module_filter = request.args.get("module", "")
        user_filter = request.args.get("user", "")
        search = request.args.get("search", "")
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))

        db = get_db()
        table = db.table("audit_log")

        today_start = datetime.now(timezone.utc).isoformat()[:10]

        stats = {
            "total_today": table.select("*", count="exact").gte("timestamp", today_start).limit(0).execute().count or 0,
            "total_all": table.select("*", count="exact").limit(0).execute().count or 0,
        }

        unique_actions = table.select("action").limit(200).execute().data or []
        stats["unique_actions"] = len(set(r["action"] for r in unique_actions if r.get("action")))

        unique_modules = table.select("module").limit(200).execute().data or []
        stats["unique_modules"] = len(set(r["module"] for r in unique_modules if r.get("module")))

        unique_users = table.select("username").limit(200).execute().data or []
        stats["unique_users"] = len(set(r["username"] for r in unique_users if r.get("username")))

        available_actions = sorted(set(
            r["action"] for r in unique_actions if r.get("action")
        ))
        available_modules = sorted(set(
            r["module"] for r in unique_modules if r.get("module")
        ))
        available_users = sorted(set(
            r["username"] for r in unique_users if r.get("username")
        ))

        query = table.select("*")

        if action_filter:
            query = query.eq("action", action_filter)
        if module_filter:
            query = query.eq("module", module_filter)
        if user_filter:
            query = query.eq("username", user_filter)
        if search:
            query = query.or_(
                f"details.ilike.%{search}%,affected_record.ilike.%{search}%"
            )

        total = query.count.execute().count if hasattr(query, 'count') else 0
        total_pages = max(1, (total // per_page) + (1 if total % per_page else 0))

        logs = (
            query
            .order("timestamp", desc=True)
            .range((page - 1) * per_page, page * per_page - 1)
            .execute()
            .data or []
        )

        return render_template(
            "audit.html",
            logs=logs,
            stats=stats,
            available_actions=available_actions,
            available_modules=available_modules,
            available_users=available_users,
            action_filter=action_filter,
            module_filter=module_filter,
            user_filter=user_filter,
            search=search,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
        )

    # ---------------- EXPORT ----------------

    @app.route("/export")
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def export_page():
        g.event_type = "EXPORT_PAGE_VIEW"
        return render_template("export.html")

    @app.route("/export/<export_type>")
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def export_data(export_type):
        g.event_type = "DATA_EXPORT"
        g.telemetry_metadata = {
            "export_type": export_type,
            "user_role": flask_session.get("user", {}).get("role"),
        }

        if export_type == "shipments":
            data = get_db().table("shipments").select("*").execute().data or []
            filename = "shipments_export.csv"
        elif export_type == "inventory":
            data = get_db().table("products").select("*").execute().data or []
            filename = "inventory_export.csv"
        elif export_type == "staff":
            data = get_db().table("users").select("username,email,role,department,is_active").execute().data or []
            filename = "staff_roster.csv"
        else:
            flash("Unknown export type.")
            return redirect(url_for("export_page"))

        output = io.StringIO()
        if data:
            writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)

        audit("DATA_EXPORT", "export", export_type, {"export_type": export_type, "rows": len(data)})

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    # ---------------- PURCHASE ORDERS & SUPPLIERS ----------------

    @app.route("/suppliers")
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def suppliers_list():
        g.event_type = "SUPPLIERS_LIST_VIEW"
        try:
            suppliers = get_db().table("suppliers").select("*").order("name").execute().data or []
        except APIError:
            flash("The 'suppliers' table doesn't exist yet. Run database setup first.")
            return render_template("suppliers.html", suppliers=[])
        return render_template("suppliers.html", suppliers=suppliers)

    @app.route("/suppliers/new", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def supplier_new():
        g.event_type = "SUPPLIER_CREATE_VIEW"
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            contact_email = request.form.get("contact_email", "").strip()
            phone = request.form.get("phone", "").strip()
            lead_time_days = int(request.form.get("lead_time_days") or 1)
            if not name:
                flash("Supplier name is required.")
                return render_template("supplier_form.html")
            data = {
                "name": name,
                "contact_email": contact_email,
                "phone": phone,
                "lead_time_days": lead_time_days,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            try:
                get_db().table("suppliers").insert(data).execute()
            except APIError:
                flash("The 'suppliers' table doesn't exist. Ask an admin to run Database Setup first.")
                return redirect(url_for("suppliers_list"))
            audit("SUPPLIER_CREATED", "suppliers", name, data)
            flash(f"Supplier '{name}' added.")
            return redirect(url_for("suppliers_list"))
        return render_template("supplier_form.html")

    @app.route("/suppliers/<supplier_id>/delete", methods=["POST"])
    @login_required
    @role_required("admin")
    @sentinel_monitor
    def supplier_delete(supplier_id):
        g.event_type = "SUPPLIER_DELETE"
        try:
            sup = get_db().table("suppliers").select("name").eq("id", supplier_id).limit(1).execute().data
            if sup:
                get_db().table("suppliers").delete().eq("id", supplier_id).execute()
                audit("SUPPLIER_DELETED", "suppliers", sup[0]["name"])
                flash(f"Supplier '{sup[0]['name']}' deleted.")
        except APIError:
            flash("Tables not set up. Run Database Setup first.")
        return redirect(url_for("suppliers_list"))

    @app.route("/purchase-orders")
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def purchase_orders_list():
        g.event_type = "PO_LIST_VIEW"
        try:
            _ = get_db().table("purchase_orders").select("id").limit(1).execute()
        except APIError:
            flash("The 'purchase_orders' table doesn't exist yet. Run database setup first.")
            return render_template("purchase_orders.html", pos=[], current_status="")
        status = request.args.get("status", "")
        raw_pos = (
            get_db().table("purchase_orders")
            .select("*")
            .order("created_at", desc=True)
            .execute().data or []
        )
        if status:
            raw_pos = [po for po in raw_pos if po.get("status") == status]
        supplier_ids = list(set(po.get("supplier_id") for po in raw_pos if po.get("supplier_id")))
        suppliers = {}
        if supplier_ids:
            for sid in supplier_ids:
                s = get_db().table("suppliers").select("id,name").eq("id", sid).limit(1).execute().data
                if s:
                    suppliers[sid] = s[0]["name"]
        pos = []
        for po in raw_pos:
            po["supplier_name"] = suppliers.get(po.get("supplier_id"), "Unknown")
            cnt = get_db().table("purchase_order_items").select("id", count="exact").eq("po_id", po["id"]).execute().count or 0
            po["items_count"] = cnt
            pos.append(po)
        return render_template("purchase_orders.html", pos=pos, current_status=status)

    @app.route("/purchase-orders/new", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def purchase_order_new():
        g.event_type = "PO_CREATE_VIEW"
        try:
            suppliers = get_db().table("suppliers").select("*").order("name").execute().data or []
        except APIError:
            flash("Tables not set up. Run Database Setup first.")
            return redirect(url_for("purchase_orders_list"))
        products = get_db().table("products").select("*").order("name").execute().data or []

        if request.method == "POST":
            supplier_id = request.form.get("supplier_id")
            notes = request.form.get("notes", "").strip()
            skus = request.form.getlist("sku")
            qtys = request.form.getlist("qty")

            if not supplier_id or not skus:
                flash("Select a supplier and at least one product.")
                return render_template("po_form.html", suppliers=suppliers, products=products)

            try:
                count = get_db().table("purchase_orders").select("id", count="exact").execute().count or 0
            except APIError:
                flash("Database tables not set up. Run Database Setup first.")
                return redirect(url_for("purchase_orders_list"))
            po_number = f"PO-{count + 1:04d}"

            total_value = 0.0
            items_data = []
            for sku, qty_str in zip(skus, qtys):
                qty = int(qty_str) if qty_str.strip() else 0
                if qty <= 0:
                    continue
                prod = next((p for p in products if p["sku"] == sku), None)
                unit_val = float(prod.get("unit_value") or 0) if prod else 0
                total_value += unit_val * qty
                items_data.append({"sku": sku, "ordered_qty": qty, "received_qty": 0, "unit_value": unit_val})

            po_data = {
                "po_number": po_number,
                "supplier_id": supplier_id,
                "status": "sent",
                "total_value": total_value,
                "notes": notes,
                "created_by": current_user().get("id"),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            try:
                po_resp = get_db().table("purchase_orders").insert(po_data).execute()
            except APIError:
                flash("Database tables not set up. Run Database Setup first.")
                return redirect(url_for("purchase_orders_list"))
            po_id = po_resp.data[0]["id"] if po_resp.data else None

            if po_id:
                for item in items_data:
                    item["po_id"] = po_id
                    get_db().table("purchase_order_items").insert(item).execute()

                audit("PO_CREATED", "purchase_orders", po_number, {"items": len(items_data), "total": total_value})

                sup_name = next((s["name"] for s in suppliers if s["id"] == supplier_id), "Unknown")
                prod_names = []
                for item in items_data:
                    p = next((x for x in products if x["sku"] == item["sku"]), None)
                    prod_names.append(f"  {item['sku']} ({p['name'] if p else '?'}) x {item['ordered_qty']} @ ₹{item['unit_value']:,.0f}")
                _send_email(
                    f"Purchase Order Created: {po_number}",
                    f"A new purchase order has been created.\n\n"
                    f"PO Number: {po_number}\n"
                    f"Supplier: {sup_name}\n"
                    f"Total Value: ₹{total_value:,.0f}\n"
                    f"Items:\n" + "\n".join(prod_names) + "\n\n"
                    f"Created by: {current_user().get('username', 'Unknown')}\n"
                    f"WarehouseOS — Purchase Order Notification"
                )

                flash(f"Purchase order {po_number} created.")
                return redirect(url_for("purchase_orders_list"))

            flash("Failed to create PO.")
            return redirect(url_for("purchase_order_new"))

        # Pre-selected products from low-stock
        pre_selected_skus = request.args.getlist("sku")
        return render_template("po_form.html", suppliers=suppliers, products=products, pre_selected_skus=pre_selected_skus)

    @app.route("/purchase-orders/<po_id>")
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def purchase_order_detail(po_id):
        g.event_type = "PO_DETAIL_VIEW"
        try:
            po = get_db().table("purchase_orders").select("*").eq("id", po_id).limit(1).execute().data
        except APIError:
            flash("Database tables not set up. Run Database Setup first.")
            return redirect(url_for("purchase_orders_list"))
        if not po:
            flash("Purchase order not found.")
            return redirect(url_for("purchase_orders_list"))
        po = po[0]
        supplier = get_db().table("suppliers").select("*").eq("id", po["supplier_id"]).limit(1).execute().data
        items = get_db().table("purchase_order_items").select("*").eq("po_id", po_id).execute().data or []
        products = get_db().table("products").select("*").execute().data or []
        product_map = {p["sku"]: p for p in products}
        return render_template("po_detail.html", po=po, supplier=supplier[0] if supplier else None, items=items, product_map=product_map)

    @app.route("/purchase-orders/discrepancies")
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def po_discrepancies():
        g.event_type = "PO_DISCREPANCIES_VIEW"
        try:
            all_items = get_db().table("purchase_order_items").select("*").execute().data or []
            pos_map = {}
            for item in all_items:
                pid = item.get("po_id")
                if pid and pid not in pos_map:
                    po_data = get_db().table("purchase_orders").select("po_number, status, created_at").eq("id", pid).limit(1).execute().data
                    if po_data:
                        pos_map[pid] = po_data[0]
        except APIError:
            flash("Database tables not set up. Run Database Setup first.")
            return render_template("po_discrepancies.html", items=[], product_map={})
        discrepant = []
        for item in all_items:
            po_info = pos_map.get(item.get("po_id"), {})
            if item.get("received_qty", 0) != item.get("ordered_qty", 0) and item.get("ordered_qty", 0) > 0 and po_info.get("status") == "received":
                item["purchase_orders"] = po_info
                discrepant.append(item)
        products = get_db().table("products").select("sku, name").execute().data or []
        product_map = {p["sku"]: p["name"] for p in products}
        return render_template("po_discrepancies.html", items=discrepant, product_map=product_map)

    @app.route("/purchase-orders/<po_id>/cancel", methods=["POST"])
    @login_required
    @role_required("admin", "manager")
    @sentinel_monitor
    def purchase_order_cancel(po_id):
        g.event_type = "PO_CANCEL"
        try:
            po = get_db().table("purchase_orders").select("*").eq("id", po_id).limit(1).execute().data
        except APIError:
            flash("Database tables not set up. Run Database Setup first.")
            return redirect(url_for("purchase_orders_list"))
        if po and po[0]["status"] == "sent":
            get_db().table("purchase_orders").update({"status": "cancelled"}).eq("id", po_id).execute()
            audit("PO_CANCELLED", "purchase_orders", po[0]["po_number"])
            flash(f"PO {po[0]['po_number']} cancelled.")
        else:
            flash("Cannot cancel — PO may already be received or doesn't exist.")
        return redirect(url_for("purchase_orders_list"))

    @app.route("/api/reorder-suggestions")
    @login_required
    @role_required("admin", "manager")
    def reorder_suggestions():
        products = get_db().table("products").select("*").execute().data or []
        suggestions = []
        for p in products:
            stock = int(p.get("stock_count") or 0)
            reorder = int(p.get("reorder_level") or 0)
            if stock <= reorder:
                suggested = max(reorder * 2 - stock, reorder)
                suggestions.append({
                    "sku": p["sku"],
                    "name": p["name"],
                    "current_stock": stock,
                    "reorder_level": reorder,
                    "suggested_qty": suggested,
                    "unit_value": float(p.get("unit_value") or 0),
                })
        return jsonify(suggestions)

    # ---------------- SIMULATION ----------------

    @app.route("/demo/simulate")
    @sentinel_monitor
    def simulation_page():
        g.event_type = "SIMULATION_PAGE_VIEW"

        password = request.args.get("pwd")
        if password != "1234567890":
            return "Access denied. Wrong demo password.", 403

        return render_template("simulation.html")

    @app.route("/demo/simulate/run", methods=["POST"])
    @sentinel_monitor
    def run_simulation():
        g.event_type = "SIMULATION_TRIGGERED"

        attack_type = request.form.get("attack_type")

        if attack_type == "brute_force":
            return _simulate_brute_force()
        elif attack_type == "insider_theft":
            return _simulate_insider_theft()
        elif attack_type == "privilege_escalation":
            return _simulate_privilege_escalation()
        elif attack_type == "data_exfiltration":
            return _simulate_data_exfiltration()
        elif attack_type == "reset_demo":
            return _simulate_reset_demo()

        flash("Unknown simulation type.")
        return redirect(url_for("simulation_page", pwd="1234567890"))

    # ---------------- SIMULATION HELPERS ----------------

    def _simulate_brute_force():
        fake_ip = "192.168.100.10"
        fake_session = f"brute-session-{uuid4().hex[:8]}"

        for i in range(30):
            event = {
                "source": "warehouse_os",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip": fake_ip,
                "route": "/login",
                "method": "POST",
                "event_type": "LOGIN_FAILED",
                "session_id": fake_session,
                "user_id": None,
                "user_role": None,
                "metadata": {
                    "attempted_email": "admin@warehouse.local",
                    "attempt_number": i + 1,
                }
            }
            try:
                req.post(
                    Config.SENTINEL_URL,
                    headers={
                        "Content-Type": "application/json",
                        "X-Sentinel-Secret": Config.SENTINEL_SHARED_SECRET,
                        "X-Source": "warehouse_os",
                    },
                    json=event,
                    timeout=5
                )
            except Exception:
                pass

        flash("Brute force simulation complete. 30 events sent from 192.168.100.10.")
        return redirect(url_for("simulation_page", pwd="1234567890"))

    def _simulate_insider_theft():
        fake_ip = "192.168.100.20"
        fake_session = f"insider-session-{uuid4().hex[:8]}"
        fake_user_id = "sim-staff-001"

        event = {
            "source": "warehouse_os",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": fake_ip,
            "route": "/inventory/writeoff",
            "method": "POST",
            "event_type": "WRITEOFF_SUBMITTED",
            "session_id": fake_session,
            "user_id": fake_user_id,
            "user_role": "staff",
            "metadata": {
                "sku": "HW-009",
                "quantity": 50,
                "unit_value": 2800,
                "total_value": 140000,
                "reason": "Theft",
                "timestamp_hour": 2,
                "outside_business_hours": True,
            }
        }

        try:
            req.post(
                Config.SENTINEL_URL,
                headers={
                    "Content-Type": "application/json",
                    "X-Sentinel-Secret": Config.SENTINEL_SHARED_SECRET,
                    "X-Source": "warehouse_os",
                },
                json=event,
                timeout=5
            )
        except Exception:
            pass

        flash("Insider theft simulation complete. High-value write-off at 2:30 AM from staff account.")
        return redirect(url_for("simulation_page", pwd="1234567890"))

    def _simulate_privilege_escalation():
        fake_ip = "192.168.100.30"
        fake_session = f"privesc-session-{uuid4().hex[:8]}"

        admin_routes = ["/admin/users", "/admin/audit", "/admin/config"]

        for route in admin_routes:
            event = {
                "source": "warehouse_os",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip": fake_ip,
                "route": route,
                "method": "GET",
                "event_type": "PRIVILEGE_ESCALATION_ATTEMPT",
                "session_id": fake_session,
                "user_id": "sim-staff-002",
                "user_role": "staff",
                "metadata": {
                    "target_route": route,
                    "user_role": "staff",
                }
            }
            try:
                req.post(
                    Config.SENTINEL_URL,
                    headers={
                        "Content-Type": "application/json",
                        "X-Sentinel-Secret": Config.SENTINEL_SHARED_SECRET,
                        "X-Source": "warehouse_os",
                    },
                    json=event,
                    timeout=5
                )
            except Exception:
                pass

        flash("Privilege escalation simulation complete. Staff session hit 3 admin routes.")
        return redirect(url_for("simulation_page", pwd="1234567890"))

    def _simulate_data_exfiltration():
        fake_ip = "192.168.100.40"
        fake_session = f"exfil-session-{uuid4().hex[:8]}"

        export_types = ["shipments", "inventory", "staff"]

        for export_type in export_types:
            event = {
                "source": "warehouse_os",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip": fake_ip,
                "route": f"/export/{export_type}",
                "method": "GET",
                "event_type": "DATA_EXPORT",
                "session_id": fake_session,
                "user_id": "sim-manager-001",
                "user_role": "manager",
                "metadata": {
                    "export_type": export_type,
                    "user_role": "manager",
                }
            }
            try:
                req.post(
                    Config.SENTINEL_URL,
                    headers={
                        "Content-Type": "application/json",
                        "X-Sentinel-Secret": Config.SENTINEL_SHARED_SECRET,
                        "X-Source": "warehouse_os",
                    },
                    json=event,
                    timeout=5
                )
            except Exception:
                pass

        flash("Data exfiltration simulation complete. 3 exports from same session in 15 seconds.")
        return redirect(url_for("simulation_page", pwd="1234567890"))

    def _simulate_reset_demo():
        supabase = get_db()

        supabase.table("blocked_ips").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()

        supabase.table("orders").update({
            "status": "pending",
            "sentinel_flag": False,
            "incident_id": None,
        }).neq("status", "pending").execute()

        stock_map = {
            "HW-001": 150, "HW-002": 500, "HW-003": 200,
            "HW-004": 180, "HW-005": 400, "HW-006": 300,
            "HW-007": 600, "HW-008": 250, "HW-009": 80,
            "HW-010": 350, "HW-011": 220, "HW-012": 450,
        }
        for sku, count in stock_map.items():
            supabase.table("products").update({"stock_count": count}).eq("sku", sku).execute()

        supabase.table("users").update({"failed_attempts": 0}).neq("id", "00000000-0000-0000-0000-000000000000").execute()

        flash("Demo state reset. Blocked IPs cleared, orders reset, stock reseeded.")
        return redirect(url_for("simulation_page", pwd="1234567890"))

    # ---------------- DB SETUP ----------------

    SETUP_SQL = """
CREATE TABLE IF NOT EXISTS public.suppliers (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name TEXT NOT NULL,
    contact_email TEXT,
    phone TEXT,
    lead_time_days INTEGER DEFAULT 7,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.purchase_orders (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    po_number TEXT NOT NULL UNIQUE,
    supplier_id UUID REFERENCES public.suppliers(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'sent',
    total_value NUMERIC(12,2) DEFAULT 0,
    notes TEXT,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT now(),
    received_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS public.purchase_order_items (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    po_id UUID REFERENCES public.purchase_orders(id) ON DELETE CASCADE,
    sku TEXT NOT NULL,
    ordered_qty INTEGER DEFAULT 0,
    received_qty INTEGER DEFAULT 0,
    unit_value NUMERIC(10,2) DEFAULT 0
);

ALTER TABLE public.purchase_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.purchase_order_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.suppliers ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "all_access" ON public.purchase_orders;
DROP POLICY IF EXISTS "all_access" ON public.purchase_order_items;
DROP POLICY IF EXISTS "all_access" ON public.suppliers;

CREATE POLICY "all_access" ON public.purchase_orders FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "all_access" ON public.purchase_order_items FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "all_access" ON public.suppliers FOR ALL USING (true) WITH CHECK (true);
"""

    def tables_exist():
        try:
            get_db().table("suppliers").select("id").limit(1).execute()
            get_db().table("purchase_orders").select("id").limit(1).execute()
            get_db().table("purchase_order_items").select("id").limit(1).execute()
            return True
        except APIError:
            return False

    @app.route("/admin/setup-purchasing", methods=["GET", "POST"])
    @login_required
    @role_required("admin", "manager")
    def setup_purchasing():
        if request.method == "POST":
            action = request.form.get("action", "create")
            if action == "verify":
                if tables_exist():
                    flash("All three tables exist and are ready! You can now use suppliers and purchase orders.")
                    return redirect(url_for("purchase_orders_list"))
                else:
                    flash("Tables not found yet. Copy the SQL below and run it in Supabase SQL editor.")
                return redirect(url_for("setup_purchasing"))
            # Try API-based creation first
            try:
                resp = req.post(
                    f"{os.getenv('SUPABASE_URL')}/sql",
                    headers={
                        "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_ROLE_KEY')}",
                        "Content-Type": "application/json",
                        "apikey": os.getenv('SUPABASE_SERVICE_ROLE_KEY'),
                    },
                    json={"query": SETUP_SQL},
                    timeout=15,
                )
                if resp.status_code < 400:
                    flash("Tables created successfully via API!")
                    return redirect(url_for("purchase_orders_list"))
            except Exception:
                pass
            # Fallback: try direct psycopg2 connection
            try:
                import psycopg2
                project_ref = os.getenv('SUPABASE_URL', '').split('//')[1].split('.')[0]
                conn = psycopg2.connect(
                    host=f"db.{project_ref}.supabase.co",
                    port=5432,
                    user="postgres",
                    password=os.getenv('SUPABASE_SERVICE_ROLE_KEY'),
                    dbname="postgres",
                    connect_timeout=5,
                )
                cur = conn.cursor()
                cur.execute(SETUP_SQL)
                conn.commit()
                cur.close()
                conn.close()
                flash("Tables created successfully!")
                return redirect(url_for("purchase_orders_list"))
            except Exception as e:
                flash(f"Could not auto-create tables. Copy the SQL below, go to your Supabase dashboard → SQL Editor, paste and run it. (Error: {str(e)[:100]})")
            return redirect(url_for("setup_purchasing"))
        exists = tables_exist()
        return render_template("setup_purchasing.html", setup_sql=SETUP_SQL, tables_exist=exists)

    # ---------------- HEALTH ----------------

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "warehouse_os"}), 200

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
