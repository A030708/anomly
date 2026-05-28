import os
import sys
import json
import threading
from datetime import datetime, timezone
from uuid import uuid4

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import (
    Flask, render_template, redirect, url_for, request,
    jsonify, session as flask_session, g, make_response
)

from boltmart.config import Config
from boltmart.sentinel import sentinel_monitor, check_blocked_ip_middleware, register_defense_webhook
from boltmart.invoice import generate_invoice
from boltmart.notifier import send_order_notification
from shared.db_client import get_supabase
from boltmart.mock_db import create_customer, get_customer, set_otp, verify_otp, OTP_CODES
from boltmart.anomaly import evaluate_payment_failure, reset_payment_status



def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    app.secret_key = Config.SECRET_KEY

    check_blocked_ip_middleware(app)
    register_defense_webhook(app)

    # --- Helpers ---

    def generate_session_id():
        if "sid" not in flask_session:
            flask_session["sid"] = str(uuid4())
        return flask_session["sid"]

    def get_cart():
        generate_session_id()
        return flask_session.get("cart", [])

    def save_cart(cart):
        flask_session["cart"] = cart

    def make_order_id():
        date_part = datetime.now().strftime("%Y%m%d")
        random_part = uuid4().hex[:6].upper()
        return f"ORD-{date_part}-{random_part}"

    def get_db():
        return get_supabase()

    def _send_notification(order_record):
        try:
            order_record = dict(order_record)
            if order_record.get("payment_method") != "cod":
                order_record["transaction_id"] = f"TXN-{order_record.get('order_id', '')[-12:]}"
            pdf = generate_invoice(order_record)
            send_order_notification(order_record, pdf)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Notification failed for order %s: %s", order_record.get("order_id"), e)

    # --- Middleware ---

    def make_ensure_session():
        if not request.path.startswith("/static"):
            generate_session_id()
            if "_created_at" not in flask_session:
                flask_session["_created_at"] = datetime.now(timezone.utc).isoformat()

    app.before_request(make_ensure_session)

    @app.before_request
    def load_customer():
        g.customer = None
        if "customer_email" in flask_session:
            g.customer = get_customer(flask_session["customer_email"])

    # --- Error Handlers ---

    @app.errorhandler(403)
    def handle_403(e):
        if hasattr(g, "is_blocked") and g.is_blocked:
            block_info = getattr(g, "block_info", {})
            return render_template(
                "403.html",
                reason=block_info.get("reason", "Unknown"),
                incident_id=block_info.get("incident_id"),
                severity=block_info.get("severity"),
                until=block_info.get("blocked_until"),
                ip=block_info.get("ip_address", request.remote_addr),
            ), 403
        return render_template("403.html"), 403

    # --- Auth Routes ---
    
    @app.route("/register", methods=["GET", "POST"])
    @sentinel_monitor
    def register():
        g.event_type = "CUSTOMER_REGISTER"
        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")
            name = request.form.get("name")
            phone = request.form.get("phone")
            
            if create_customer(email, password, name, phone):
                flask_session["customer_email"] = email
                return redirect(url_for("home"))
            else:
                return render_template("register.html", error="Email already exists.")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    @sentinel_monitor
    def login():
        g.event_type = "CUSTOMER_LOGIN"
        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")
            
            customer = get_customer(email)
            if customer and customer["password"] == password:
                if customer.get("blocked"):
                    return render_template("login.html", error="Account is suspended.")
                # Trigger OTP
                set_otp(email)
                return redirect(url_for("verify_otp_route", email=email))
            else:
                return render_template("login.html", error="Invalid credentials.")
        return render_template("login.html")
        
    @app.route("/verify_otp", methods=["GET", "POST"])
    @sentinel_monitor
    def verify_otp_route():
        g.event_type = "OTP_VERIFICATION"
        email = request.args.get("email")
        if request.method == "POST":
            email = request.form.get("email")
            code = request.form.get("code")
            if verify_otp(email, code):
                flask_session["customer_email"] = email
                return redirect(url_for("home"))
            else:
                return render_template("otp.html", email=email, error="Invalid or expired OTP.")
        
        # Display the OTP on screen (or print it) since it's a simulation
        code = OTP_CODES.get(email, {}).get("code")
        print(f"DEBUG: OTP for {email} is {code}")
        
        return render_template("otp.html", email=email, code=code)
        
    @app.route("/logout")
    def logout():
        flask_session.pop("customer_email", None)
        return redirect(url_for("home"))

    # --- Routes ---

    @app.route("/")
    @sentinel_monitor
    def home():
        g.event_type = "HOME_VIEW"
        return render_template("home.html")

    @app.route("/shop")
    @sentinel_monitor
    def shop():
        g.event_type = "SHOP_BROWSE"

        category = request.args.get("category")
        query = get_db().table("products").select("*").eq("is_active", True).order("name")

        if category:
            query = query.eq("category", category)

        products = query.execute().data or []

        categories_resp = (
            get_db()
            .table("products")
            .select("category")
            .eq("is_active", True)
            .execute()
        )
        categories = sorted(set(r["category"] for r in (categories_resp.data or [])))

        return render_template("shop.html", products=products, categories=categories, selected=category)

    @app.route("/product/<sku>")
    @sentinel_monitor
    def product_detail(sku):
        g.event_type = "PRODUCT_VIEW"

        resp = (
            get_db()
            .table("products")
            .select("*")
            .eq("sku", sku)
            .eq("is_active", True)
            .limit(1)
            .execute()
        )

        product = resp.data[0] if resp.data else None

        if not product:
            return "Product not found", 404

        g.telemetry_metadata = {
            "sku": sku,
            "product_name": product["name"],
            "price": float(product["price"]),
        }

        return render_template("product.html", product=product)

    @app.route("/cart/add", methods=["POST"])
    @sentinel_monitor
    def add_to_cart():
        g.event_type = "CART_ADD"

        sku = request.form.get("sku")
        quantity = int(request.form.get("quantity", 1))

        if not sku:
            return redirect(url_for("shop"))

        resp = (
            get_db()
            .table("products")
            .select("*")
            .eq("sku", sku)
            .limit(1)
            .execute()
        )

        product = resp.data[0] if resp.data else None

        if not product:
            return redirect(url_for("shop"))

        cart = get_cart()

        found = False
        for item in cart:
            if item["sku"] == sku:
                item["quantity"] += quantity
                found = True
                break

        if not found:
            cart.append({
                "sku": sku,
                "name": product["name"],
                "price": float(product["price"]),
                "quantity": quantity,
                "image_url": product.get("image_url"),
            })

        save_cart(cart)

        g.telemetry_metadata = {
            "sku": sku,
            "quantity_added": quantity,
            "total_items_in_cart": sum(i["quantity"] for i in cart),
        }

        return redirect(url_for("view_cart"))

    @app.route("/cart/update", methods=["POST"])
    @sentinel_monitor
    def update_cart():
        g.event_type = "CART_UPDATE"

        sku = request.form.get("sku")
        action = request.form.get("action")

        cart = get_cart()

        new_cart = []
        for item in cart:
            if item["sku"] == sku:
                if action == "remove":
                    continue
                elif action == "decrement":
                    item["quantity"] -= 1
                    if item["quantity"] > 0:
                        new_cart.append(item)
                elif action == "increment":
                    item["quantity"] += 1
                    new_cart.append(item)
                else:
                    new_cart.append(item)
            else:
                new_cart.append(item)

        save_cart(new_cart)
        return redirect(url_for("view_cart"))

    @app.route("/cart/remove", methods=["POST"])
    @sentinel_monitor
    def remove_from_cart():
        g.event_type = "CART_REMOVE"
        sku = request.form.get("sku")

        cart = [item for item in get_cart() if item["sku"] != sku]
        save_cart(cart)
        return redirect(url_for("view_cart"))

    @app.route("/cart")
    @sentinel_monitor
    def view_cart():
        g.event_type = "CART_VIEW"

        cart = get_cart()
        subtotal = sum(item["price"] * item["quantity"] for item in cart)
        delivery_charge = Config.DELIVERY_FEE if subtotal < Config.FREE_DELIVERY_THRESHOLD else 0
        total = subtotal + delivery_charge

        return render_template(
            "cart.html",
            cart=cart,
            subtotal=subtotal,
            delivery_charge=delivery_charge,
            total=total,
        )

    @app.route("/checkout", methods=["GET", "POST"])
    @sentinel_monitor
    def checkout():
        g.event_type = "CHECKOUT_PAGE"

        cart = get_cart()

        if not cart:
            return redirect(url_for("shop"))

        subtotal = sum(item["price"] * item["quantity"] for item in cart)
        delivery_charge = Config.DELIVERY_FEE if subtotal < Config.FREE_DELIVERY_THRESHOLD else 0
        total = subtotal + delivery_charge

        if request.method == "POST":
            g.event_type = "ORDER_PLACED"

            order_id = make_order_id()

            items_json = [{
                "sku": i["sku"],
                "name": i["name"],
                "quantity": i["quantity"],
                "unit_price": i["price"],
                "line_total": i["price"] * i["quantity"],
            } for i in cart]

            created_at_str = flask_session.get("_created_at")
            if created_at_str:
                session_age_seconds = (datetime.now(timezone.utc) - datetime.fromisoformat(created_at_str)).total_seconds()
            else:
                session_age_seconds = 0

            g.telemetry_metadata = {
                "order_value": total,
                "item_count": len(items_json),
                "order_id": order_id,
                "items_exceed_stock": any(
                    item["quantity"] > 50 for item in items_json
                ),
                "single_sku_order": len(set(i["sku"] for i in items_json)) == 1,
                "session_age_seconds": int(session_age_seconds),
                "prior_items_in_cart": len(cart),
            }

            payment_method = request.form.get("payment_method", "online")
            state = request.form.get("state", "")

            # Payment Simulation
            card_number = request.form.get("card_number")
            if payment_method == "online":
                # Simulated payment failure conditions
                # If card number starts with 4000, we simulate failure
                if card_number and card_number.startswith("4000"):
                    # Record payment failure
                    is_anomaly = evaluate_payment_failure(
                        request.form.get("email"), 
                        request.headers.get("X-Forwarded-For", request.remote_addr)
                    )
                    
                    if is_anomaly:
                        customer = get_customer(request.form.get("email"))
                        if customer:
                            customer["blocked"] = True
                        return render_template("checkout.html", cart=cart, subtotal=subtotal, delivery_charge=delivery_charge, total=total, error="Payment failed. Account suspended due to suspicious activity.")
                    
                    return render_template("checkout.html", cart=cart, subtotal=subtotal, delivery_charge=delivery_charge, total=total, error="Payment failed. Please check your card details.")
                else:
                    # Payment Success
                    reset_payment_status(request.headers.get("X-Forwarded-For", request.remote_addr))


            order_record = {
                "order_id": order_id,
                "customer_name": request.form.get("name"),
                "phone": request.form.get("phone"),
                "email": request.form.get("email"),

                "address": request.form.get("address"),
                "city": request.form.get("city"),
                "state": state,
                "pincode": request.form.get("pincode"),

                "items": items_json,
                "total_value": total,

                "payment_method": payment_method,
                "payment_status": "pending" if payment_method == "cod" else "paid_demo",

                "status": "pending",
                "source": "boltmart",
                "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr),
                "session_id": flask_session.get("sid"),
            }

            get_db().table("orders").insert(order_record).execute()

            threading.Thread(
                target=_send_notification,
                args=(order_record,),
                daemon=True
            ).start()

            save_cart([])

            return redirect(url_for("order_confirmation", order_id=order_id))

        return render_template(
            "checkout.html",
            cart=cart,
            subtotal=subtotal,
            delivery_charge=delivery_charge,
            total=total,
        )

    @app.route("/confirmation/<order_id>")
    @sentinel_monitor
    def order_confirmation(order_id):
        g.event_type = "ORDER_CONFIRMATION_VIEW"

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
        if order.get("payment_method") != "cod":
            order["transaction_id"] = order.get("transaction_id") or f"TXN-{order_id[-12:]}"

        return render_template("confirmation.html", order=order, tracking_mode=False)

    @app.route("/track/<order_id>")
    @sentinel_monitor
    def track_order(order_id):
        g.event_type = "ORDER_TRACKING"

        g.telemetry_metadata = {"order_id_queried": order_id}

        resp = (
            get_db()
            .table("orders")
            .select("*")
            .eq("order_id", order_id)
            .limit(1)
            .execute()
        )

        order = resp.data[0] if resp.data else None

        if order:
            if isinstance(order.get("items"), str):
                order["items"] = json.loads(order["items"])
            elif not isinstance(order.get("items"), list):
                order["items"] = []
            if order.get("payment_method") != "cod":
                order["transaction_id"] = order.get("transaction_id") or f"TXN-{order_id[-12:]}"

        return render_template("confirmation.html", order=order, tracking_mode=True)

    @app.route("/invoice/<order_id>")
    def download_invoice(order_id):
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

        if order.get("payment_method") != "cod":
            order["transaction_id"] = order.get("transaction_id") or f"TXN-{order_id[-12:]}"
        if isinstance(order.get("items"), str):
            order["items"] = json.loads(order["items"])

        pdf_bytes = generate_invoice(order)
        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f'attachment; filename="invoice-{order_id[:12]}.pdf"'
        return response

    @app.route("/track", methods=["GET", "POST"])
    def track_search():
        if request.method == "POST":
            order_id = request.form.get("order_id")
            if order_id:
                return redirect(url_for("track_order", order_id=order_id))

        return render_template("home.html", show_track_search=True)

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "boltmart"}), 200

    @app.route("/.env")
    @app.route("/admin")
    @app.route("/api/v1/users")
    @sentinel_monitor
    def honeypot_probe():
        g.event_type = "HONEYPOT_PROBE"
        g.telemetry_metadata = {
            "honeypot_route": request.path,
            "reason": "Hidden route accessed by client",
            "attack_hint": "scanner_or_recon_bot",
        }

        return render_template(
            "403.html",
            ip=request.headers.get("X-Forwarded-For", request.remote_addr),
            reason=f"Access to protected route {request.path} is not allowed.",
            severity="critical",
            incident_id=None,
            until=None,
        ), 403

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5001, debug=True)
