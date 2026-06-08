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
from boltmart.notifier import send_order_notification, send_welcome_email, send_otp_email, send_order_status_email
from shared.db_client import get_supabase
from werkzeug.security import check_password_hash, generate_password_hash
from boltmart.db_users import create_customer, get_customer, set_otp, verify_otp, get_otp, set_reset_code, verify_reset_code
import razorpay




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

    def get_wishlist():
        generate_session_id()
        return flask_session.get("wishlist", [])

    def save_wishlist(wl):
        flask_session["wishlist"] = wl

    def track_recently_viewed(sku, name, price, image_url=None):
        recent = flask_session.get("recently_viewed", [])
        recent = [r for r in recent if r["sku"] != sku]
        recent.insert(0, {"sku": sku, "name": name, "price": price, "image_url": image_url})
        flask_session["recently_viewed"] = recent[:8]

    def get_recently_viewed():
        return flask_session.get("recently_viewed", [])

    def make_order_id():
        date_part = datetime.now().strftime("%Y%m%d")
        random_part = uuid4().hex[:6].upper()
        return f"ORD-{date_part}-{random_part}"

    def get_db():
        return get_supabase()

    def validate_coupon(code, subtotal):
        try:
            resp = get_db().table("coupons").select("*").eq("code", code.strip().upper()).limit(1).execute()
            if not resp.data:
                return None, "Invalid coupon code"
            coupon = resp.data[0]
            if not coupon.get("is_active"):
                return None, "Coupon is expired or deactivated"
            if coupon.get("used_count", 0) >= coupon.get("max_uses", 100):
                return None, "Coupon usage limit reached"
            if subtotal < (coupon.get("min_order_value") or 0):
                return None, f"Minimum order value of Rs {coupon['min_order_value']:.0f} required"
            if coupon["discount_type"] == "percentage":
                discount = round(subtotal * coupon["discount_value"] / 100, 2)
            else:
                discount = min(coupon["discount_value"], subtotal)
            return coupon, discount
        except Exception:
            return None, None

    def _send_notification(order_record):
        try:
            order_record = dict(order_record)
            pdf = generate_invoice(order_record)
            send_order_notification(order_record, pdf)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning("Notification failed for order %s: %s", order_record.get("order_id"), e)

    def create_notification(email, ntype, title, message, link=None):
        try:
            get_db().table("notifications").insert({
                "email": email, "type": ntype,
                "title": title, "message": message, "link": link
            }).execute()
        except Exception:
            pass

    def send_inapp_notifications(order):
        email = order.get("email")
        oid = order.get("order_id", "")
        if not email:
            return
        create_notification(email, "order", "Order Placed",
            f"Your order {oid} has been placed successfully.", f"/confirmation/{oid}")

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
        g.unread_count = 0
        if "customer_email" in flask_session:
            g.customer = get_customer(flask_session["customer_email"])
            if g.customer:
                g.unread_count = get_unread_count(flask_session["customer_email"])

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
            
            if not email.lower().endswith("@gmail.com"):
                return render_template("register.html", error="Only @gmail.com addresses are allowed.")
            if create_customer(email, password, name, phone):
                otp_code = set_otp(email)
                threading.Thread(
                    target=send_welcome_email,
                    args=({"email": email, "name": name, "phone": phone},),
                    daemon=True
                ).start()
                threading.Thread(
                    target=send_otp_email,
                    args=(email, otp_code),
                    daemon=True
                ).start()
                return redirect(url_for("verify_otp_route", email=email))
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
            if customer and check_password_hash(customer["password"], password):
                if customer.get("blocked"):
                    return render_template("login.html", error="Account is suspended.")
                # Trigger OTP and send via email
                otp_code = set_otp(email)
                threading.Thread(
                    target=send_otp_email,
                    args=(email, otp_code),
                    daemon=True
                ).start()
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
        
        # OTP has been sent via email — no on-screen display
        return render_template("otp.html", email=email)
        
    @app.route("/forgot-password", methods=["GET", "POST"])
    @sentinel_monitor
    def forgot_password():
        g.event_type = "FORGOT_PASSWORD"
        if request.method == "POST":
            email = request.form.get("email")
            customer = get_customer(email)
            if customer:
                code = set_reset_code(email)
                threading.Thread(
                    target=send_otp_email,
                    args=(email, code),
                    daemon=True
                ).start()
            return render_template("forgot_password.html", sent=True)
        return render_template("forgot_password.html")

    @app.route("/reset-password", methods=["GET", "POST"])
    @sentinel_monitor
    def reset_password():
        g.event_type = "RESET_PASSWORD"
        if request.method == "POST":
            email = request.form.get("email")
            code = request.form.get("code")
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")

            if new_password != confirm_password:
                return render_template("reset_password.html", email=email, error="Passwords do not match.")
            if len(new_password) < 6:
                return render_template("reset_password.html", email=email, error="Password must be at least 6 characters.")

            if verify_reset_code(email, code):
                hashed = generate_password_hash(new_password)
                get_db().table("customers").update({"password": hashed}).eq("email", email).execute()
                return redirect(url_for("login"))
            else:
                return render_template("reset_password.html", email=email, error="Invalid or expired reset code.")

        email = request.args.get("email")
        return render_template("reset_password.html", email=email)

    @app.route("/logout")
    def logout():
        flask_session.pop("customer_email", None)
        return redirect(url_for("home"))

    # --- Routes ---

    @app.route("/")
    @sentinel_monitor
    def home():
        g.event_type = "HOME_VIEW"
        return render_template("home.html", recently_viewed=get_recently_viewed())

    @app.route("/shop")
    @sentinel_monitor
    def shop():
        g.event_type = "SHOP_BROWSE"

        category = request.args.get("category")
        search_query = request.args.get("q", "").strip()
        min_price = request.args.get("min_price", type=float)
        max_price = request.args.get("max_price", type=float)

        query = get_db().table("products").select("*").eq("is_active", True).order("name")

        if category:
            query = query.eq("category", category)
        if min_price is not None:
            query = query.gte("price", min_price)
        if max_price is not None:
            query = query.lte("price", max_price)

        products = query.execute().data or []

        # Client-side search filter (Supabase free tier doesn't have full-text search)
        if search_query:
            search_lower = search_query.lower()
            products = [
                p for p in products
                if search_lower in p.get("name", "").lower()
                or search_lower in p.get("description", "").lower()
                or search_lower in p.get("category", "").lower()
                or search_lower in p.get("sku", "").lower()
            ]

        categories_resp = (
            get_db()
            .table("products")
            .select("category")
            .eq("is_active", True)
            .execute()
        )
        categories = sorted(set(r["category"] for r in (categories_resp.data or [])))

        # Aggregate ratings per product
        product_ratings = {}
        try:
            reviews_resp = get_db().table("reviews").select("sku, rating").execute()
            rating_map = {}
            for r in (reviews_resp.data or []):
                sku = r["sku"]
                if sku not in rating_map:
                    rating_map[sku] = []
                rating_map[sku].append(r["rating"])
            product_ratings = {
                sku: round(sum(vals) / len(vals), 1) for sku, vals in rating_map.items()
            }
        except Exception:
            pass

        return render_template(
            "shop.html",
            products=products,
            categories=categories,
            selected=category,
            search_query=search_query,
            min_price=min_price,
            max_price=max_price,
            product_ratings=product_ratings,
        )

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

        reviews = []
        avg_rating = None
        try:
            reviews_resp = get_db().table("reviews").select("*").eq("sku", sku).order("created_at", desc=True).execute()
            reviews = reviews_resp.data or []
            avg_rating = round(sum(r["rating"] for r in reviews) / len(reviews), 1) if reviews else None
        except Exception:
            pass

        track_recently_viewed(sku, product["name"], float(product["price"]), product.get("image_url"))

        g.telemetry_metadata = {
            "sku": sku,
            "product_name": product["name"],
            "price": float(product["price"]),
        }

        return render_template("product.html", product=product, reviews=reviews, avg_rating=avg_rating)

    @app.route("/product/<sku>/review", methods=["POST"])
    @sentinel_monitor
    def submit_review(sku):
        g.event_type = "REVIEW_SUBMIT"
        if not g.customer:
            return redirect(url_for("login"))

        rating = int(request.form.get("rating", 5))
        title = request.form.get("title", "")
        comment = request.form.get("comment", "")
        email = flask_session["customer_email"]

        existing = get_db().table("reviews").select("*").eq("sku", sku).eq("email", email).execute()
        if existing.data:
            get_db().table("reviews").update({
                "rating": rating, "title": title, "comment": comment,
                "customer_name": g.customer["name"]
            }).eq("id", existing.data[0]["id"]).execute()
        else:
            get_db().table("reviews").insert({
                "sku": sku, "email": email, "customer_name": g.customer["name"],
                "rating": rating, "title": title, "comment": comment
            }).execute()

        return redirect(url_for("product_detail", sku=sku))

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

    @app.route("/wishlist/add/<sku>", methods=["POST"])
    @sentinel_monitor
    def add_to_wishlist(sku):
        g.event_type = "WISHLIST_ADD"
        resp = get_db().table("products").select("*").eq("sku", sku).limit(1).execute()
        product = resp.data[0] if resp.data else None
        if not product:
            return redirect(url_for("shop"))

        wl = get_wishlist()
        if not any(item["sku"] == sku for item in wl):
            wl.append({
                "sku": sku,
                "name": product["name"],
                "price": float(product["price"]),
                "image_url": product.get("image_url"),
            })
        save_wishlist(wl)
        return redirect(request.referrer or url_for("view_wishlist"))

    @app.route("/wishlist/remove/<sku>", methods=["POST"])
    @sentinel_monitor
    def remove_from_wishlist(sku):
        g.event_type = "WISHLIST_REMOVE"
        wl = [item for item in get_wishlist() if item["sku"] != sku]
        save_wishlist(wl)
        return redirect(request.referrer or url_for("view_wishlist"))

    @app.route("/wishlist")
    @sentinel_monitor
    def view_wishlist():
        g.event_type = "WISHLIST_VIEW"
        wl = get_wishlist()
        return render_template("wishlist.html", wishlist=wl)

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

        saved_addresses = []
        if g.customer:
            try:
                addr_resp = get_db().table("addresses").select("*").eq("email", flask_session["customer_email"]).order("created_at", desc=True).execute()
                saved_addresses = addr_resp.data or []
            except Exception:
                pass

        coupon_code = flask_session.get("coupon_code")
        coupon_discount = flask_session.get("coupon_discount", 0)
        coupon_error = None

        if request.method == "POST":
            action = request.form.get("action")

            if action == "apply_coupon":
                code = request.form.get("coupon_code", "").strip()
                if code:
                    coupon, discount = validate_coupon(code, subtotal)
                    if coupon:
                        flask_session["coupon_code"] = code.upper()
                        flask_session["coupon_discount"] = discount
                        coupon_code = code.upper()
                        coupon_discount = discount
                    else:
                        coupon_error = discount or "Invalid coupon"
                        flask_session.pop("coupon_code", None)
                        flask_session.pop("coupon_discount", None)
                return render_template(
                    "checkout.html",
                    cart=cart, subtotal=subtotal,
                    delivery_charge=delivery_charge,
                    total=subtotal + delivery_charge - (coupon_discount if coupon_code else 0),
                    saved_addresses=saved_addresses,
                    coupon_code=coupon_code,
                    coupon_discount=coupon_discount,
                    coupon_error=coupon_error,
                )

            if not g.customer:
                return redirect(url_for("login"))

            total = subtotal + delivery_charge - (coupon_discount if coupon_code else 0)

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

            order_record = {
                "order_id": order_id,
                "customer_name": request.form.get("name"),
                "phone": request.form.get("phone"),
                "email": flask_session.get("customer_email"),

                "address": request.form.get("address"),
                "city": request.form.get("city"),
                "state": state,
                "pincode": request.form.get("pincode"),

                "items": items_json,
                "total_value": total,

                "payment_method": payment_method,
                "payment_status": "pending",

                "status": "pending",
                "source": "boltmart",
                "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr),
                "session_id": flask_session.get("sid"),
            }

            get_db().table("orders").insert(order_record).execute()

            threading.Thread(target=send_inapp_notifications, args=(order_record,), daemon=True).start()

            if payment_method in ("cod", "wallet"):
                threading.Thread(
                    target=_send_notification,
                    args=(order_record,),
                    daemon=True
                ).start()
                return redirect(url_for("order_confirmation", order_id=order_id))

            return redirect(url_for("payment_page", order_id=order_id))

        return render_template(
            "checkout.html",
            cart=cart,
            subtotal=subtotal,
            delivery_charge=delivery_charge,
            total=subtotal + delivery_charge - (coupon_discount if coupon_code else 0),
            saved_addresses=saved_addresses,
            coupon_code=coupon_code,
            coupon_discount=coupon_discount,
            coupon_error=coupon_error,
        )

    # --- Razorpay Payment ---

    @app.route("/pay/<order_id>")
    @sentinel_monitor
    def payment_page(order_id):
        g.event_type = "PAYMENT_PAGE"
        resp = get_db().table("orders").select("*").eq("order_id", order_id).limit(1).execute()
        order = resp.data[0] if resp.data else None
        if not order:
            return "Order not found", 404

        if order["payment_method"] in ("cod", "wallet"):
            return redirect(url_for("order_confirmation", order_id=order_id))

        if not Config.RAZORPAY_KEY_ID or not Config.RAZORPAY_KEY_SECRET:
            return render_template("payment.html", order=order, razorpay_key=None, razorpay_order_id=None,
                                   error="Payment gateway not configured. Contact support.")

        client = razorpay.Client(auth=(Config.RAZORPAY_KEY_ID, Config.RAZORPAY_KEY_SECRET))
        razorpay_order = client.order.create({
            "amount": int(order["total_value"] * 100),
            "currency": "INR",
            "receipt": order_id,
            "payment_capture": 1,
        })

        get_db().table("orders").update({"razorpay_order_id": razorpay_order["id"]}).eq("order_id", order_id).execute()

        return render_template("payment.html", order=order, razorpay_key=Config.RAZORPAY_KEY_ID,
                               razorpay_order_id=razorpay_order["id"],
                               callback_url=url_for("payment_callback", order_id=order_id, _external=True))

    @app.route("/pay/<order_id>/callback", methods=["POST"])
    @sentinel_monitor
    def payment_callback(order_id):
        g.event_type = "PAYMENT_CALLBACK"
        resp = get_db().table("orders").select("*").eq("order_id", order_id).limit(1).execute()
        order = resp.data[0] if resp.data else None
        if not order:
            return "Order not found", 404

        razorpay_payment_id = request.form.get("razorpay_payment_id")
        razorpay_order_id = request.form.get("razorpay_order_id")
        razorpay_signature = request.form.get("razorpay_signature")

        if razorpay_payment_id and razorpay_order_id and razorpay_signature:
            try:
                client = razorpay.Client(auth=(Config.RAZORPAY_KEY_ID, Config.RAZORPAY_KEY_SECRET))
                params = {
                    "razorpay_order_id": razorpay_order_id,
                    "razorpay_payment_id": razorpay_payment_id,
                    "razorpay_signature": razorpay_signature,
                }
                client.utility.verify_payment_signature(params)
                get_db().table("orders").update({
                    "payment_status": "paid",
                    "razorpay_payment_id": razorpay_payment_id,
                    "status": "confirmed",
                }).eq("order_id", order_id).execute()
                create_notification(order["email"], "order", "Payment Successful",
                    f"Payment of Rs {order['total_value']:.0f} confirmed for order {order_id}.", f"/confirmation/{order_id}")
                # Send invoice email now that payment is confirmed
                updated = get_db().table("orders").select("*").eq("order_id", order_id).limit(1).execute()
                if updated.data:
                    threading.Thread(target=_send_notification, args=(updated.data[0],), daemon=True).start()
            except Exception:
                get_db().table("orders").update({"payment_status": "failed"}).eq("order_id", order_id).execute()

        return redirect(url_for("order_confirmation", order_id=order_id))

    # --- Razorpay Webhook ---

    @app.route("/api/razorpay/webhook", methods=["POST"])
    def razorpay_webhook():
        payload = request.get_data(as_text=True)
        sig = request.headers.get("X-Razorpay-Signature", "")

        try:
            client = razorpay.Client(auth=(Config.RAZORPAY_KEY_ID, Config.RAZORPAY_KEY_SECRET))
            client.utility.verify_webhook_signature(payload, sig, Config.RAZORPAY_KEY_SECRET)
            event = request.json.get("event", "")
            if event == "payment.captured":
                order_id = request.json["payload"]["payment"]["entity"]["receipt"]
                payment_id = request.json["payload"]["payment"]["entity"]["id"]
                get_db().table("orders").update({
                    "payment_status": "paid",
                    "razorpay_payment_id": payment_id,
                    "status": "confirmed",
                }).eq("order_id", order_id).execute()
        except Exception:
            pass
        return jsonify({"status": "ok"}), 200

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

    # --- My Orders ---

    @app.route("/my-orders")
    @sentinel_monitor
    def my_orders():
        g.event_type = "MY_ORDERS_VIEW"

        if not g.customer:
            return redirect(url_for("login"))

        email = flask_session.get("customer_email")
        resp = (
            get_db()
            .table("orders")
            .select("*")
            .eq("email", email)
            .order("created_at", desc=True)
            .execute()
        )
        orders = resp.data or []

        for order in orders:
            raw_items = order.get("items", [])
            if isinstance(raw_items, str):
                raw_items = json.loads(raw_items)
            elif not isinstance(raw_items, list):
                raw_items = []
            order["order_items"] = raw_items

        return render_template("my_orders.html", orders=orders)

    # --- Cancel Order ---

    @app.route("/cancel-order/<order_id>", methods=["POST"])
    @sentinel_monitor
    def cancel_order(order_id):
        g.event_type = "ORDER_CANCEL"

        if not g.customer:
            return redirect(url_for("login"))

        email = flask_session.get("customer_email")
        resp = (
            get_db()
            .table("orders")
            .select("*")
            .eq("order_id", order_id)
            .eq("email", email)
            .limit(1)
            .execute()
        )
        order = resp.data[0] if resp.data else None

        if not order:
            return "Order not found", 404

        if order.get("status") in ("pending", "confirmed"):
            get_db().table("orders").update({"status": "cancelled"}).eq("order_id", order_id).execute()
            # Send cancellation email
            threading.Thread(
                target=send_order_status_email,
                args=(order, "cancelled"),
                daemon=True
            ).start()
            create_notification(email, "order", "Order Cancelled",
                f"Order {order_id} has been cancelled.", f"/my-orders")

        return redirect(url_for("my_orders"))

    # --- Return / Replace ---

    @app.route("/return-request/<order_id>", methods=["GET", "POST"])
    @sentinel_monitor
    def return_request(order_id):
        g.event_type = "RETURN_REQUEST"
        if not g.customer:
            return redirect(url_for("login"))

        email = flask_session["customer_email"]
        resp = get_db().table("orders").select("*").eq("order_id", order_id).eq("email", email).limit(1).execute()
        order = resp.data[0] if resp.data else None
        if not order:
            return "Order not found", 404

        if isinstance(order.get("items"), str):
            order["items"] = json.loads(order["items"])
        elif not isinstance(order.get("items"), list):
            order["items"] = []

        if request.method == "POST":
            rtype = request.form.get("type")
            reason = request.form.get("reason", "").strip()
            selected_skus = request.form.getlist("items")

            if not reason or not selected_skus:
                return render_template("return_form.html", order=order, error="Please select items and provide a reason.")

            items = [i for i in order["items"] if i["sku"] in selected_skus]

            get_db().table("return_requests").insert({
                "order_id": order_id, "email": email,
                "items": items, "reason": reason,
                "type": rtype, "status": "pending",
            }).execute()

            create_notification(email, "order", f"Return/{rtype.capitalize()} Requested",
                f"{rtype.capitalize()} request for order {order_id} is pending review.", f"/my-orders")
            return redirect(url_for("my_orders"))

        return render_template("return_form.html", order=order)

    @app.route("/my-returns")
    @sentinel_monitor
    def my_returns():
        g.event_type = "MY_RETURNS_VIEW"
        if not g.customer:
            return redirect(url_for("login"))

        email = flask_session["customer_email"]
        returns = []
        try:
            resp = get_db().table("return_requests").select("*").eq("email", email).order("created_at", desc=True).execute()
            returns = resp.data or []
            for r in returns:
                if isinstance(r.get("items"), str):
                    r["items"] = json.loads(r["items"])
        except Exception:
            pass
        return render_template("my_returns.html", returns=returns)

    # --- Addresses ---

    @app.route("/addresses")
    @sentinel_monitor
    def manage_addresses():
        g.event_type = "ADDRESSES_VIEW"
        if not g.customer:
            return redirect(url_for("login"))
        email = flask_session["customer_email"]
        addresses = []
        try:
            resp = get_db().table("addresses").select("*").eq("email", email).order("created_at", desc=True).execute()
            addresses = resp.data or []
        except Exception:
            pass
        return render_template("addresses.html", addresses=addresses)

    @app.route("/addresses/add", methods=["POST"])
    @sentinel_monitor
    def add_address():
        g.event_type = "ADDRESS_ADD"
        if not g.customer:
            return redirect(url_for("login"))
        email = flask_session["customer_email"]
        data = {
            "email": email,
            "label": request.form.get("label", "Home"),
            "name": request.form.get("name"),
            "phone": request.form.get("phone"),
            "address_line": request.form.get("address_line"),
            "city": request.form.get("city"),
            "state": request.form.get("state"),
            "pincode": request.form.get("pincode"),
            "is_default": request.form.get("is_default") == "on",
        }
        try:
            if data["is_default"]:
                get_db().table("addresses").update({"is_default": False}).eq("email", email).execute()
            get_db().table("addresses").insert(data).execute()
        except Exception:
            pass
        return redirect(url_for("manage_addresses"))

    @app.route("/addresses/delete/<int:addr_id>", methods=["POST"])
    @sentinel_monitor
    def delete_address(addr_id):
        g.event_type = "ADDRESS_DELETE"
        if not g.customer:
            return redirect(url_for("login"))
        get_db().table("addresses").delete().eq("id", addr_id).eq("email", flask_session["customer_email"]).execute()
        return redirect(url_for("manage_addresses"))

    # --- Notifications ---

    def get_unread_count(email):
        try:
            resp = get_db().table("notifications").select("id", count="exact").eq("email", email).eq("is_read", False).execute()
            return resp.count or 0
        except Exception:
            return 0

    @app.route("/notifications")
    @sentinel_monitor
    def notifications():
        g.event_type = "NOTIFICATIONS_VIEW"
        if not g.customer:
            return redirect(url_for("login"))
        email = flask_session["customer_email"]
        notifs = []
        try:
            resp = get_db().table("notifications").select("*").eq("email", email).order("created_at", desc=True).limit(50).execute()
            notifs = resp.data or []
        except Exception:
            pass
        return render_template("notifications.html", notifications=notifs)

    @app.route("/notifications/read", methods=["POST"])
    @sentinel_monitor
    def mark_notifications_read():
        g.event_type = "NOTIFICATIONS_READ"
        if not g.customer:
            return redirect(url_for("login"))
        try:
            get_db().table("notifications").update({"is_read": True}).eq("email", flask_session["customer_email"]).eq("is_read", False).execute()
        except Exception:
            pass
        return redirect(url_for("notifications"))

    # --- Profile ---

    @app.route("/profile", methods=["GET", "POST"])
    @sentinel_monitor
    def profile():
        g.event_type = "PROFILE_VIEW"

        if not g.customer:
            return redirect(url_for("login"))

        customer = g.customer
        message = None

        if request.method == "POST":
            action = request.form.get("action")
            if action == "update_profile":
                name = request.form.get("name", customer["name"])
                phone = request.form.get("phone", customer["phone"])
                get_db().table("customers").update({"name": name, "phone": phone}).eq("email", flask_session.get("customer_email")).execute()
                customer["name"] = name
                customer["phone"] = phone
                message = "Profile updated successfully!"
            elif action == "change_password":
                current_pw = request.form.get("current_password")
                new_pw = request.form.get("new_password")
                confirm_pw = request.form.get("confirm_password")
                if not check_password_hash(customer["password"], current_pw):
                    message = "Current password is incorrect."
                elif new_pw != confirm_pw:
                    message = "New passwords do not match."
                elif len(new_pw) < 6:
                    message = "Password must be at least 6 characters."
                else:
                    hashed = generate_password_hash(new_pw)
                    get_db().table("customers").update({"password": hashed}).eq("email", flask_session.get("customer_email")).execute()
                    customer["password"] = hashed
                    message = "Password changed successfully!"

        # Count orders for this customer
        email = flask_session.get("customer_email")
        order_resp = get_db().table("orders").select("order_id").eq("email", email).execute()
        order_count = len(order_resp.data or [])

        return render_template("profile.html", customer=customer, message=message, order_count=order_count)

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
