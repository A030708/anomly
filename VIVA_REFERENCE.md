# ANOMALY PLATFORM — Complete Project Reference for Viva

---

## 1. PROJECT OVERVIEW

A **modular monolith** with 3 Flask web applications sharing a single **Supabase (PostgreSQL)** database:

| Module | Port | Purpose |
|---|---|---|
| **BoltMart** | `:5001` | E-commerce marketplace (customers browse, cart, checkout, pay) |
| **Warehouse OS** | `:5002` | Warehouse management (inventory, PO, fulfillment, suppliers) |
| **Sentinel XDR** | `:5003` | Security Operations Center (event ingestion, ML detection, incident response) |

**Communication flow:**
- BoltMart & Warehouse OS send every HTTP request as a telemetry event to Sentinel XDR (via REST)
- Sentinel XDR sends defense actions (IP blocks) back to BoltMart & Warehouse OS via **signed webhooks** (`/api/defense_webhook`)

---

## 2. TECH STACK

| Layer | Technology |
|---|---|
| **Language** | Python 3.11+ |
| **Web Framework** | Flask 3.0 (with blueprints) |
| **Database** | Supabase (PostgreSQL) |
| **Session** | Flask-Session (server-side, Redis-backed) |
| **Templates** | Jinja2 HTML |
| **Payments** | Razorpay |
| **Machine Learning** | scikit-learn (Isolation Forest, One-Class SVM) |
| **LLM** | Groq (LLaMA 3.1) — analyzes incidents |
| **PDF** | ReportLab — invoice generation |
| **Email** | SMTP (custom notifier) |
| **Auth** | bcrypt (password hashing) |
| **Background Jobs** | RQ (Redis Queue) |
| **Async** | Eventlet (for WebSocket) |
| **WebSocket** | Flask-SocketIO |
| **CI** | GitHub Actions |

---

## 3. PROJECT STRUCTURE — ALL FILES BY MODULE

```
C:\proj\
├── .env                        # Environment variables (secrets)
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── render.yaml                 # Render.com deployment config
├── requirements.txt            # Python dependencies (21 packages)
├── pytest.ini                  # Pytest configuration
├── README.md
├── setup_db.py                 # SQL schema + verification
├── cleanup_db.py               # Cleanup script
├── start_bm.py / start_wos.py  # Start scripts
│
├── shared/                     # ─── SHARED LIBRARY ───
│   ├── __init__.py
│   ├── constants.py            # Attack types, event types, severity, thresholds, products, demo users
│   └── db_client.py            # get_supabase() — lru_cache singleton, insert_row/update_rows/select_rows
│
├── boltmart/                   # ─── BOLTMART (E-COMMERCE) ───
│   ├── app.py                  # Main Flask app (1278 lines) — ALL routes
│   ├── config.py               # Config class (supabase, sentinel, razorpay, smtp, delivery fee)
│   ├── db_users.py             # DB operations: create_customer, get_customer, OTP, reset codes, payment failures
│   ├── sentinel.py             # Sentinel middleware: sentinel_monitor decorator, IP block check, defense webhook
│   ├── anomaly.py              # evaluate_payment_failure() — flags 3+ failed payments, alerts Sentinel
│   ├── anomaly_catalog.py
│   ├── invoice.py              # generate_invoice() — ReportLab PDF with items table, billing, totals
│   ├── notifier.py             # Email functions: welcome, OTP, order confirmation (with PDF), fraud alerts, etc.
│   ├── seed.py                 # Database seed data
│   ├── static/
│   │   ├── css/style.css
│   │   └── images/products/    # 14 product images
│   └── templates/              # 19 Jinja2 HTML files
│       ├── base.html           # Layout template (navbar, footer, notifications)
│       ├── home.html           # Landing page
│       ├── shop.html           # Product catalog
│       ├── product.html        # Single product detail
│       ├── cart.html           # Shopping cart
│       ├── wishlist.html       # Wishlist
│       ├── checkout.html       # Checkout form (address, payment method, coupon)
│       ├── payment.html        # Razorpay payment page
│       ├── confirmation.html   # Order success page
│       ├── login.html / register.html / otp.html
│       ├── forgot_password.html / reset_password.html
│       ├── profile.html / addresses.html
│       ├── my_orders.html
│       ├── notifications.html
│       └── 403.html            # Blocked IP page
│
├── warehouse_os/               # ─── WAREHOUSE OS ───
│   ├── app.py                  # Main Flask app (~1800 lines, single file, no blueprints)
│   ├── config.py
│   ├── sentinel.py             # Same pattern as boltmart/sentinel.py
│   ├── categories_store.json   # Product categories
│   ├── config_store.json       # Warehouse settings
│   ├── static/css/style.css
│   └── templates/              # 27 Jinja2 HTML files
│       ├── base.html
│       ├── dashboard.html
│       ├── inventory.html
│       ├── stock_in.html       # Stock receiving
│       ├── fulfillment.html    # Order fulfillment
│       ├── delivery.html       # Delivery tracking
│       ├── returns.html        # Returns & replacements
│       ├── purchase_orders.html / po_form.html / po_detail.html / po_discrepancies.html
│       ├── suppliers.html / supplier_form.html
│       ├── movements.html      # Inventory movements
│       ├── writeoff.html       # Inventory write-offs
│       ├── export.html         # CSV export
│       ├── audit.html          # Audit log
│       ├── admin.html          # Admin panel
│       ├── coupons.html        # Coupon management
│       ├── categories.html
│       ├── setup_purchasing.html / simulation.html
│       ├── user_form.html / change_password.html
│       └── 403.html
│
├── sentinel_xdr/               # ─── SENTINEL XDR (SECURITY) ───
│   ├── app.py                  # Flask app — registers 18 blueprints, /api/ingest endpoint
│   ├── config.py
│   ├── database.py             # All Supabase queries (events, alerts, incidents, etc.)
│   ├── detection_rules.py      # 15 detection rules (brute force, scraping, enumeration, etc.)
│   ├── anomaly_detector.py     # scikit-learn Isolation Forest + One-Class SVM (23-feature vector)
│   ├── llm_analyzer.py         # Groq (LLaMA 3.1) — analyzes incidents
│   ├── active_response.py      # Signed webhook dispatch: BLOCK_IP, REVOKE_SESSION, etc.
│   ├── message_queue.py        # In-memory event queue (thread-safe)
│   ├── worker.py               # Background event processing thread
│   ├── notifier.py
│   ├── feedback.py / feedback_store.json
│   ├── log_collector.py
│   ├── settings_store.json
│   ├── models/                 # Pre-trained ML models (.pkl files)
│   │   ├── isolation_forest.pkl
│   │   └── scaler.pkl
│   ├── blueprints/             # 20 route blueprints
│   │   ├── auth.py             # Login/logout
│   │   ├── dashboard.py        # Summary stats, charts
│   │   ├── events.py           # Event viewer, CSV export
│   │   ├── alerts.py           # Alert list/detail
│   │   ├── incidents.py        # Incident management
│   │   ├── cases.py            # Case management
│   │   ├── playbooks.py        # Automated playbooks
│   │   ├── audit.py            # Audit log
│   │   ├── network.py          # Network traffic analysis
│   │   ├── assets.py           # Asset inventory
│   │   ├── vulnerabilities.py  # Vulnerability tracking
│   │   ├── threat_intel.py     # Threat intelligence (IoC management)
│   │   ├── mitre.py            # MITRE ATT&CK mapping
│   │   ├── hunt.py             # Threat hunting
│   │   ├── forensics.py        # Forensics viewer
│   │   ├── compliance.py       # Compliance reporting
│   │   ├── reports.py          # Report generation
│   │   ├── settings.py         # System settings
│   │   ├── admin.py            # Admin panel
│   │   └── __init__.py
│   └── templates/              # 20+ Jinja2 templates organized by blueprint folder
│       ├── base.html / login.html
│       ├── dashboard/index.html
│       ├── events/list.html
│       ├── alerts/list.html / detail.html
│       ├── incidents/list.html / detail.html
│       ├── cases/list.html / detail.html
│       ├── playbooks/list.html / detail.html
│       ├── mitre/map.html
│       ├── network/map.html
│       ├── threat_intel/list.html / detail.html
│       ├── vulnerabilities/list.html
│       ├── assets/list.html
│       ├── hunt/hunting.html
│       ├── forensics/view.html
│       ├── compliance/view.html
│       ├── audit/log.html
│       ├── reports/list.html
│       ├── settings/view.html
│       └── admin/panel.html
│
├── demo/
│   └── master_bot.py           # Attack simulation script
├── qa/
│   └── login_brute_test.py     # Brute force test script
├── tests/                      # Pytest test files (5 test modules + conftest)
├── img/                        # Screenshots (admin, users, warehouse)
└── .github/workflows/ci.yml    # CI pipeline
```

---

## 4. DATABASE TABLES (Supabase/PostgreSQL)

Defined in `setup_db.py`:

| Table | Purpose |
|---|---|
| `customers` | email, name, phone, password (bcrypt), blocked, checkout_blocked_until |
| `orders` | order_id, customer_name, phone, email, address, items (JSONB), total_value, payment_method, payment_status, status, source, ip_address, session_id |
| `otps` | email, code, expires_at |
| `password_resets` | email, code, expires_at |
| `payment_failures` | identifier (IP), failure_count |
| `reviews` | sku, email, customer_name, rating, title, comment |
| `return_requests` | order_id, email, items (JSONB), reason, type (return/replace), status |
| `notifications` | email, type, title, message, link, is_read |
| `coupons` | code, discount_type (%/fixed), discount_value, min_order_value, max_uses, used_count, is_active |
| `addresses` | email, label, name, phone, address_line, city, state, pincode, is_default |
| `blocked_ips` | ip_address, reason, severity, blocked_until, incident_id, groq_summary, blocked_by |
| Sentinel tables: `events`, `alerts`, `incidents`, `cases`, `playbooks`, `assets`, `vulnerabilities`, `threat_intel_iocs`, `audit_logs`, etc. |

---

## 5. HOW TO NAVIGATE — KEY LOCATIONS

**If asked to modify...**

| Feature | File | Line(s) |
|---|---|---|
| **Product catalog** | `boltmart/app.py` | Route `/shop` and `/product/<sku>` |
| **Cart operations** | `boltmart/app.py` | `/add_to_cart`, `/cart`, `/update_cart`, `/remove_from_cart` — lines 215-370 |
| **Wishlist operations** | `boltmart/app.py` | `/wishlist`, `/toggle_wishlist` |
| **Checkout flow** | `boltmart/app.py` | Route `/checkout` — lines 650-777 |
| **Order placement** | `boltmart/app.py` | Lines 700-776 (inside `/checkout` route) |
| **Coupon validation** | `boltmart/app.py` | `validate_coupon()` function — lines 76-94 |
| **Payment processing** | `boltmart/app.py` | Route `/payment`, `/api/payment/callback` |
| **PDF invoice** | `boltmart/invoice.py` | Full file (205 lines) |
| **Email sending** | `boltmart/notifier.py` | 8 email functions (592 lines total) |
| **Fraud detection** | `boltmart/anomaly.py` | `evaluate_payment_failure()` |
| **IP block check** | `boltmart/sentinel.py` | `check_blocked_ip_middleware()` — line 101 |
| **Defense webhook** | `boltmart/sentinel.py` | `register_defense_webhook()` — line 152 |
| **Session/cart helpers** | `boltmart/app.py` | Lines 40-57 (`get_cart`, `save_cart`, `get_wishlist`, `save_wishlist`) |
| **Order ID generation** | `boltmart/app.py` | `make_order_id()` — line 68 |
| **Stale order cleanup** | `boltmart/app.py` | `cleanup_stale_orders()` — line 122 (background thread) |
| **Database seeding** | `boltmart/seed.py` | Full file |
| **Warehouse — Inventory** | `warehouse_os/app.py` | `/inventory` route |
| **Warehouse — Fulfillment** | `warehouse_os/app.py` | `/fulfillment` route |
| **Warehouse — Purchase Orders** | `warehouse_os/app.py` | `/purchase_orders`, `/po/new`, `/po/<id>` |
| **Sentinel — Event ingestion** | `sentinel_xdr/app.py` | `/api/ingest` endpoint |
| **Sentinel — Detection rules** | `sentinel_xdr/detection_rules.py` | All 15 rules |
| **Sentinel — ML detection** | `sentinel_xdr/anomaly_detector.py` | Full file |
| **Sentinel — LLM analysis** | `sentinel_xdr/llm_analyzer.py` | Groq integration |
| **Sentinel — Active response** | `sentinel_xdr/active_response.py` | Webhook dispatch |
| **DB schema** | `setup_db.py` | Full SQL |
| **Shared constants** | `shared/constants.py` | All attack types, event types, severity, thresholds |
| **Supabase client** | `shared/db_client.py` | Singleton pattern with `lru_cache` |

---

## 6. CHECKOUT FLOW (BoltMart)

```
1. GET /checkout → renders form with address selection, cart items, coupon
2. POST /checkout → validates, applies coupon, creates order in DB, then:
   a. Clears cart, wishlist, coupon from session (flask_session.pop)
   b. If COD → email invoice + in-app notification → redirect to /confirmation
   c. If online → redirect to /payment (Razorpay)
3. GET /payment → renders Razorpay checkout
4. POST /api/payment/callback → Razorpay callback, updates order status
   - On failure → increment payment_failures, check if >= 3 → block checkout 1hr
```

**Session keys used:**
- `cart` — list of items `{sku, name, price, quantity, image}`
- `wishlist` — list of items `{sku, name, price, image, stock}`
- `coupon_code` — applied coupon code
- `coupon_discount` — calculated discount amount
- `sid` — session UUID
- `customer_email` — logged-in user
- `_created_at` — session creation timestamp
- `recently_viewed` — last 8 products

---

## 7. SENTINEL XDR DETECTION PIPELINE

```
1. Ingest (HTTP) → message_queue.py (thread-safe queue)
2. Worker pops events → detection_rules.py (15 rules) + anomaly_detector.py (ML)
3. If anomalous → database.py creates alert + incident
4. If threshold met → active_response.py dispatches webhook:
   POST /api/defense_webhook with signed payload → BoltMart/Warehouse OS block the IP
```

**15 Detection Rules** (`detection_rules.py`):
Brute force, credential stuffing, scraping, inventory fraud, privilege escalation, data exfiltration, fake order flood, bulk order fraud, invoice splitting, cross-system attack, honeypot probe, order enumeration + more

**ML Models** (`anomaly_detector.py`):
- Isolation Forest (unsupervised anomaly detection)
- One-Class SVM (novelty detection)
- Input: 23-feature vector (route sensitivity, hour of day, item count, order value, session age, etc.)

**LLM Integration** (`llm_analyzer.py`):
- Groq API with LLaMA 3.1
- Generates natural-language incident summaries
- Suggests remediation steps

---

## 8. RECENT CHANGES MADE

| Change | File | What |
|---|---|---|
| Clear cart after order | `boltmart/app.py:767-770` | Added `flask_session.pop("cart")`, `flask_session.pop("wishlist")`, etc. after DB insert |
| PIL import fix | `warehouse_os/app.py:1` | Added `from PIL import Image` (was missing, crashed image uploads) |
| CSV export fix | `sentinel_xdr/blueprints/events.py` | Mapped to real DB fields instead of nonexistent ones |
| Unified shared secret | All `config.py` files | Default value → `"sentinel-xdr-shared-secret-2024"` |
| Audit pagination fix | `warehouse_os/app.py:1733-1740` | Replaced broken query with proper `count("exact")` |
| Discount cap | `boltmart/app.py:89` | Capped percentage discount at subtotal |
| Request.json safety | `warehouse_os/app.py:1435` | Replaced `request.json.get()` with `request.get_json(silent=True)` |
| Wallet removal | `boltmart/app.py` + `checkout.html` | Removed "wallet" payment option entirely |
| Address auto-fill | `boltmart/templates/checkout.html` | Default address auto-fills form, visual selection state (green border) |

---

## 9. CONFIGURATION KEYS (`.env`)

```
SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
FLASK_SECRET_KEY
SENTINEL_URL, SENTINEL_SHARED_SECRET
RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
ADMIN_EMAIL
APP_URL
```

**Running the project:**
```powershell
# Terminal 1
python -m boltmart.app          # :5001

# Terminal 2
python -m warehouse_os.app      # :5002

# Terminal 3
python -m sentinel_xdr.app       # :5003
```
