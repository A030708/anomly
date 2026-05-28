# shared/constants.py

SENTINEL_SHARED_SECRET = "sentinel-xdr-shared-secret-2024"
SENTINEL_INGEST_URL = "http://localhost:5003/api/ingest"

# Attack Types
ATTACK_BRUTE_FORCE = "BRUTE_FORCE"
ATTACK_CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
ATTACK_SCRAPING = "SCRAPING"
ATTACK_INVENTORY_FRAUD = "INVENTORY_FRAUD"
ATTACK_PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
ATTACK_DATA_EXFILTRATION = "DATA_EXFILTRATION"
ATTACK_FAKE_ORDER_FLOOD = "FAKE_ORDER_FLOOD"
ATTACK_BULK_ORDER_FRAUD = "BULK_ORDER_FRAUD"
ATTACK_INVOICE_SPLITTING = "INVOICE_SPLITTING"
ATTACK_CROSS_SYSTEM = "CROSS_SYSTEM_ATTACK"
ATTACK_HONEYPOT = "HONEYPOT_PROBE"
ATTACK_ENUMERATION = "ORDER_ENUMERATION"

# Event Types
EVENT_PAGE_VIEW = "PAGE_VIEW"
EVENT_PRODUCT_VIEW = "PRODUCT_VIEW"
EVENT_CART_ADD = "CART_ADD"
EVENT_CHECKOUT_ATTEMPT = "CHECKOUT_ATTEMPT"
EVENT_ORDER_PLACED = "ORDER_PLACED"
EVENT_LOGIN_ATTEMPT = "LOGIN_ATTEMPT"
EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_LOGIN_FAILURE = "LOGIN_FAILURE"
EVENT_WRITE_OFF = "WRITE_OFF"
EVENT_DATA_EXPORT = "DATA_EXPORT"
EVENT_ADMIN_ACCESS = "ADMIN_ACCESS"
EVENT_INVOICE_SUBMIT = "INVOICE_SUBMIT"
EVENT_HONEYPOT = "HONEYPOT_HIT"
EVENT_ORDER_TRACK = "ORDER_TRACK"

# Severity Levels
SEV_LOW = "low"
SEV_MEDIUM = "medium"
SEV_HIGH = "high"
SEV_CRITICAL = "critical"

# Anomaly Thresholds
THRESHOLD_LOW = 0.40
THRESHOLD_MEDIUM = 0.60
THRESHOLD_HIGH = 0.75
THRESHOLD_CRITICAL = 0.90

# Block Durations (minutes)
BLOCK_DURATION = {
    SEV_LOW: 30,
    SEV_MEDIUM: 120,
    SEV_HIGH: 1440,
    SEV_CRITICAL: 10080
}

# Actions
ACTION_BLOCK_IP = "BLOCK_IP"
ACTION_REVOKE_SESSION = "REVOKE_SESSION"
ACTION_HOLD_FOR_REVIEW = "HOLD_FOR_REVIEW"
ACTION_RATE_LIMIT = "RATE_LIMIT"
ACTION_WATCH_AND_LOG = "WATCH_AND_LOG"

# Route Sensitivity Scores
ROUTE_SENSITIVITY = {
    "/": 0.1,
    "/shop": 0.1,
    "/product": 0.2,
    "/cart": 0.3,
    "/checkout": 0.6,
    "/track": 0.3,
    "/admin": 1.0,
    "/api": 0.5,
    "/export": 0.8,
    "/download": 0.8,
    "/.env": 1.0,
    "/login": 0.5,
    "/inventory": 0.6,
    "/write-off": 0.9,
}

# Products
PRODUCTS = [
    {"sku": "HW-001", "name": "Heavy Duty Power Drill 13mm",
     "price": 2499, "category": "Power Tools", "stock": 150,
     "reorder": 20, "unit_value": 2499,
     "description": "Professional-grade 13mm drill with variable speed control, reverse function, and ergonomic grip. Ideal for heavy-duty drilling in wood, metal, and masonry.",
     "image": "drill.jpg"},
    {"sku": "HW-002", "name": "Safety Helmet Class A Yellow",
     "price": 349, "category": "Safety Gear", "stock": 500,
     "reorder": 50, "unit_value": 349,
     "description": "ANSI/ISEA Z89.1 Class A certified safety helmet. 6-point suspension, adjustable ratchet, UV-resistant ABS shell.",
     "image": "helmet.jpg"},
    {"sku": "HW-003", "name": "Adjustable Wrench Set 5pc",
     "price": 799, "category": "Hand Tools", "stock": 200,
     "reorder": 30, "unit_value": 799,
     "description": "5-piece professional adjustable wrench set. Chrome vanadium steel, sizes 6, 8, 10, 12, and 15 inch.",
     "image": "wrench.jpg"},
    {"sku": "HW-004", "name": "Extension Cord 10m 3-Pin",
     "price": 649, "category": "Electrical", "stock": 180,
     "reorder": 25, "unit_value": 649,
     "description": "Heavy-duty 10 meter 3-pin extension cord with surge protection, 10A rating, and flexible PVC insulation.",
     "image": "cord.jpg"},
    {"sku": "HW-005", "name": "Work Gloves Heavy Duty Pack 3",
     "price": 199, "category": "Safety Gear", "stock": 400,
     "reorder": 60, "unit_value": 199,
     "description": "Pack of 3 pairs heavy-duty work gloves. Cut-resistant Kevlar lining, nitrile-coated palm, one-size-fits-most.",
     "image": "gloves.jpg"},
    {"sku": "HW-006", "name": "Steel Measuring Tape 5m",
     "price": 149, "category": "Hand Tools", "stock": 300,
     "reorder": 40, "unit_value": 149,
     "description": "Professional 5m steel measuring tape with magnetic hook, belt clip, and shock-absorbent casing.",
     "image": "tape.jpg"},
    {"sku": "HW-007", "name": "Cable Ties Assorted 100pcs",
     "price": 99, "category": "Electrical", "stock": 600,
     "reorder": 80, "unit_value": 99,
     "description": "100-piece assorted cable tie kit. Includes 4, 6, 8, and 12 inch sizes. Nylon 66, self-locking.",
     "image": "ties.jpg"},
    {"sku": "HW-008", "name": "Professional Paint Brush Set 5pc",
     "price": 299, "category": "Painting", "stock": 250,
     "reorder": 35, "unit_value": 299,
     "description": "5-piece professional paint brush set. Natural bristle for oil-based, synthetic for water-based. Sizes 1 to 4 inch.",
     "image": "brush.jpg"},
    {"sku": "HW-009", "name": "Angle Grinder 850W 4 inch",
     "price": 3299, "category": "Power Tools", "stock": 80,
     "reorder": 10, "unit_value": 3299,
     "description": "850W professional angle grinder, 11,000 RPM, 4-inch disc capacity. Spindle lock, safety guard, side handle included.",
     "image": "grinder.jpg"},
    {"sku": "HW-010", "name": "Safety Goggles Anti-Fog",
     "price": 249, "category": "Safety Gear", "stock": 350,
     "reorder": 50, "unit_value": 249,
     "description": "Anti-fog, scratch-resistant safety goggles. Indirect ventilation, UV protection, fits over prescription glasses.",
     "image": "goggles.jpg"},
    {"sku": "HW-011", "name": "Ball Peen Hammer 500g",
     "price": 399, "category": "Hand Tools", "stock": 220,
     "reorder": 30, "unit_value": 399,
     "description": "500g ball peen hammer with fiberglass handle and rubber grip. Drop-forged steel head, anti-vibration design.",
     "image": "hammer.jpg"},
    {"sku": "HW-012", "name": "Electrical Insulation Tape 5 Roll",
     "price": 179, "category": "Electrical", "stock": 450,
     "reorder": 60, "unit_value": 179,
     "description": "5-roll pack electrical insulation tape. PVC, self-extinguishing, rated to 600V. Black, 19mm x 20m per roll.",
     "image": "tape2.jpg"},
]

# Demo Users
DEMO_USERS = [
    {"username": "admin", "email": "admin@boltmart.in",
     "password": "Admin@2024", "role": "admin", "department": "Management"},
    {"username": "manager_raj", "email": "raj@boltmart.in",
     "password": "Manager@2024", "role": "manager", "department": "Operations"},
    {"username": "manager_priya", "email": "priya@boltmart.in",
     "password": "Manager@2024", "role": "manager", "department": "Logistics"},
    {"username": "staff_arjun", "email": "arjun@boltmart.in",
     "password": "Staff@2024", "role": "staff", "department": "Fulfillment"},
    {"username": "staff_deepa", "email": "deepa@boltmart.in",
     "password": "Staff@2024", "role": "staff", "department": "Inventory"},
    {"username": "staff_vikram", "email": "vikram@boltmart.in",
     "password": "Staff@2024", "role": "staff", "department": "Fulfillment"},
    {"username": "vendor_steelco", "email": "contact@steelco.in",
     "password": "Vendor@2024", "role": "vendor", "department": "External"},
]
