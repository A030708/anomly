"""
BoltMart — Anomaly Detection Catalog
=====================================
Complete registry of all fraud/anomaly detection rules.
Each rule has: ID, category, detection logic, severity, action, status.

Status Legend:
  ✅ ACTIVE    — Currently implemented
  🔧 PLANNED   — Ready to build
  📋 FUTURE    — ML/AI phase
"""

ANOMALY_CATALOG = {
    # ========================================================================
    # 1. ACCOUNT & IDENTITY ANOMALIES
    # ========================================================================
    "AUTH_MULTI_ACCOUNT_SAME_IP": {
        "id": "AUTH-001",
        "category": "account",
        "title": "Multiple accounts from same IP",
        "severity": "HIGH",
        "detection": ">3 registrations from same IP in 1 hour",
        "action": "Block IP, flag all accounts for review",
        "status": "🔧 PLANNED",
    },
    "AUTH_REGISTRATION_BURST": {
        "id": "AUTH-002",
        "category": "account",
        "title": "Account creation burst",
        "severity": "HIGH",
        "detection": ">10 new users from same IP range in 5 minutes",
        "action": "CAPTCHA gate, shadow-ban IP range",
        "status": "🔧 PLANNED",
    },
    "AUTH_GEO_VELOCITY": {
        "id": "AUTH-003",
        "category": "account",
        "title": "Simultaneous logins from different geos",
        "severity": "CRITICAL",
        "detection": "Same user, 2 sessions from cities 500km+ apart in <10 minutes",
        "action": "Force re-auth + OTP, alert admin",
        "status": "🔧 PLANNED",
    },
    "AUTH_CREDENTIAL_STUFFING": {
        "id": "AUTH-004",
        "category": "account",
        "title": "Credential stuffing attack",
        "severity": "CRITICAL",
        "detection": "Same IP, 20+ different emails failing login in 2 minutes",
        "action": "Block IP, Sentinel CRITICAL alert",
        "status": "🔧 PLANNED",
    },
    "AUTH_PASSWORD_RESET_ABUSE": {
        "id": "AUTH-005",
        "category": "account",
        "title": "Password reset abuse",
        "severity": "MEDIUM",
        "detection": ">5 password reset requests/hour for same email",
        "action": "Rate-limit, alert user via email",
        "status": "🔧 PLANNED",
    },
    "AUTH_NEW_DEVICE_LOGIN": {
        "id": "AUTH-006",
        "category": "account",
        "title": "New device/login from unknown device",
        "severity": "MEDIUM",
        "detection": "Unknown user-agent or device fingerprint hash",
        "action": "OTP challenge on first login from device",
        "status": "🔧 PLANNED",
    },

    # ========================================================================
    # 2. CART & BROWSING ANOMALIES
    # ========================================================================
    "CART_INVENTORY_HOARDING": {
        "id": "CART-001",
        "category": "cart",
        "title": "Inventory hoarding",
        "severity": "MEDIUM",
        "detection": "Adding 100+ qty of same item, never checking out",
        "action": "Flag as bot, reduce cart quantity limit for session",
        "status": "🔧 PLANNED",
    },
    "CART_RAPID_MANIPULATION": {
        "id": "CART-002",
        "category": "cart",
        "title": "Rapid cart manipulation",
        "severity": "LOW",
        "detection": "50+ add/remove actions in 1 minute",
        "action": "Rate-limit session, log telemetry",
        "status": "🔧 PLANNED",
    },
    "CART_SCRAPER_DETECTED": {
        "id": "CART-003",
        "category": "cart",
        "title": "Scraper / bot detection",
        "severity": "MEDIUM",
        "detection": "100+ product pages in 2 minutes without cart action",
        "action": "CAPTCHA, rate-limit, log IP to Sentinel",
        "status": "🔧 PLANNED",
    },
    "CART_PRICE_TAMPERING": {
        "id": "CART-004",
        "category": "cart",
        "title": "Price manipulation via form tampering",
        "severity": "HIGH",
        "detection": "Negative quantity, negative price, or modified hidden fields",
        "action": "Reject order immediately, flag account for manual review",
        "status": "🔧 PLANNED",
    },
    "CART_COUPON_ABUSE": {
        "id": "CART-005",
        "category": "cart",
        "title": "Coupon code abuse",
        "severity": "MEDIUM",
        "detection": "Same coupon code used 10+ times by different sessions in 1hr",
        "action": "Suspend coupon code, alert admin",
        "status": "🔧 PLANNED",
    },

    # ========================================================================
    # 3. ORDER & CHECKOUT ANOMALIES
    # ========================================================================
    "ORDER_RAPID_FIRE": {
        "id": "ORD-001",
        "category": "order",
        "title": "Rapid fire orders",
        "severity": "HIGH",
        "detection": "Same customer, >3 orders placed in <60 seconds",
        "action": "Hold all orders for manual admin review",
        "status": "🔧 PLANNED",
    },
    "ORDER_HIGH_VALUE_NEW_USER": {
        "id": "ORD-002",
        "category": "order",
        "title": "High-value order from new user",
        "severity": "HIGH",
        "detection": "First-ever order total > ₹50,000",
        "action": "Manual review + OTP verification, alert admin",
        "status": "🔧 PLANNED",
    },
    "ORDER_COD_ABUSE": {
        "id": "ORD-003",
        "category": "order",
        "title": "COD abuse (repeat non-acceptance)",
        "severity": "HIGH",
        "detection": "Same user, >3 COD orders not accepted in past 30 days",
        "action": "Force prepaid-only payment for that user",
        "status": "🔧 PLANNED",
    },
    "ORDER_SPLITTING": {
        "id": "ORD-004",
        "category": "order",
        "title": "Order splitting to bypass thresholds",
        "severity": "MEDIUM",
        "detection": "Same cart split into 5+ small orders placed within 10 minutes",
        "action": "Merge detection flag, escalate for review",
        "status": "🔧 PLANNED",
    },
    "ORDER_MIDNIGHT_BURST": {
        "id": "ORD-005",
        "category": "order",
        "title": "Midnight order burst",
        "severity": "MEDIUM",
        "detection": "All orders from same IP placed between 1AM–5AM",
        "action": "Flag for fraud review team",
        "status": "🔧 PLANNED",
    },
    "ORDER_SUSPICIOUS_ADDRESS": {
        "id": "ORD-006",
        "category": "order",
        "title": "Suspicious shipping address",
        "severity": "HIGH",
        "detection": "PO box, incomplete address, or same address used by 5+ users",
        "action": "Hold order, verify phone number before dispatch",
        "status": "🔧 PLANNED",
    },

    # ========================================================================
    # 4. PAYMENT ANOMALIES (EXTENDING EXISTING CARD DETECTION)
    # ========================================================================
    "PAY_THREE_STRIKE": {
        "id": "PAY-001",
        "category": "payment",
        "title": "3 consecutive payment failures",
        "severity": "CRITICAL",
        "detection": "3 failed payment attempts in a row for any order(s)",
        "action": "Block user + IP, notify user + admin, Sentinel CRITICAL",
        "status": "✅ ACTIVE",
    },
    "PAY_CARD_LUHN_FAIL": {
        "id": "PAY-002",
        "category": "payment",
        "title": "Invalid card number (Luhn check)",
        "severity": "MEDIUM",
        "detection": "Card number fails Luhn algorithm check",
        "action": "Reject payment, log attempt, increment strike counter",
        "status": "🔧 PLANNED",
    },
    "PAY_CARD_BIN_MISMATCH": {
        "id": "PAY-003",
        "category": "payment",
        "title": "Card BIN / country mismatch",
        "severity": "HIGH",
        "detection": "Card issuer country != billing country",
        "action": "Flag for review, OTP verify, alert admin if recurring",
        "status": "🔧 PLANNED",
    },
    "PAY_CARD_BINNING_ATTACK": {
        "id": "PAY-004",
        "category": "payment",
        "title": "Card BIN sequential attack",
        "severity": "CRITICAL",
        "detection": "Sequential card number generation detected (BIN probing)",
        "action": "Block IP immediately, alert admin, Sentinel CRITICAL",
        "status": "🔧 PLANNED",
    },
    "PAY_HIGH_VALUE_VELOCITY": {
        "id": "PAY-005",
        "category": "payment",
        "title": "High-value payment velocity",
        "severity": "HIGH",
        "detection": "Multiple high-value attempts (>₹10k) in <5 minute window",
        "action": "Temp block, require OTP re-verification",
        "status": "🔧 PLANNED",
    },

    # ========================================================================
    # 5. INVENTORY & WAREHOUSE ANOMALIES
    # ========================================================================
    "INV_STOCK_DRAIN": {
        "id": "INV-001",
        "category": "inventory",
        "title": "Stock drain attack",
        "severity": "CRITICAL",
        "detection": "Same SKU ordered 50+ times by different users in 10 minutes",
        "action": "Pause fulfillment for that SKU, alert warehouse manager",
        "status": "🔧 PLANNED",
    },
    "INV_WRITEOFF_SPIKE": {
        "id": "INV-002",
        "category": "inventory",
        "title": "Write-off spike on single SKU",
        "severity": "MEDIUM",
        "detection": "5+ write-offs on same SKU within 1 hour",
        "action": "Manager approval required for further write-offs",
        "status": "🔧 PLANNED",
    },
    "INV_NEGATIVE_STOCK": {
        "id": "INV-003",
        "category": "inventory",
        "title": "Negative stock due to race condition",
        "severity": "CRITICAL",
        "detection": "Stock count goes below zero after order deduction",
        "action": "Log critical system alert, pause orders for that SKU",
        "status": "🔧 PLANNED",
    },
    "INV_BULK_REORDER_TRIGGER": {
        "id": "INV-004",
        "category": "inventory",
        "title": "Bulk auto-reorder anomaly",
        "severity": "LOW",
        "detection": "Sudden demand spike triggers bulk auto-reorder of same item",
        "action": "Flag for purchasing team to review before committing",
        "status": "🔧 PLANNED",
    },

    # ========================================================================
    # 6. OTP & VERIFICATION ANOMALIES
    # ========================================================================
    "OTP_BRUTE_FORCE": {
        "id": "OTP-001",
        "category": "otp",
        "title": "OTP brute force attempt",
        "severity": "HIGH",
        "detection": ">10 OTP verify attempts with wrong code",
        "action": "Block OTP for 1 hour, block IP, alert admin",
        "status": "🔧 PLANNED",
    },
    "OTP_REQUEST_FLOOD": {
        "id": "OTP-002",
        "category": "otp",
        "title": "OTP request flood",
        "severity": "HIGH",
        "detection": ">20 OTP requests from same phone number in 5 minutes",
        "action": "Rate-limit phone for 24 hours",
        "status": "🔧 PLANNED",
    },
    "OTP_SKIP_CHECKOUT": {
        "id": "OTP-003",
        "category": "otp",
        "title": "Checkout bypass without phone verify",
        "severity": "MEDIUM",
        "detection": "Attempting checkout with unverified phone number",
        "action": "Block checkout, redirect to phone verification page",
        "status": "🔧 PLANNED",
    },
    "OTP_SMS_GATEWAY_ABUSE": {
        "id": "OTP-004",
        "category": "otp",
        "title": "SMS gateway abuse (programmatic)",
        "severity": "CRITICAL",
        "detection": "Same IP triggering 100+ OTP sends in 5 minutes",
        "action": "Blacklist IP permanently, admin alert via phone",
        "status": "🔧 PLANNED",
    },

    # ========================================================================
    # 7. TECHNICAL ATTACK ANOMALIES
    # ========================================================================
    "TECH_SQL_INJECTION": {
        "id": "TECH-001",
        "category": "technical",
        "title": "SQL injection attempt",
        "severity": "CRITICAL",
        "detection": "Suspicious characters in search/checkout fields (`' OR 1=1--`)",
        "action": "Reject request, log + alert Sentinel XDR, sanitize input",
        "status": "✅ ACTIVE",
    },
    "TECH_PARAMETER_TAMPERING": {
        "id": "TECH-002",
        "category": "technical",
        "title": "Parameter tampering in forms",
        "severity": "HIGH",
        "detection": "Modified hidden fields (price, discount, user_id, quantity)",
        "action": "Reject request, flag account for manual review",
        "status": "🔧 PLANNED",
    },
    "TECH_API_SCRAPING": {
        "id": "TECH-003",
        "category": "technical",
        "title": "API scraping / high-frequency crawling",
        "severity": "MEDIUM",
        "detection": "Same IP hitting product pages at >60 RPM",
        "action": "Rate-limit → CAPTCHA → temporary IP block",
        "status": "🔧 PLANNED",
    },
    "TECH_HONEYPOT_PROBE": {
        "id": "TECH-004",
        "category": "technical",
        "title": "Honeypot route probe",
        "severity": "HIGH",
        "detection": "Accessing hidden routes (`/.env`, `/admin`, `/api/v1`)",
        "action": "Log IP, Sentinel CRITICAL alert, auto-block after 3 probes",
        "status": "✅ ACTIVE",
    },
    "TECH_BOT_DETECTION": {
        "id": "TECH-005",
        "category": "technical",
        "title": "Bot / headless browser detection",
        "severity": "MEDIUM",
        "detection": "No User-Agent, known bot signature, or missing JS fingerprint",
        "action": "Serve CAPTCHA, log to Sentinel with bot score",
        "status": "🔧 PLANNED",
    },
    "TECH_SESSION_HIJACKING": {
        "id": "TECH-006",
        "category": "technical",
        "title": "Session hijacking detection",
        "severity": "CRITICAL",
        "detection": "Same session_id active from 2+ different IPs simultaneously",
        "action": "Invalidate session immediately, force logout, alert user",
        "status": "🔧 PLANNED",
    },

    # ========================================================================
    # 8. CROSS-SESSION & TREND ANOMALIES
    # ========================================================================
    "CROSS_SAME_CARD_MULTI_USER": {
        "id": "CROSS-001",
        "category": "cross_session",
        "title": "Same card used by multiple accounts",
        "severity": "CRITICAL",
        "detection": "Card last-4 digits used by 3+ different user accounts",
        "action": "Flag all accounts for fraud review, notify admin",
        "status": "🔧 PLANNED",
    },
    "CROSS_SAME_PHONE_DIFF_NAMES": {
        "id": "CROSS-002",
        "category": "cross_session",
        "title": "Same phone, different customer names",
        "severity": "HIGH",
        "detection": "Phone number linked to 3+ different customer names in orders",
        "action": "Verify identity via OTP, hold all linked orders",
        "status": "🔧 PLANNED",
    },
    "CROSS_FRAUD_RING_ADDRESS": {
        "id": "CROSS-003",
        "category": "cross_session",
        "title": "Fraud ring — same address, many cards",
        "severity": "CRITICAL",
        "detection": "Shipping address used with 10+ unique card BINs in 1 hour",
        "action": "Block address, alert admin with all linked accounts",
        "status": "🔧 PLANNED",
    },
    "CROSS_DAILY_VOLUME_SPIKE": {
        "id": "CROSS-004",
        "category": "cross_session",
        "title": "Daily order volume spike >500%",
        "severity": "MEDIUM",
        "detection": "Orders exceed 500% of daily average in a single hour",
        "action": "Auto-scale Sentinel monitoring, alert ops team",
        "status": "🔧 PLANNED",
    },
    "CROSS_GEO_IMPOSSIBLE_TRAVEL": {
        "id": "CROSS-005",
        "category": "cross_session",
        "title": "Impossible geo-velocity",
        "severity": "CRITICAL",
        "detection": "Order placed Mumbai → 5 min later login from London",
        "action": "Account takeover alert, block account, force password reset",
        "status": "🔧 PLANNED",
    },
}

# ============================================================================
# GROUPED SUMMARY BY CATEGORY
# ============================================================================
CATEGORY_SUMMARY = {
    "account": {
        "label": "Account & Identity",
        "icon": "👤",
        "count": 6,
        "rules": ["AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005", "AUTH-006"],
    },
    "cart": {
        "label": "Cart & Browsing",
        "icon": "🛒",
        "count": 5,
        "rules": ["CART-001", "CART-002", "CART-003", "CART-004", "CART-005"],
    },
    "order": {
        "label": "Order & Checkout",
        "icon": "📦",
        "count": 6,
        "rules": ["ORD-001", "ORD-002", "ORD-003", "ORD-004", "ORD-005", "ORD-006"],
    },
    "payment": {
        "label": "Payment",
        "icon": "💳",
        "count": 5,
        "rules": ["PAY-001", "PAY-002", "PAY-003", "PAY-004", "PAY-005"],
    },
    "inventory": {
        "label": "Inventory & Warehouse",
        "icon": "🏭",
        "count": 4,
        "rules": ["INV-001", "INV-002", "INV-003", "INV-004"],
    },
    "otp": {
        "label": "OTP & Verification",
        "icon": "📱",
        "count": 4,
        "rules": ["OTP-001", "OTP-002", "OTP-003", "OTP-004"],
    },
    "technical": {
        "label": "Technical Attacks",
        "icon": "🔧",
        "count": 6,
        "rules": ["TECH-001", "TECH-002", "TECH-003", "TECH-004", "TECH-005", "TECH-006"],
    },
    "cross_session": {
        "label": "Cross-Session & Trends",
        "icon": "📊",
        "count": 5,
        "rules": ["CROSS-001", "CROSS-002", "CROSS-003", "CROSS-004", "CROSS-005"],
    },
}

# ============================================================================
# SEVERITY BREAKDOWN
# ============================================================================
SEVERITY_COUNTS = {
    "CRITICAL": len([r for r in ANOMALY_CATALOG.values() if r["severity"] == "CRITICAL"]),
    "HIGH": len([r for r in ANOMALY_CATALOG.values() if r["severity"] == "HIGH"]),
    "MEDIUM": len([r for r in ANOMALY_CATALOG.values() if r["severity"] == "MEDIUM"]),
    "LOW": len([r for r in ANOMALY_CATALOG.values() if r["severity"] == "LOW"]),
}

TOTAL_RULES = len(ANOMALY_CATALOG)
ACTIVE_RULES = len([r for r in ANOMALY_CATALOG.values() if r["status"] == "✅ ACTIVE"])
PLANNED_RULES = len([r for r in ANOMALY_CATALOG.values() if r["status"] == "🔧 PLANNED"])

# ============================================================================
# BUILT-IN DETECTION FUNCTIONS (reference stubs)
# ============================================================================

DETECTION_HELPERS = {
    "luhn_check": "Validate card number using Luhn algorithm",
    "geo_distance_km": "Calculate great-circle distance between 2 lat/lng points",
    "device_fingerprint": "Hash of user-agent + screen + timezone + plugins",
    "velocity_window": "Count events per unique key within rolling time window (Redis sorted set)",
    "card_bin_lookup": "Extract issuer/bank/country from first 6 digits of card",
    "address_similarity": "Levenshtein distance between address strings for fraud ring detection",
    "bot_score": "Heuristic score based on headers, JS execution, mouse movement",
    "session_geo_check": "Compare current request geo vs last known geo for session",
}
