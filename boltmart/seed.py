import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from boltmart.config import Config
from shared.db_client import get_supabase

PRODUCTS = [
    {"sku": "HW-001", "name": "Heavy Duty Power Drill 13mm", "description": "Professional 850W impact drill with variable speed control", "category": "Power Tools", "price": 2499, "stock_count": 150, "reorder_level": 20, "unit_value": 2100, "is_active": True, "image_url": "/static/images/products/drill.jpg"},
    {"sku": "HW-002", "name": "Safety Helmet Class A Yellow", "description": "ISI certified construction helmet with adjustable strap", "category": "Safety Gear", "price": 349, "stock_count": 500, "reorder_level": 50, "unit_value": 280, "is_active": True, "image_url": "/static/images/products/helmet.jpg"},
    {"sku": "HW-003", "name": "Adjustable Wrench Set 5pc", "description": "Chrome vanadium steel wrenches, sizes 6in to 12in", "category": "Hand Tools", "price": 799, "stock_count": 200, "reorder_level": 30, "unit_value": 650, "is_active": True, "image_url": "/static/images/products/wrench.jpg"},
    {"sku": "HW-004", "name": "Extension Cord 10m 3-Pin", "description": "Heavy duty 16A rated cable with grounded plug", "category": "Electrical", "price": 649, "stock_count": 180, "reorder_level": 25, "unit_value": 520, "is_active": True, "image_url": "/static/images/products/cord.jpg"},
    {"sku": "HW-005", "name": "Work Gloves Heavy Duty Pack 3", "description": "Cut resistant leather palm gloves with reinforced stitching", "category": "Safety Gear", "price": 199, "stock_count": 400, "reorder_level": 60, "unit_value": 150, "is_active": True, "image_url": "/static/images/products/gloves.jpg"},
    {"sku": "HW-006", "name": "Steel Measuring Tape 5m", "description": "Retractable tape with metric and imperial markings, magnetic tip", "category": "Hand Tools", "price": 149, "stock_count": 300, "reorder_level": 40, "unit_value": 120, "is_active": True, "image_url": "/static/images/products/tape.jpg"},
    {"sku": "HW-007", "name": "Cable Ties Assorted 100pcs", "description": "UV resistant nylon cable ties in assorted sizes, black", "category": "Electrical", "price": 99, "stock_count": 600, "reorder_level": 80, "unit_value": 75, "is_active": True, "image_url": "/static/images/products/cableties.jpg"},
    {"sku": "HW-008", "name": "Professional Paint Brush Set 5pc", "description": "Synthetic bristle brushes for oil and water based paints", "category": "Painting", "price": 299, "stock_count": 250, "reorder_level": 35, "unit_value": 240, "is_active": True, "image_url": "/static/images/products/brush.jpg"},
    {"sku": "HW-009", "name": "Angle Grinder 850W 4 inch", "description": "Variable speed grinder with safety guard and side handle", "category": "Power Tools", "price": 3299, "stock_count": 80, "reorder_level": 10, "unit_value": 2800, "is_active": True, "image_url": "/static/images/products/grinder.jpg"},
    {"sku": "HW-010", "name": "Safety Goggles Anti-Fog", "description": "Wraparound design, ANSI Z87.1 certified impact resistant", "category": "Safety Gear", "price": 249, "stock_count": 350, "reorder_level": 50, "unit_value": 195, "is_active": True, "image_url": "/static/images/products/goggles.jpg"},
    {"sku": "HW-011", "name": "Ball Peen Hammer 500g", "description": "Forged steel head with cushioned rubber grip handle", "category": "Hand Tools", "price": 399, "stock_count": 220, "reorder_level": 30, "unit_value": 320, "is_active": True, "image_url": "/static/images/products/hammer.jpg"},
    {"sku": "HW-012", "name": "Electrical Insulation Tape 5 Roll", "description": "Flame retardant PVC tape pack, each 10m roll, assorted colors", "category": "Electrical", "price": 179, "stock_count": 450, "reorder_level": 60, "unit_value": 140, "is_active": True, "image_url": "/static/images/products/insulation_tape.jpg"},
]


def seed_products():
    url = Config.SUPABASE_URL
    key = Config.SUPABASE_KEY

    if not url or not key:
        print("Missing SUPABASE_URL or SUPABASE_KEY")
        return

    db = get_supabase()

    existing = db.table("products").select("*").limit(1).execute()
    count = len(existing.data or [])

    if count > 0:
        print(f"Found {count} existing products. Skipping seed.")
        return

    result = db.table("products").insert(PRODUCTS).execute()

    if result.data:
        print(f"Seeded {len(result.data)} products successfully!")
        for p in result.data:
            print(f"  {p['sku']} - {p['name']} - Rs{p['price']} (Stock: {p['stock_count']})")
    else:
        print("Failed to insert products")


def seed_coupons():
    supabase = get_supabase()
    coupons = [
        {"code": "WELCOME10", "discount_type": "percentage", "discount_value": 10, "min_order_value": 500, "max_uses": 200},
        {"code": "SAVE200", "discount_type": "fixed", "discount_value": 200, "min_order_value": 1000, "max_uses": 100},
        {"code": "FREEDEL", "discount_type": "fixed", "discount_value": 99, "min_order_value": 0, "max_uses": 500},
        {"code": "BOLT50", "discount_type": "percentage", "discount_value": 50, "min_order_value": 2000, "max_uses": 50},
    ]
    for coupon in coupons:
        existing = supabase.table("coupons").select("code").eq("code", coupon["code"]).execute()
        if not existing.data:
            supabase.table("coupons").insert(coupon).execute()
            print(f"  [+] Coupon {coupon['code']} created")
        else:
            print(f"  [=] Coupon {coupon['code']} already exists")


if __name__ == "__main__":
    seed_products()
    seed_coupons()
