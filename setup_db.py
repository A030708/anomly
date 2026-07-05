import sys
import os

SQL = """
-- Create customers table
CREATE TABLE IF NOT EXISTS customers (
    email TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT,
    password TEXT NOT NULL,
    blocked BOOLEAN DEFAULT FALSE,
    checkout_blocked_until TIMESTAMPTZ DEFAULT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create otps table
CREATE TABLE IF NOT EXISTS otps (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);

-- Create payment_failures table
CREATE TABLE IF NOT EXISTS payment_failures (
    identifier TEXT PRIMARY KEY,
    failure_count INTEGER DEFAULT 0
);

-- Create password_resets table
CREATE TABLE IF NOT EXISTS password_resets (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);

-- Create reviews table
CREATE TABLE IF NOT EXISTS reviews (
    id SERIAL PRIMARY KEY,
    sku TEXT NOT NULL,
    email TEXT NOT NULL,
    customer_name TEXT NOT NULL,
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    title TEXT,
    comment TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(sku, email)
);

-- Create return_requests table
CREATE TABLE IF NOT EXISTS return_requests (
    id SERIAL PRIMARY KEY,
    order_id TEXT NOT NULL,
    email TEXT NOT NULL,
    items JSONB NOT NULL DEFAULT '[]',
    reason TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('return', 'replace')),
    status TEXT NOT NULL DEFAULT 'pending',
    admin_note TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create notifications table
CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    link TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create coupons table
CREATE TABLE IF NOT EXISTS coupons (
    code TEXT PRIMARY KEY,
    discount_type TEXT NOT NULL CHECK (discount_type IN ('percentage', 'fixed')),
    discount_value NUMERIC NOT NULL,
    min_order_value NUMERIC DEFAULT 0,
    max_uses INTEGER DEFAULT 100,
    used_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add checkout_blocked_until to existing customers table
ALTER TABLE customers ADD COLUMN IF NOT EXISTS checkout_blocked_until TIMESTAMPTZ DEFAULT NULL;

-- Create addresses table
CREATE TABLE IF NOT EXISTS addresses (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    label TEXT DEFAULT 'Home',
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    address_line TEXT NOT NULL,
    city TEXT NOT NULL,
    state TEXT NOT NULL,
    pincode TEXT NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
"""

if __name__ == "__main__":
    print("=" * 60)
    print("BoltMart Database Setup")
    print("=" * 60)
    print()
    print("Please paste the following SQL into your Supabase Dashboard SQL Editor")
    print("and click 'Run':")
    print()
    print("  https://app.supabase.com/project/YOUR_PROJECT_ID/sql/new")
    print()
    print("-" * 60)
    print(SQL.strip())
    print("-" * 60)
    print()

    if "--verify" in sys.argv:
        print("Verifying tables...")
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        try:
            from shared.db_client import get_supabase
            supabase = get_supabase()

            for table in ("customers", "otps", "payment_failures", "reviews", "addresses", "password_resets", "coupons", "notifications"):
                try:
                    supabase.table(table).select("*").limit(1).execute()
                    print(f"  [+] {table} table exists")
                except Exception:
                    print(f"  [-] {table} table NOT found")
        except Exception as e:
            print(f"  Error: {e}")
