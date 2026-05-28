import sys
sys.path.insert(0, ".")
from shared.db_client import get_supabase

db = get_supabase()
orders = db.table("orders").select("order_id, items, items").order("created_at", desc=True).limit(5).execute().data
for o in orders:
    has_items = "items" in o
    items_val = o.get("items")
    items_type = type(items_val).__name__
    print(f'{o["order_id"]}: has_items={has_items}, type={items_type}, val={items_val}')
