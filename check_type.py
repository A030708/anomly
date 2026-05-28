import sys
sys.path.insert(0, ".")
from shared.db_client import get_supabase

db = get_supabase()
orders = db.table("orders").select("*").eq("order_id", "ORD-20260525-BEFD03").limit(1).execute()
order = orders.data[0]
print(f"Type: {type(order)}")
print(f"Type name: {type(order).__name__}")
print(f"Is dict: {isinstance(order, dict)}")
print(f"items key exists: {'items' in order}")
print(f"items value: {order.get('items')}")
print(f"items type: {type(order.get('items'))}")
