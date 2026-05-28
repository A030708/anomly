import sys
sys.path.insert(0, "C:/Users/abhir/OneDrive/Desktop/proj")
import json

from shared.db_client import get_supabase

db = get_supabase()
order = db.table("orders").select("*").eq("order_id", "ORD-20260525-BEFD03").limit(1).execute().data[0]

if isinstance(order.get("items"), str):
    order["items"] = json.loads(order["items"])
elif not isinstance(order.get("items"), list):
    order["items"] = []

oid = order.get("order_id", "")
order["transaction_id"] = order.get("transaction_id") or f"TXN-{oid[-12:]}"
if order.get("payment_method") == "cod":
    order["transaction_id"] = None

from flask import Flask, render_template
app = Flask("test", template_folder="C:/Users/abhir/OneDrive/Desktop/proj/boltmart/templates")
with app.app_context():
    html = render_template("confirmation.html", order=order, tracking_mode=False)
    print("Template rendered OK -", len(html), "chars")
