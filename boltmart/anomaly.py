import requests
from datetime import datetime, timezone
from boltmart.db_users import record_payment_failure, set_checkout_block, get_customer_name
from boltmart.config import Config
from boltmart.notifier import send_fraud_alert, send_checkout_blocked_email

SENTINEL_URL = "http://localhost:5003"

def evaluate_payment_failure(email, ip_address, session_id="anonymous"):
    failures = record_payment_failure(ip_address)
    
    if failures >= 3:
        print(f"[ANOMALY] 3+ payment failures from IP {ip_address}, email={email}")
        payload = {
            "source": "boltmart",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": ip_address,
            "route": "/api/payment",
            "method": "POST",
            "event_type": "CARD_TESTING_SUSPICION",
            "session_id": session_id,
            "user_id": email,
            "user_role": "customer",
            "metadata": {
                "failures": failures,
                "reason": f"Payment failed {failures} times consecutively. Possible card testing or fraud.",
                "action_taken": "Checkout blocked for 1 hour."
            }
        }
        
        headers = {
            "Content-Type": "application/json",
            "X-Sentinel-Secret": Config.SENTINEL_SHARED_SECRET,
            "X-Source": "boltmart"
        }
        
        try:
            requests.post(
                f"{SENTINEL_URL}/api/ingest",
                json=payload,
                headers=headers,
                timeout=2
            )
        except Exception as e:
            print("Failed to contact Sentinel XDR:", e)
            
        send_fraud_alert(ip_address, payload["event_type"], payload["metadata"])
        
        if email:
            try:
                name = get_customer_name(email)
                send_checkout_blocked_email(email, name)
                set_checkout_block(email, 60)
            except Exception as e:
                print("Failed to block checkout:", e)
            
        return True
        
    return False

def reset_payment_status(ip_address):
    pass
