import requests
from boltmart.db_users import record_payment_failure, reset_payment_failures
from boltmart.config import Config
from boltmart.notifier import send_fraud_alert, send_user_suspended

SENTINEL_URL = "http://localhost:5003"

def evaluate_payment_failure(email, ip_address):
    failures = record_payment_failure(ip_address)
    
    if failures >= 3:
        # Trigger anomaly to Sentinel XDR
        payload = {
            "source": "boltmart_payment_gateway",
            "ip": ip_address,
            "route": "/api/payment",
            "method": "POST",
            "event_type": "CARD_TESTING_SUSPICION",
            "user_id": email,
            "user_role": "customer",
            "metadata": {
                "failures": failures,
                "reason": f"Payment failed {failures} times consecutively. Possible card testing or fraud.",
                "action_taken": "User suspended and IP blocked."
            }
        }
        
        try:
            res = requests.post(
                f"{SENTINEL_URL}/api/ingest",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=2
            )
            # Sentinel XDR will receive this, see the event type, and hopefully flag it as anomalous
            # since card testing is clearly suspicious.
        except Exception as e:
            print("Failed to contact Sentinel XDR:", e)
            
        send_fraud_alert(ip_address, payload["event_type"], payload["metadata"])
        if email:
            send_user_suspended(email, "Multiple failed payment attempts detected.")
            
        return True # Threshold reached
        
    return False

def reset_payment_status(ip_address):
    reset_payment_failures(ip_address)
