import sys
sys.path.insert(0, "C:/Users/abhir/OneDrive/Desktop/proj")
from boltmart.app import create_app
app = create_app()
print("BoltMart started", flush=True)
app.run(host="0.0.0.0", port=5001, debug=True)
